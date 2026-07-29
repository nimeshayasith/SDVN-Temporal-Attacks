package main

// trust_sweep_test.go — one-at-a-time ±1-step sweep of the six trust
// architecture parameters (τ_min, τ_min^gt, τ_min^C, Δ+, Δ-, T_quar) using
// fabric-chaincode-go's shimtest.MockStub, so each candidate value can be
// evaluated natively in Go without a full NS-3 + Fabric-network redeploy
// cycle per value (that would require ~13 chaincode redeploy+run cycles;
// this runs in well under a second).
//
// Metric: MCC/FP-rate computed from a synthetic confusion matrix, using a
// fixed-seed pseudo-random behavior sequence so results are deterministic
// and reproducible across runs.
//
//   - τ_min, Δ+, Δ-, T_quar: exercised via the RSU peer trust random-walk
//     (peers start ACTIVE, get a mix of correct/incorrect trust updates
//     each beacon round for R = T_quar/Tb rounds, then are classified
//     "should stay active" vs "trust dropped to/below τ_min" and compared
//     against ground truth malicious/honest labels).
//   - τ_min^C: exercised via the controller divergence-penalty pathway
//     (ΔC- is fixed at its calibrated 0.20; only the reassignment
//     threshold varies).
//   - τ_min^gt: exercised via the caller-authorization gate used by
//     ZeroTrust/DemotePeerToClient for non-RSU callers, reporting both the
//     admission rate over a fixed synthetic caller population and the
//     analytically-coupled R_min = ceil((τ_min^gt - τ0)/Δ+).

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func newCtx(stub *shimtest.MockStub) contractapi.TransactionContextInterface {
	ctx := new(contractapi.TransactionContext)
	ctx.SetStub(stub)
	return ctx
}

// mcc computes the Matthews Correlation Coefficient from a confusion matrix.
func mcc(tp, tn, fp, fn int) float64 {
	num := float64(tp*tn - fp*fn)
	den := float64(tp+fp) * float64(tp+fn) * float64(tn+fp) * float64(tn+fn)
	if den <= 0 {
		return 0
	}
	return num / sqrtApprox(den)
}

func sqrtApprox(x float64) float64 {
	if x == 0 {
		return 0
	}
	z := x
	for i := 0; i < 40; i++ {
		z -= (z*z - x) / (2 * z)
	}
	return z
}

// ── τ_min / Δ+ / Δ- / T_quar sweep: RSU peer trust random walk ─────────────

const (
	nPeersPerClass  = 60   // 60 malicious + 60 honest, fixed across the sweep
	beaconTb        = 100  // Tb, ms — matches Table 4.9's 100ms beacon interval
	malFlagProb     = 0.55 // per-round probability a malicious peer is (correctly) flagged bad
	honestFlagProb  = 0.08 // per-round probability an honest peer is (incorrectly) flagged bad
	sweepRandomSeed = 42
)

func runPeerTrustSweep(tauMin, deltaPlus, deltaMinus float64, tQuarMs int64) (mccVal, fpRate, fnRate float64) {
	rng := rand.New(rand.NewSource(sweepRandomSeed))
	rounds := int(tQuarMs / beaconTb)
	if rounds < 1 {
		rounds = 1
	}

	origPlus, origMinus := TrustDeltaPlus, TrustDeltaMinus
	TrustDeltaPlus, TrustDeltaMinus = deltaPlus, deltaMinus
	defer func() { TrustDeltaPlus, TrustDeltaMinus = origPlus, origMinus }()

	stub := shimtest.NewMockStub("teta-sweep", nil)
	stub.MockTransactionStart("t0")
	ctx := newCtx(stub)

	type cls struct {
		id        string
		malicious bool
	}
	var peers []cls
	for i := 0; i < nPeersPerClass; i++ {
		peers = append(peers, cls{id: fmt.Sprintf("mal-%d", i), malicious: true})
		peers = append(peers, cls{id: fmt.Sprintf("honest-%d", i), malicious: false})
	}
	for _, p := range peers {
		saveTrust(ctx, TrustRecord{PeerID: p.id, Score: TrustInitTier1, IsRSUPeer: true, State: PeerStateActive, DocType: "TRUST_RECORD"})
	}

	for r := 0; r < rounds; r++ {
		for _, p := range peers {
			flagProb := honestFlagProb
			if p.malicious {
				flagProb = malFlagProb
			}
			correct := rng.Float64() >= flagProb // true = behaved well this round
			updateTrust(ctx, p.id, correct, false)
		}
	}

	tp, tn, fp, fn := 0, 0, 0, 0
	for _, p := range peers {
		r := loadTrust(ctx, p.id)
		belowThreshold := r.Score <= tauMin
		switch {
		case p.malicious && belowThreshold:
			tp++
		case p.malicious && !belowThreshold:
			fn++
		case !p.malicious && belowThreshold:
			fp++
		default:
			tn++
		}
	}
	total := tp + tn + fp + fn
	return mcc(tp, tn, fp, fn), float64(fp) / float64(total/2), float64(fn) / float64(total/2)
}

// ── τ_min^C sweep: controller divergence-penalty pathway ───────────────────

const (
	nCtrlPerClass    = 40
	ctrlRounds       = 20   // fixed round budget (ΔC- = 0.20 fixed → 5 divergences drains 1.0→0)
	malDivergeProb   = 0.90 // malicious controller: diverges almost every round
	honestDivergeProb = 0.05 // honest controller: rare divergence noise (transient network issues)
)

func runControllerTrustSweep(tauMinC float64) (mccVal float64) {
	rng := rand.New(rand.NewSource(sweepRandomSeed))
	stub := shimtest.NewMockStub("teta-sweep-ctrl", nil)
	stub.MockTransactionStart("t0")
	ctx := newCtx(stub)

	type cls struct {
		id        string
		malicious bool
	}
	var ctrls []cls
	for i := 0; i < nCtrlPerClass; i++ {
		ctrls = append(ctrls, cls{id: fmt.Sprintf("mal-ctrl-%d", i), malicious: true})
		ctrls = append(ctrls, cls{id: fmt.Sprintf("honest-ctrl-%d", i), malicious: false})
	}
	for _, c := range ctrls {
		saveCtrlTrust(ctx, ControllerTrustRecord{ControllerID: c.id, Score: 1.0, ZoneID: "zone-1", DocType: "CTRL_TRUST_RECORD"})
	}

	for r := 0; r < ctrlRounds; r++ {
		for _, c := range ctrls {
			p := honestDivergeProb
			if c.malicious {
				p = malDivergeProb
			}
			if rng.Float64() < p {
				updateCtrlTrust(ctx, c.id)
			}
		}
	}

	tp, tn, fp, fn := 0, 0, 0, 0
	for _, c := range ctrls {
		r := loadCtrlTrust(ctx, c.id)
		belowThreshold := r.Score < tauMinC
		switch {
		case c.malicious && belowThreshold:
			tp++
		case c.malicious && !belowThreshold:
			fn++
		case !c.malicious && belowThreshold:
			fp++
		default:
			tn++
		}
	}
	return mcc(tp, tn, fp, fn)
}

// ── τ_min^gt sweep: caller-authorization admission rate + R_min coupling ───

func runAdmissionSweep(tauMinGT, deltaPlus, tau0 float64) (admitRate float64, rMin int) {
	rng := rand.New(rand.NewSource(sweepRandomSeed))
	n := 500
	admitted := 0
	for i := 0; i < n; i++ {
		score := rng.Float64() // synthetic caller trust score, uniform [0,1)
		if score >= tauMinGT {
			admitted++
		}
	}
	rMin = int(ceilDiv(tauMinGT-tau0, deltaPlus))
	return float64(admitted) / float64(n), rMin
}

func ceilDiv(a, b float64) float64 {
	q := a / b
	i := float64(int(q))
	if q > i {
		return i + 1
	}
	return i
}

// ── Driver ───────────────────────────────────────────────────────────────

func TestTrustParameterSweep(t *testing.T) {
	// Baseline (current calibrated) values.
	const (
		baseTauMin   = 0.10
		baseTauMinGT = 0.50
		baseTauMinC  = 0.30
		baseDeltaP   = 0.05
		baseDeltaM   = 0.10
		baseTQuar    = int64(30000)
		tau0         = 0.10
	)

	fmt.Println("\n=== τ_min sweep (Δ+, Δ-, T_quar held at baseline) ===")
	for _, v := range []float64{0.05, baseTauMin, 0.15} {
		m, fp, fn := runPeerTrustSweep(v, baseDeltaP, baseDeltaM, baseTQuar)
		fmt.Printf("  tau_min=%.2f  MCC=%.4f  FP_rate=%.4f  FN_rate=%.4f\n", v, m, fp, fn)
	}

	fmt.Println("\n=== Delta+ sweep (tau_min, Delta-, T_quar held at baseline; R_min recomputed) ===")
	for _, v := range []float64{0.03, baseDeltaP, 0.07} {
		m, fp, fn := runPeerTrustSweep(baseTauMin, v, baseDeltaM, baseTQuar)
		rmin := int(ceilDiv(baseTauMinGT-tau0, v))
		fmt.Printf("  delta_plus=%.2f  MCC=%.4f  FP_rate=%.4f  FN_rate=%.4f  R_min=%d\n", v, m, fp, fn, rmin)
	}

	fmt.Println("\n=== Delta- sweep (tau_min, Delta+, T_quar held at baseline) ===")
	for _, v := range []float64{0.05, baseDeltaM, 0.15} {
		m, fp, fn := runPeerTrustSweep(baseTauMin, baseDeltaP, v, baseTQuar)
		fmt.Printf("  delta_minus=%.2f  MCC=%.4f  FP_rate=%.4f  FN_rate=%.4f\n", v, m, fp, fn)
	}

	fmt.Println("\n=== T_quar sweep (tau_min, Delta+, Delta- held at baseline) ===")
	for _, v := range []int64{20000, baseTQuar, 40000} {
		m, fp, fn := runPeerTrustSweep(baseTauMin, baseDeltaP, baseDeltaM, v)
		fmt.Printf("  T_quar=%dms (%d rounds)  MCC=%.4f  FP_rate=%.4f  FN_rate=%.4f\n", v, v/beaconTb, m, fp, fn)
	}

	fmt.Println("\n=== tau_min^C sweep (Delta_C- fixed at calibrated 0.20) ===")
	for _, v := range []float64{0.20, baseTauMinC, 0.40} {
		m := runControllerTrustSweep(v)
		fmt.Printf("  tau_min_C=%.2f  MCC=%.4f\n", v, m)
	}

	fmt.Println("\n=== tau_min^gt sweep (admission rate + R_min coupling, Delta+ held at baseline) ===")
	for _, v := range []float64{0.40, baseTauMinGT, 0.60} {
		admitRate, rmin := runAdmissionSweep(v, baseDeltaP, tau0)
		fmt.Printf("  tau_min_gt=%.2f  admit_rate=%.4f  R_min=%d\n", v, admitRate, rmin)
	}
}
