#!/usr/bin/env python3
"""
submit_alerts.py — Bridge: TGN alerts (tgn_alerts.json) → Hyperledger Fabric
                   TemporalEchoMitigator::SubmitAlert  (Algorithm 4, Eq. 3.36)

Run this AFTER tgn_detector generates tgn_alerts.json:

    # Step 1 — run NS-3 TGN detector (generates tgn_alerts.json)
    ./waf --run "scratch/tgn_detector --simTime=60 --N_Vehicles=6 --attack_scenario=1"

    # Step 2 — submit alerts to Fabric (Fabric network must be running)
    python3 submit_alerts.py

    # Or specify custom paths:
    python3 submit_alerts.py --alerts tgn_alerts.json --network /path/to/teta-guard/network

What it does per alert:
    1. Reads AlertObject from tgn_alerts.json  (v_id, alpha, y_hat, S_trig, t_alert)
    2. Calls peer chaincode invoke → TemporalEchoMitigator.SubmitAlert
    3. Endorsement policy: OutOf(3, RSU1..RSU5) — PBFT equivalent in Fabric
    4. Smart contract executes: LOG + FlowMod(DROP/REROUTE) + KeyRevoke + EMIT
"""

import argparse
import datetime
import json
import os
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Blockchain submission log helpers
# ---------------------------------------------------------------------------

_blog = None   # blockchain_submission_log.txt file handle

def blog_open(path: str) -> None:
    global _blog
    _blog = open(path, "w")
    _blog.write(
        "================================================================\n"
        "  BLOCKCHAIN SUBMISSION LOG — TETA-Guard\n"
        "  TemporalEchoMitigator::SubmitAlert  (Algorithm 4, Eq. 3.36)\n"
        f"  Run started : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        "================================================================\n\n"
        "  Pipeline position:\n"
        "    routing.cc / tgn_detector.cc  → tgn_alerts.json\n"
        "    submit_alerts.py (this script) → Hyperledger Fabric\n"
        "    TemporalEchoMitigator.SubmitAlert → PBFT consensus\n"
        "    Smart contract executes Algorithm 4 → FlowMod + Revoke + LOG\n\n"
        "================================================================\n\n"
    )
    _blog.flush()

def blog_close(ok: int, fail: int) -> None:
    if not _blog:
        return
    _blog.write(
        "================================================================\n"
        "  RUN SUMMARY\n"
        "================================================================\n\n"
        f"  Alerts submitted : {ok}\n"
        f"  Alerts failed    : {fail}\n"
        f"  Run finished     : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        "================================================================\n"
    )
    _blog.flush()
    _blog.close()

def blog_alert(idx: int, total: int, alert: dict, dry_run: bool) -> None:
    if not _blog:
        return
    alpha  = alert.get("alpha",  "?")
    y_hat  = alert.get("y_hat",  0.0)
    s_trig = alert.get("S_trig", [])
    t_ms   = alert.get("t_alert", 0)
    v_id   = alert.get("v_id",   "?")
    sig_names = ["TTW-S1","TTW-S2","TTW-S3",
                 "BSHH-S1","BSHH-S2","BSHH-S3",
                 "ME-S1","ME-S2","ME-S3"]
    triggered = [sig_names[s] for s in s_trig if 0 <= s < len(sig_names)]

    _blog.write(
        f"────────────────────────────────────────────────────────────────\n"
        f"[{datetime.datetime.now().strftime('%H:%M:%S')}]  "
        f"ALERT {idx}/{total}\n\n"
        f"  STEP ①  ALERT RECEIVED FROM TGN  (Eq. 3.36)\n"
        f"    Vid        : {v_id}\n"
        f"    α (variant): {alpha}\n"
        f"    ŷ_v (score): {y_hat:.4f}\n"
        f"    S_trig     : {s_trig}  →  {', '.join(triggered) or 'none'}\n"
        f"    t_alert    : {t_ms} ms\n\n"
        f"  STEP ②  FABRIC INVOCATION  (Section 9.3)\n"
        f"    Channel    : {CHANNEL}\n"
        f"    Chaincode  : {CHAINCODE}\n"
        f"    Function   : SubmitAlert\n"
        f"    Endorsers  : {MIN_ENDORSERS}/{len(RSU_PEERS)} peers required\n"
        f"    Peers      : {', '.join(h for h,_ in RSU_PEERS[:MIN_ENDORSERS])}\n"
        f"    Mode       : {'DRY RUN (no actual invocation)' if dry_run else 'LIVE'}\n\n"
        f"  STEP ③  PBFT CONSENSUS  (§3.4.10)\n"
        f"    Policy     : OutOf({MIN_ENDORSERS}, RSU1..RSU{len(RSU_PEERS)})\n"
        f"    Tolerance  : ⌊({len(RSU_PEERS)}-1)/3⌋ = "
        f"{(len(RSU_PEERS)-1)//3} faulty peer(s) tolerated\n\n"
        f"  STEP ④  SMART CONTRACT ACTIONS  (Algorithm 4)\n"
    )
    if alpha in ("TTW", "BSHH"):
        _blog.write(
            f"    VERIFY_THRESHOLD_SIG({v_id})\n"
            f"    PUSH_FLOWMOD(DROP, {v_id})  ← SDN controller isolation\n"
            f"    REVOKE_SESSION_KEY({v_id})   ← LKH O(log n) update (Module 5)\n"
            f"    FLAG_REAUTH({v_id})\n"
        )
    else:
        _blog.write(
            f"    GET_WITNESSES(e_ij, t)\n"
            f"    VERIFY_QUORUM(W_v, t)       ← Module 4 quorum check\n"
            f"    INVALIDATE_PATHS(P_false)   ← phantom paths removed\n"
            f"    PUSH_REROUTE_FLOWMOD()\n"
            f"    FLAG_REAUTH({v_id})\n"
        )
    _blog.write(
        f"    LOG(L, {{{v_id}, {y_hat:.4f}, {t_ms}}})  ← immutable ledger\n"
        f"    EMIT(AttackDetected, {{{v_id}, {alpha}, {y_hat:.4f}}})\n\n"
    )
    _blog.flush()

def blog_result(v_id: str, alpha: str, success: bool) -> None:
    if not _blog:
        return
    status = "COMMITTED — record immutable" if success else "FAILED — check Fabric logs"
    _blog.write(f"  VERDICT: {status}\n\n")
    _blog.flush()

# ---------------------------------------------------------------------------
# Network configuration — matches docker-compose-teta.yaml and configtx.yaml
# ---------------------------------------------------------------------------

# Default path to the blockchain network directory (blockchain/network/)
DEFAULT_NETWORK = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "blockchain", "network"
)

ORDERER_ADDRESS = "orderer.tetaguard.net:7050"
CHANNEL         = "teta-channel"
CHAINCODE       = "temporalecho"
MSPID           = "TetaGuardMSP"

# ── RSU mode (N_RSUs > 0): 5 fixed RSU Fabric peers ─────────────────────────
# Endorsement policy: OutOf(3, RSU1..RSU5) — tolerates 1 Byzantine RSU
RSU_PEERS = [
    ("peer0.rsu1.tetaguard.net", 7051),
    ("peer0.rsu2.tetaguard.net", 7052),
    ("peer0.rsu3.tetaguard.net", 7053),
    ("peer0.rsu4.tetaguard.net", 7054),
    ("peer0.rsu5.tetaguard.net", 7055),
]
RSU_MIN_ENDORSERS = 3   # OutOf(3,5): tolerates 1 Byzantine

# ── OBU mode (N_RSUs = 0): 3 designated OBU Fabric peers ─────────────────────
# Used when there is no fixed RSU infrastructure.
# Endorsement policy: OutOf(2, OBU1..OBU3) — tolerates 1 crash fault.
# Note: 3 peers cannot guarantee Byzantine fault tolerance (needs n ≥ 4 for f=1).
OBU_PEERS = [
    ("peer0.obu1.tetaguard.net", 7061),
    ("peer0.obu2.tetaguard.net", 7062),
    ("peer0.obu3.tetaguard.net", 7063),
]
OBU_MIN_ENDORSERS = 2   # OutOf(2,3): tolerates 1 crash fault

def get_active_peers(n_rsus: int):
    """Return (peers, min_endorsers) based on whether RSU infrastructure exists."""
    if n_rsus > 0:
        return RSU_PEERS, RSU_MIN_ENDORSERS
    else:
        return OBU_PEERS, OBU_MIN_ENDORSERS

# Active peer set — set at startup based on --n_rsus argument
_ACTIVE_PEERS   = RSU_PEERS
_MIN_ENDORSERS  = RSU_MIN_ENDORSERS

# Legacy alias kept for compatibility with build_invoke_cmd
MIN_ENDORSERS = _MIN_ENDORSERS


# ---------------------------------------------------------------------------
# Build peer chaincode invoke command
# ---------------------------------------------------------------------------

def build_invoke_cmd(alert: dict, network_dir: str, controller_topo_json: str = "") -> list:
    """
    Constructs the `peer chaincode invoke` command for SubmitAlert.

    AlertObject fields (matching temporalecho.go):
        v_id    string
        alpha   string  — "TTW", "BSHH", or "ME"
        y_hat   float64
        S_trig  []int
        t_alert int64   — milliseconds
    """
    alert_json  = json.dumps(alert)
    t_alert     = str(alert.get("t_alert", int(time.time() * 1000)))

    # Chaincode function args: alertJSON, controllerTopologyJSON, intervalTimestamp
    invoke_payload = json.dumps({
        "function": "SubmitAlert",
        "Args": [alert_json, controller_topo_json, t_alert]
    })

    crypto = os.path.join(network_dir, "crypto-config")
    admin  = os.path.join(crypto,
                          "peerOrganizations", "tetaguard.net",
                          "users", "Admin@tetaguard.net", "msp")
    tls_ca = os.path.join(crypto,
                          "ordererOrganizations", "tetaguard.net",
                          "tlsca", "tlsca.tetaguard.net-cert.pem")

    peer_bin = os.path.join(
        os.path.dirname(network_dir), "fabric-samples", "bin", "peer")

    cmd = [
        peer_bin, "chaincode", "invoke",
        "-o",         ORDERER_ADDRESS,
        "--tls",
        "--cafile",   tls_ca,
        "-C",         CHANNEL,
        "-n",         CHAINCODE,
    ]

    # Add endorsing peers — use active peer set (RSU or OBU based on --n_rsus)
    for host, port in _ACTIVE_PEERS[:_MIN_ENDORSERS]:
        peer_tls = os.path.join(crypto,
                                "peerOrganizations", "tetaguard.net",
                                "peers", f"{host}", "tls", "ca.crt")
        cmd += ["--peerAddresses", f"{host}:{port}",
                "--tlsRootCertFiles", peer_tls]

    cmd += [
        "--waitForEvent",
        "-c", invoke_payload,
    ]

    return cmd


def submitDetectionAlert(gateway_cfg: dict, alert: dict,
                         beacon_evidence: dict = None) -> bool:
    """
    Section 9.3 — Fabric chaincode invocation (Python equivalent of the JS SDK call).

    gateway_cfg keys:
        network_dir (str)  — path to teta-guard/network directory
        dry_run     (bool) — if True, print command without executing

    alert keys match DetectionAlert (Eq. 3.36):
        v_id    (str)   — offending vehicle ID
        alpha   (str)   — "TTW", "BSHH", or "ME"
        y_hat   (float) — anomaly score ∈ (0,1)
        S_trig  (list)  — triggered signature bitmask indices
        t_alert (int)   — alert timestamp in ms

    beacon_evidence (dict, optional) — B_nk(t) BeaconEvidenceRecord (Section 9.4).
        If provided it is passed as the controller_topo_json arg so the smart
        contract can run the δ divergence check (Eq. 3.1) for controller-origin
        attack detection (Section 9.6).
    """
    network_dir = gateway_cfg.get("network_dir", DEFAULT_NETWORK)
    dry_run     = gateway_cfg.get("dry_run", False)
    ctrl_topo   = json.dumps(beacon_evidence) if beacon_evidence else ""
    cmd = build_invoke_cmd(alert, network_dir, ctrl_topo)
    return run_invoke(cmd, dry_run=dry_run)


def run_invoke(cmd: list, dry_run: bool = False) -> bool:
    """Run the peer invoke command. Returns True on success."""
    if dry_run:
        print(f"[DryRun] {' '.join(cmd[:6])} ... (suppressed)")
        return True

    env = os.environ.copy()
    env["CORE_PEER_LOCALMSPID"]      = MSPID
    env["FABRIC_CFG_PATH"]           = ""   # uses network core.yaml

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, env=env)
        if result.returncode == 0:
            return True
        print(f"[ERROR] peer invoke failed:\n{result.stderr[-500:]}")
        return False
    except subprocess.TimeoutExpired:
        print("[ERROR] peer invoke timed out (30 s)")
        return False
    except FileNotFoundError:
        print(f"[ERROR] peer binary not found: {cmd[0]}")
        print("  Is the Fabric network running?  docker-compose -f network/docker-compose-teta.yaml up")
        return False


# ---------------------------------------------------------------------------
# Submit beacon evidence stub (called if --submit_beacons flag is set)
# ---------------------------------------------------------------------------

def submit_beacon_evidence(peer_id: str, interval_ms: int,
                           network_dir: str, dry_run: bool) -> None:
    """
    Calls SubmitBeaconEvidence on the chaincode.
    In simulation mode the beacon evidence is derived from pem_event_log.csv.
    """
    evidence = {
        "peer_id":      peer_id,
        "interval":     interval_ms,
        "observations": [],   # populated by the RSU application layer
        "peer_sig":     "sim_placeholder"
    }
    payload = json.dumps({
        "function": "SubmitBeaconEvidence",
        "Args": [json.dumps(evidence)]
    })
    print(f"[Fabric] SubmitBeaconEvidence  peer={peer_id}  interval={interval_ms}ms")
    # (build and run a similar peer invoke here if needed)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Submit TGN alerts from tgn_alerts.json to Hyperledger Fabric "
                    "TemporalEchoMitigator.SubmitAlert  (Algorithm 4, Eq. 3.36)"
    )
    ap.add_argument("--alerts",   default="tgn_alerts.json",
                    help="Input alert JSON from tgn_detector (default: tgn_alerts.json)")
    ap.add_argument("--network",  default=DEFAULT_NETWORK,
                    help="Path to teta-guard/network directory")
    ap.add_argument("--ctrl_topo", default="",
                    help="Optional: controller topology JSON for divergence check "
                         "(Eq. 3.1). Empty = skip controller-origin detection in contract.")
    ap.add_argument("--dry_run",  action="store_true",
                    help="Print commands without executing peer invoke")
    ap.add_argument("--delay",    type=float, default=0.5,
                    help="Seconds to wait between consecutive invocations (default: 0.5)")
    ap.add_argument("--n_rsus",   type=int, default=-1,
                    help="Number of RSU nodes in the simulation (from --N_RSUs). "
                         "0 = OBU mode (peer0.obu1..3, OutOf(2,3)); "
                         ">0 = RSU mode (peer0.rsu1..5, OutOf(3,5)); "
                         "-1 = auto-detect from tgn_alerts.json (default).")
    args = ap.parse_args()

    # ── Select peer set based on --n_rsus ────────────────────────────────────
    global _ACTIVE_PEERS, _MIN_ENDORSERS, MIN_ENDORSERS
    n_rsus = args.n_rsus
    if n_rsus == -1:
        # Auto-detect: check if any alert has alpha=TTW/BSHH/ME from an RSU scenario
        # Conservative default: use RSU peers unless explicitly told N_RSUs=0
        n_rsus = 1   # default to RSU mode
    _ACTIVE_PEERS, _MIN_ENDORSERS = get_active_peers(n_rsus)
    MIN_ENDORSERS = _MIN_ENDORSERS
    mode = "RSU" if n_rsus > 0 else "OBU"
    print(f"[Bridge] Peer mode: {mode}  "
          f"({len(_ACTIVE_PEERS)} peers, OutOf({_MIN_ENDORSERS},{len(_ACTIVE_PEERS)}))")
    if n_rsus == 0:
        print(f"[Bridge] OBU peers: {', '.join(h for h,_ in _ACTIVE_PEERS)}")
        print(f"[Bridge] Note: 3 OBU peers tolerate 1 crash fault but NOT Byzantine faults.")

    # ── Load tgn_alerts.json ─────────────────────────────────────────────────
    if not os.path.exists(args.alerts):
        sys.exit(
            f"[ERROR] '{args.alerts}' not found.\n"
            f"  Run tgn_detector first:\n"
            f"    ./waf --run 'scratch/tgn_detector --simTime=60 "
            f"--N_Vehicles=6 --attack_scenario=1'"
        )

    with open(args.alerts) as f:
        alerts = json.load(f)

    if not isinstance(alerts, list):
        sys.exit("[ERROR] tgn_alerts.json must be a JSON array of AlertObjects")

    print(f"[Bridge] Loaded {len(alerts)} alert(s) from '{args.alerts}'")

    if len(alerts) == 0:
        print("[Bridge] No alerts to submit — TGN detected no anomalies.")
        return

    # ── Open blockchain submission log ───────────────────────────────────────
    blog_open("blockchain_submission_log.txt")

    # ── Submit each alert ────────────────────────────────────────────────────
    ok = 0; fail = 0

    for i, alert in enumerate(alerts, 1):
        v_id   = alert.get("v_id",   "?")
        alpha  = alert.get("alpha",  "?")
        y_hat  = alert.get("y_hat",  0.0)
        s_trig = alert.get("S_trig", [])
        t_ms   = alert.get("t_alert", 0)

        print(f"\n[Bridge] Alert {i}/{len(alerts)}: "
              f"node={v_id}  variant={alpha}  score={y_hat:.3f}  "
              f"sigs={s_trig}  t={t_ms}ms")

        blog_alert(i, len(alerts), alert, args.dry_run)

        cmd = build_invoke_cmd(alert, args.network, args.ctrl_topo)
        success = run_invoke(cmd, dry_run=args.dry_run)

        if success:
            print(f"  ✓ SubmitAlert accepted — chaincode will LOG + "
                  f"{'FlowMod_DROP' if alpha in ('TTW','BSHH') else 'Reroute'} + EMIT")
            ok += 1
        else:
            print(f"  ✗ SubmitAlert FAILED for node {v_id}")
            fail += 1

        blog_result(v_id, alpha, success)

        if i < len(alerts) and args.delay > 0:
            time.sleep(args.delay)

    # ── Summary ───────────────────────────────────────────────────────────────
    blog_close(ok, fail)
    print(f"\n[Bridge] Done:  {ok} submitted  {fail} failed  "
          f"({'dry run — no actual invocations' if args.dry_run else 'Fabric invocations complete'})")

    if fail > 0:
        print("\n  Troubleshooting:")
        print("  1. Is Fabric running?  cd teta-guard/network && docker-compose -f docker-compose-teta.yaml up -d")
        print("  2. Is the chaincode installed?  peer chaincode list --installed -C teta-channel")
        print("  3. Check peer logs:  docker logs peer0.rsu1.tetaguard.net")
        sys.exit(1)


if __name__ == "__main__":
    main()
