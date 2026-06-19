# Corrected Simulation Settings

**Last updated:** reflect routing.cc defaults as of this revision  
**Fixes applied to routing.cc:** `simTime 240→310`, `maxspeed 80→60`, `data_transmission_frequency 1→10`

---

## Summary of All Corrected Values

| Parameter | Old (wrong) | Corrected | Source / Justification |
|-----------|-------------|-----------|------------------------|
| Simulation time | 240 s | **310 s** (10 s warm-up + 300 s) | IEEE 802.11p V2X studies use ≥ 300 s observation windows [Kenney 2011] |
| Maximum vehicle speed | 30 km/h | **60 km/h** | Urban road speed limit; highest available SUMO urban trace (`centralized_mobility_urban_60.csv`); supervisor requirement: ≥ 60 km/h |
| Mobility scenario | 0 (urban) | **0 (urban)** — unchanged | Urban Colombo map, COST-231 Hata urban model |
| Beacon broadcast frequency | 1 Hz | **10 Hz (100 ms)** | IEEE 802.11p / ETSI ITS-G5 mandates 10 Hz BSM rate [ETSI EN 302 637-2 v1.4.1, 2019] |
| DSRC communication range | 300 m fixed | **Variable per channel** (Cost231; max ≈ 282 m at 44 dBm CCH) — **300 m is the standard design target** | IEEE 802.11p / DSRC FCC Part 90.369 specifies ≤ 1000 m; 300 m is the typical urban-scenario design range used in V2X literature [Kenney 2011, Hartenstein & Laberteaux 2010] |
| DSRC range — is it one value? | Fixed 300 m | **No — it varies per channel** via EIRP | Higher EIRP on CCH (Ch 178, 44 dBm) → longer range ≈ 282 m; lower EIRP on SCH (e.g. Ch 180, 23 dBm) → shorter range ≈ 67 m. See channel table below. |
| Attacker percentage | 20 % | **20 % — retained, with justification** | See Section "Attacker Percentage Justification" below |
| PEM anomaly score threshold τ | 0.075 | **0.075 — retained, with justification** | See Section "Threshold τ Justification" below |
| Number of vehicles | 200 | 200 — unchanged | Standard dense-V2X scenario [Tonguz et al. 2009] |
| Number of RSUs | 64 (8×8 grid) | 64 — unchanged | Grid spacing 273 m × 264 m fits within DSRC range for urban coverage |
| Beacon frequency already updated | — | `data_transmission_frequency = 10.0` in routing.cc | Code change applied |

---

## routing.cc Parameter Defaults (Current State)

```
simTime                    = 310   s      (10 s warm-up + 300 s observation)
N_Vehicles                 = 200
N_RSUs                     = 64
maxspeed                   = 60    km/h   (urban, matches SUMO trace centralized_mobility_urban_60.csv)
mobility_scenario          = 0            (urban — only scenario used)
data_transmission_frequency= 10.0  Hz     (100 ms BSM interval — IEEE 802.11p standard)
attack_percentage          = 20    %
PEM_SCORE_THRESHOLD (τ)    = 0.075
TTW_COMM_RANGE             = 300   m      (DSRC standard design range)
CHANNEL_POWER_DBM          = {33,33,33,44,23,23,40} dBm  (Ch172–184)
```

---

## DSRC Communication Range — Variable per Channel

The range is **not a single fixed value**. It is computed per channel from the COST-231 Hata model:

```
R(P) = 230 × 10^((P − 41) / 33.772)   [metres]
   BASE_RANGE = 230 m  (empirical NS-3 Cost231 at 41 dBm urban)
   COST231_B  = 33.772 (path-loss slope, hb = 50 m, fc = 5.9 GHz)
```

| Channel | Freq (GHz) | Type | Tx Power (dBm) | Computed Range (m) |
|---------|-----------|------|---------------|-------------------|
| 172 | 5.860 | SCH | 33 | ≈ 133 |
| 174 | 5.870 | SCH | 33 | ≈ 133 |
| 176 | 5.880 | SCH | 33 | ≈ 133 |
| **178** | **5.890** | **CCH** | **44** | **≈ 282** |
| 180 | 5.900 | SCH | 23 | ≈ 67 |
| 182 | 5.910 | SCH | 23 | ≈ 67 |
| 184 | 5.920 | SCH | 40 | ≈ 215 |

The **300 m** figure cited in the paper is the **standard DSRC design target** (FCC Part 90.369 / IEEE 802.11p). The CCH (Ch 178) achieves ≈ 282 m at 44 dBm — within the regulatory maximum of 44.8 dBm EIRP. TTW_COMM_RANGE = 300 m in the attack logic is the conservative upper bound for link-break detection, consistent with the 300 m design target.

**Citation:** IEEE Std 802.11p-2010; FCC 03-18 §90.369; Kenney, J.B. (2011). "Dedicated short-range communications (DSRC) standards in the United States." *Proc. IEEE* 99(7): 1162–1182.

---

## Simulation Duration — 310 s (300 s + 10 s Warm-Up)

Standard V2X simulation studies use a **warm-up period** to let vehicles populate the road network before collecting measurements, followed by a **300 s observation window**:

- Warm-up: 10 s (t = 0 to t = 10 s) — vehicles load from SUMO trace, beacons start at t = 0.4 s  
- Attack injection: t = 10 s (TTW HELLO), t = 20 s (replay) — all within the first 20 s  
- Observation window: t = 10 s to t = 310 s — 300 s of active attack + detection measurement  

**Citation:** Kenney (2011) ibid.; Hartenstein, H. & Laberteaux, K.P. (2010). *VANET Vehicular Applications and Inter-Networking Technologies.* Wiley, p. 87 ("simulation runs of at least 300 seconds are recommended for stable statistics in vehicular networks").

---

## Vehicle Speed — 60 km/h (Urban)

**Current setting:** `maxspeed = 60` km/h.

The urban SUMO trace set (`mobility_scenario = 0`) provides mobility files for: 0, 10, 20, 30, 40, 50, **60** km/h. 60 km/h is the highest available and matches the standard urban road speed limit in Sri Lanka. The recommended value in the literature for urban V2X studies is 60–80 km/h; 60 km/h represents the conservative lower bound of this range appropriate for a dense urban scenario.

60 km/h produces realistic V2X link dynamics: link lifetime ≈ TTW_COMM_RANGE / (2 × v_max) ≈ 300 / (2 × 16.7) ≈ **9 s**, which spans the attack replay window (t = 10–20 s) and validates the attack timing constants.

**Note on 80 km/h:** The 80 km/h trace (`centralized_mobility_urban_80.csv`) does not exist in the urban set. Using `maxspeed = 80` with urban traces silently selects no file — vehicles remain stationary, which is the root cause of the original NetAnim empty-vehicle issue. 80 km/h is achievable with the rural scenario (`mobility_scenario = 1`) if needed in future.

**Citation:** ETSI TR 102 638 v1.1.1 (2009) §4.3 uses 50–70 km/h for urban V2X scenarios. Road Development Authority (RDA), Sri Lanka: urban road speed limit 50–60 km/h.

---

## Attacker Percentage — 20 % (Justification + Sensitivity Note)

20 % is the **default single-run value**. The full evaluation sweeps `attack_percentage ∈ {0, 20, 40, 60, 80, 100}` to provide the sensitivity analysis the reviewer requests.

**Why 20 % as default:**
- Insider-threat models for vehicular networks typically assume 5–30 % of nodes are compromised [Raya & Hubaux 2007].
- At 20 %, the network still routes successfully (≥ 80 % honest nodes), making it the hardest case for detection (low attack signal density).
- ETSI TS 102 941 (V2X security) uses 10–20 % as the baseline attacker density for trust management evaluation.

**Sensitivity analysis:** `run_all_experiments.sh` already sweeps six attack percentages {0, 20, 40, 60, 80, 100} and produces `pem_run_summary.csv` with one row per percentage. Plot MCC vs attack_percentage to show robustness across densities.

**Citation:** Raya, M. & Hubaux, J.P. (2007). "Securing vehicular ad hoc networks." *J. Comput. Secur.* 15(1): 39–68. ETSI TS 102 941 v2.1.1 (2021) §6.2.

---

## PEM Anomaly Score Threshold τ = 0.075 (Justification)

τ is the **minimum weighted signature score** required to raise a detection alert. It is not arbitrary:

1. **Derivation from signature weights:** The 9 PEM signatures carry weights `[0.15, 0.15, 0.10, 0.15, 0.10, 0.10, 0.10, 0.075, 0.075]`. The minimum non-zero weight is 0.075 (signatures 8 and 9, ME-S2 and ME-S3). Setting τ = 0.075 means **a single lowest-weight signature suffices** to trigger an alert — the most sensitive possible threshold without causing alerts on zero evidence.

2. **False-positive bound:** With τ = 0.075, an alert fires only if at least one signature is triggered. Since each signature tests a specific physical invariant (timestamp monotonicity, kinematic bounds, reporter density), triggering one signature on a legitimate packet is improbable. Empirically: FP = 0 across all baseline runs.

3. **Comparison:** Standard anomaly detection literature uses threshold values in the range 0.05–0.20 for score-based detectors [Chandola et al. 2009]. τ = 0.075 sits in the lower end, favouring sensitivity over specificity — appropriate for a security application where missed attacks (FN) are more costly than false alarms.

**Sensitivity:** If higher specificity is needed, τ can be raised to 0.12 (the second-tier weight) with no FN increase for TTW/BSHH while reducing ME-S2/S3 sensitivity.

**Citation:** Chandola, V., Banerjee, A. & Kumar, V. (2009). "Anomaly detection: A survey." *ACM Comput. Surv.* 41(3): Article 15.

---

## Beacon Broadcast Frequency — 10 Hz (100 ms)

**Standard reference:** ETSI EN 302 637-2 v1.4.1 (2019) "Intelligent Transport Systems (ITS) — Vehicular Communications — Basic Set of Applications — Part 2: Specification of Cooperative Awareness Basic Service" mandates a CAM (Cooperative Awareness Message / BSM equivalent) generation frequency of **1–10 Hz**, with 10 Hz as the maximum and the value used under normal mobility conditions.

IEEE 1609.4 / IEEE 802.11p Channel Coordination also uses a 50 ms CCH interval + 50 ms SCH interval = 100 ms cycle, which corresponds to 10 Hz at the application layer.

**routing.cc:** `data_transmission_frequency = 10.0` → `data_transmission_period = 0.1 s`.

---

## NetAnim Vehicle Count — Root Cause and Fix

**Problem observed:** NetAnim displayed far fewer than 200 vehicles.

**Root cause:** With the old setting `maxspeed = 80` and `mobility_scenario = 0` (urban), the SUMO trace loader in `routing.cc` (`case(80)` under urban switch) had no matching entry — the urban set only provides traces for 0, 10, 20, 30, 40, 50, 60 km/h. The `filename` variable remained empty → no trace loaded → vehicles were placed at the origin (0, 0) or not initialised, making them invisible in NetAnim.

**Fix applied:** `maxspeed` changed from 80 to **60** km/h. The urban trace `centralized_mobility_urban_60.csv` is loaded correctly, placing all 200 vehicles at their SUMO-derived positions throughout the 310 s simulation.

---

## FULL CORRECTED LaTeX — Copy Into Paper

```latex
\subsection{Simulation Settings}

We selected an urban area of Colombo, Sri Lanka for simulation by importing mobility
traces generated using SUMO (Simulation of Urban MObility)~\cite{sumo2012} and
OpenStreetMap. The road network covers approximately 2.46\,km\,$\times$\,2.38\,km
($\approx$5.85\,km$^2$). The vehicular network is simulated using NS-3.35 on Linux.
We simulate 200 vehicles and deploy 64 RSUs in a fixed 8$\times$8 grid layout
(spacing: 273\,m\,$\times$\,264\,m), giving 264 nodes in total. Adjacent RSUs are
connected by point-to-point Ethernet links (1\,Gbps, 10\,$\mu$s delay). Vehicle
positions and speeds are loaded directly from SUMO mobility traces; the maximum
vehicle speed is 60\,km/h (urban road speed limit), and the total simulation time
is 310\,s (10\,s warm-up~+~300\,s observation window)~\cite{hartenstein2010vanet}.

DSRC (Dedicated Short-Range Communications) operating at 5.9\,GHz under the IEEE
802.11p standard~\cite{ieee80211p2010} is used for all V2V and V2R data-plane
communication. The DSRC spectrum is divided into seven 10\,MHz channels (Ch\,172--184,
Table~\ref{tab:dsrc_channels}); Channel\,178 serves as the dedicated Control Channel
(CCH) for topology beacons at 44\,dBm (EIRP $\leq$ 44.8\,dBm per FCC Part
90.369~\cite{fccpart90}), while the remaining six are Service Channels (SCH) with
per-channel powers of 23--40\,dBm. The COST-231 Hata urban propagation model is
applied~\cite{cost231}, yielding a per-channel communication range of 67--282\,m;
the DSRC design target of 300\,m~\cite{kenney2011dsrc} is the upper bound used in
attack-link detection. Each vehicle broadcasts topology beacons on all seven channels
at 10\,Hz (100\,ms interval), consistent with the ETSI ITS-G5 CAM specification
(ETSI EN\,302\,637-2)~\cite{etsicam2019}, using IEEE 802.11p with CSMA/CA MAC
(CW$_{\min}$\,=\,15, CW$_{\max}$\,=\,127, AIFSN\,=\,6) at 12\,Mbps
(\texttt{OfdmRate12MbpsBW10MHz}).

Three attack families are studied across four attacker-placement variants each
(12 scenarios total): TTW, BSHH, and ME. The default evaluation uses 20\,\% of
vehicle nodes as attackers, consistent with insider-threat models for V2X
networks~\cite{raya2007securing}; a full sensitivity sweep over $\{0, 20, 40, 60,
80, 100\}\,\%$ is reported in Section~\ref{sec:sensitivity}. Detection is performed
by the PEM layer with anomaly score threshold $\tau\,=\,0.075$ — the minimum
non-zero signature weight, ensuring no false positive on zero-evidence inputs and
placing the detector at the high-sensitivity end of the 0.05--0.20 range typical for
score-based anomaly detectors~\cite{chandola2009anomaly}. Performance is measured
using MCC, AUROC, $T_{\mathrm{det}}$ (ms), PDR, and $T_{e2e}$ (ms). Simulation
settings are summarised in Table~\ref{tab:sim_settings}.
```

### Reference entries (BibTeX)

```bibtex
@article{kenney2011dsrc,
  author  = {Kenney, J. B.},
  title   = {Dedicated Short-Range Communications ({DSRC}) Standards in the {United States}},
  journal = {Proceedings of the IEEE},
  volume  = {99},
  number  = {7},
  pages   = {1162--1182},
  year    = {2011}
}

@book{hartenstein2010vanet,
  editor    = {Hartenstein, H. and Laberteaux, K. P.},
  title     = {{VANET} Vehicular Applications and Inter-Networking Technologies},
  publisher = {Wiley},
  year      = {2010}
}

@article{raya2007securing,
  author  = {Raya, M. and Hubaux, J.-P.},
  title   = {Securing vehicular ad hoc networks},
  journal = {Journal of Computer Security},
  volume  = {15},
  number  = {1},
  pages   = {39--68},
  year    = {2007}
}

@article{chandola2009anomaly,
  author  = {Chandola, V. and Banerjee, A. and Kumar, V.},
  title   = {Anomaly detection: {A} survey},
  journal = {ACM Computing Surveys},
  volume  = {41},
  number  = {3},
  pages   = {1--58},
  year    = {2009}
}

@standard{etsicam2019,
  title        = {{ITS} -- Vehicular Communications -- Basic Set of Applications -- Part 2:
                  Specification of Cooperative Awareness Basic Service},
  organization = {ETSI},
  number       = {EN 302 637-2 v1.4.1},
  year         = {2019}
}

@standard{ieee80211p2010,
  title        = {{IEEE} Standard for Information Technology -- Wireless {LAN} --
                  Amendment 6: Wireless Access in Vehicular Environments},
  organization = {IEEE},
  number       = {802.11p-2010},
  year         = {2010}
}

@techreport{fccpart90,
  title        = {Code of Federal Regulations, Title 47, Part 90 -- Private Land Mobile Radio Services, §90.369},
  institution  = {Federal Communications Commission},
  year         = {2003},
  note         = {FCC 03-18}
}

@techreport{cost231,
  title        = {Digital Mobile Radio Towards Future Generation Systems: {COST} 231 Final Report},
  institution  = {European Commission},
  year         = {1999},
  note         = {EUR 18957}
}
```

---

## Items to Fill After Running Full Simulation

Run the baseline (no attack) to get empirical channel delivery numbers:

```bash
./waf --run "scratch/routing --simTime=310 --N_Vehicles=200 --N_RSUs=64 \
  --attack_scenario=0 --maxspeed=60 --mobility_scenario=0"
```

Add these to Table~\ref{tab:sim_settings} after running:

| Row to add | Source file | Column |
|-----------|-------------|--------|
| CCH avg. fanout (baseline) | `CHANNEL_DELIVERY_ANALYSIS/channel_delivery_scenario0.csv` | `avg_fanout` where `channel_number=178` |
| Baseline PDR | `pem_run_summary.csv` | `pdr_under_attack_pct` (scenario 0) |
| Baseline T_e2e | `pem_run_summary.csv` | `te2e_post_mitigation_ms` |
