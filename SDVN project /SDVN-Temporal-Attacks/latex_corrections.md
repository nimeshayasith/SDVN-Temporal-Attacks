# LaTeX Simulation Settings — What to Keep vs. What to Fix

This file lists every parameter in your `\subsection{Simulation Settings}` and the two
tables, showing the value in the LaTeX draft vs. the actual value in `routing.cc`.
Fix the highlighted items before submitting.

---

## 1. DSRC Channel Table (`tab:dsrc_channels`)

The power column is **correct** for urban `mobility_scenario = 0`:

| Ch | LaTeX Tx Power | Code (`CHANNEL_POWER_DBM`) | Status |
|----|---------------|---------------------------|--------|
| 172 | 33 dBm | 33.0 dBm | ✅ correct |
| 174 | 33 dBm | 33.0 dBm | ✅ correct |
| 176 | 33 dBm | 33.0 dBm | ✅ correct |
| **178 CCH** | **44 dBm** | **44.0 dBm** | ✅ correct |
| 180 | 23 dBm | 23.0 dBm | ✅ correct |
| 182 | 23 dBm | 23.0 dBm | ✅ correct |
| 184 | 40 dBm | 40.0 dBm | ✅ correct |

**TX count / RX count / Avg Fanout** — these come from a real simulation run.
Run the 200-vehicle baseline and copy the numbers from `channel_delivery_analysis.csv`:

```bash
./waf --run "scratch/routing --simTime=240 --N_Vehicles=200 --N_RSUs=64 \
  --attack_scenario=0 --maxspeed=30"
cat channel_delivery_analysis.csv
```

The columns you need: `tx_count`, `phyrxend_rx`, `avg_fanout`.
Replace the placeholder numbers in the table with those from the CSV.

> **Note on PDR wording in the body text:** The text says
> *"baseline PDR ≈ 15–30 %"*.  This refers to the **flow PDR** (multi-hop
> delivery from source to destination) not the per-channel beacon PDR.
> Verify this range from `pem_run_summary.csv` column `pdr_under_attack_pct`
> with `attack_scenario=0`.  If the range differs, update the text.

---

## 2. Simulation Settings Table (`tab:sim_settings`) — Row-by-row

### ✅ Rows that are CORRECT (no change needed)

| Parameter | LaTeX value | Code value |
|-----------|-------------|-----------|
| Network simulation tool | NS-3.35 (Linux, Ubuntu) | ✅ |
| Mobility trace extraction | SUMO, OpenStreetMap | ✅ |
| Number of nodes | 264 (200 vehicles, 64 RSUs) | `N_Vehicles=200`, `N_RSUs=64` ✅ |
| Vehicle placement | SUMO NS-2 trace, `ConstantVelocityMobilityModel` | ✅ |
| Simulation time | 240 s | `simTime = 240` ✅ |
| Maximum vehicle speed | 30 km/h (urban) | `maxspeed=30`, `mobility_urban_30_200veh.tcl` ✅ |
| Data plane | 5.9 GHz DSRC / IEEE 802.11p (7 channels, Ch 172–184) | ✅ |
| MAC mode | IEEE 802.11p Ad-hoc (`AdhocWifiMac`, QoS enabled) | ✅ |
| PHY data rate | 12 Mbps (`OfdmRate12MbpsBW10MHz`) | ✅ |
| DSRC comm. range | 300 m | `TTW_COMM_RANGE = 300.0` ✅ |
| Propagation loss model | COST-231 Hata (urban V2V) | `ns3::Cost231PropagationLossModel` ✅ |
| Beacon broadcast freq. | 1 Hz per vehicle per channel | 100 ms period = 10 Hz per channel ⚠️ — see below |
| CCH (Ch 178) Tx power | 44 dBm | `CHANNEL_POWER_DBM[3] = 44.0` ✅ |
| RL learning rate α | 0.1 | `learning_rate = 0.1` ✅ |
| RL discount factor γ | 0.5 | `discount_factor = 0.50` ✅ |
| Link-lifetime threshold | 0.4 s | `link_lifetime_threshold = 0.400` ✅ |
| Attack families | TTW, BSHH, ME (3 × 4 = 12 scenarios) | ✅ |
| Attacker percentage | 20 % of vehicle nodes | `pct=20` in `declare_attackers` ✅ |
| PEM score threshold τ | 0.075 | `PEM_SCORE_THRESHOLD = 0.075` ✅ |
| Detection latency budget | < 100 ms | ✅ |
| Performance metrics | MCC, AUROC, T_det, PDR, T_e2e | ✅ |
| Control plane | CSMA Ethernet, RSU → Controller, UDP port 7777 | ✅ |
| P2P link speed | 1 Gbps, 10 µs delay | `DataRate="1000Mbps"`, `Delay=10µs` ✅ |

---

### ❌ Rows that NEED FIXING

#### 1. Map area
- **LaTeX says:** 2.6 km × 3.0 km (≈ 7.8 km²)
- **SUMO map file:** `urban_2km.net.xml`
- **Actual SUMO config:** end time 300 s, area name "urban_2km"
- **Fix:** Measure the actual bounding box of your SUMO `.net.xml` and replace
  the dimensions. Run:
  ```bash
  grep "convBoundary\|netOffset\|projParameter" \
    "sumo_maps/urban_2km.net.xml" | head -5
  ```
  Then update the LaTeX to match the real map bounds.

#### 2. RSU deployment — origin and spacing
- **LaTeX says:** 8×8 grid, origin (502, 195) m, spacing 322 m × 379 m
- **Code says:**
  ```cpp
  // urban mobility_scenario == 0
  delta_x = 273.0;
  delta_y = 264.0;
  MinX = 273.0;
  MinY = 264.0;
  GridWidth = 8;
  ```
  → Origin = **(273, 264) m**, spacing = **273 m × 264 m**, 8 columns × 8 rows
- **Fix:** Change the LaTeX row to:
  ```
  RSU deployment | 8×8 fixed grid, origin (273, 264) m, spacing 273 m × 264 m
  ```

#### 3. RSU interconnect — link counts
- **LaTeX says:** 56 horizontal + 56 vertical links
- **Code says:**
  ```cpp
  // horizontal: connects RSU_i to RSU_{i+1} for all i where (i+1) % gridWidth != 0
  // With 64 RSUs in an 8×8 grid: 7 horizontal links × 8 rows = 56 horizontal ✅
  // vertical: connects RSU_i to RSU_{i+20}  ← stride is 20, NOT 8!
  // width = N_RSUs - 20 = 64 - 20 = 44 vertical links  ← NOT 56
  ```
- **Fix:** Change "56 vertical" to **44 vertical links** (total 100 P2P links):
  ```
  RSU interconnect | P2P Ethernet (56 horiz. + 44 vert. links, 1 Gbps, 10 µs delay)
  ```
  > **Why 20?** The code does `RSU_Nodes.Get(i+20)` for vertical links,
  > meaning vertical connections skip every 20 nodes, not every 8 (one grid row).
  > This looks like the stride should be 8 for a true 8×8 grid — you may want to
  > fix the code instead (change `i+20` → `i+8` and `width = N_RSUs - 8 = 56`).
  > If you fix the code, both horizontal and vertical become 56 and the LaTeX
  > stays correct.

#### 4. Beacon broadcast frequency
- **LaTeX says:** 1 Hz per vehicle per channel
- **Code says:**
  ```cpp
  // in main():
  for (double t=0.40; t<simTime-1; t=t+data_transmission_period) {
  ```
  where `data_transmission_period = 0.1` (100 ms) → **10 Hz per vehicle per channel**
- **Fix:** Change "1 Hz" to **10 Hz**:
  ```
  Beacon broadcast freq. | 10 Hz per vehicle per channel (100 ms period)
  ```

#### 5. Traffic class MAC parameters
- **LaTeX says:** Best effort (qf=1): CW_min=15, CW_max=127, AIFSN=6
- **Code says (qf=1 branch):**
  ```cpp
  CW_min = 15;   ✅
  CW_max = 127;  ✅
  AIFSN  = 6;    ✅
  SIFS   = 12;   ✅
  T_slot = 20.0; ✅
  AIFS   = SIFS + (AIFSN * T_slot) = 12 + 6×20 = 132 µs ✅
  ```
  All MAC timing values are correct. ✅

#### 6. TXOP limit
- **LaTeX says:** 5 ms
- **Code says:** `TxopLimit = NanoSeconds(5000000)` = **5 ms** ✅

#### 7. Queue max packets
- **LaTeX says:** queue max 50,000 packets
- **Code says:** `MaxPackets = 50000` ✅

#### 8. Number of flows
- **LaTeX says:** 4 instances (2 bidirectional pairs, flows=2)
- **Code says:** `const int flows = 2;` — bidirectional = 2×flows = 4 flow directions ✅

#### 9. Flow packet size
- **LaTeX says:** 750 bytes
- **Code says:** `flow_packet_size = 100` (bytes), `flow_size = 55`
- **Fix:** The 750-byte claim does not match code. Either:
  - Change LaTeX to reflect actual `flow_packet_size = 100 bytes`, or
  - Update the code to use 750-byte packets if that's the intended design.


#### 12. Baseline PDR and T_e2e
- **LaTeX says:** Baseline flow PDR 13–30 %, T_e2e 1.2–2.8 ms, Jitter 14–37 ms
- **Source:** These come from actual simulation runs with `attack_scenario=0`.
  Re-run and read from `pem_run_summary.csv` and the console output.
  Update the ranges if your latest runs give different numbers.

---

## 3. Body Text Corrections

| Location | LaTeX text | Correct value |
|----------|-----------|--------------|
| Para 1 — RSU grid | "spacing: 322 m × 379 m, origin at (502, 195) m" | **273 m × 264 m, origin (273, 264) m** |
| Para 1 — P2P links | "56 horizontal + 56 vertical links" | **56 horizontal + 44 vertical links** (or fix code to use stride=8) |
| Para 3 — beacon freq | "1 Hz" (implied) | **10 Hz** (100 ms period) |
| Para 3 — baseline PDR | "≈ 15–30 %" | Verify from simulation CSV output |

---

## 4. Quick Checklist Before Submission

- [ ] Run `./waf --run "scratch/routing --simTime=240 --N_Vehicles=200 --N_RSUs=64 --attack_scenario=0 --maxspeed=30"` and read `channel_delivery_analysis.csv` → update TX/RX/fanout columns in `tab:dsrc_channels`
- [ ] Read `pem_run_summary.csv` from the same run → update baseline PDR, T_e2e, jitter
- [ ] Fix RSU origin: (273, 264) m and spacing: 273 m × 264 m
- [ ] Fix vertical P2P link count: 44 (or fix code stride from 20→8 to get 56)
- [ ] Fix beacon frequency: 10 Hz (100 ms period)
- [ ] Fix flow packet size: verify 100 bytes or change code to 750
- [ ] Fix RL iterations: 1050 (not 50)
- [ ] Check map bounding box from SUMO `.net.xml` and update area dimensions
- [ ] Run `grep "convBoundary" sumo_maps/urban_2km.net.xml` to get exact map size
