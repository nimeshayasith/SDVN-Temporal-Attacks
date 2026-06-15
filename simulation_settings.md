# Simulation Settings — LaTeX Section for Report

> **Status:** Baseline verified — 200 vehicles + 64 RSUs, SUMO positions (baseline only), real IEEE 802.11p (all layers).
> PDR and latency results from `--simTime=10`. Full 240 s runs are still pending.
> Attack scenario results (1–12) are **not yet re-validated** under the SUMO setup and must be re-run.
>
> **Node placement (confirmed from source code):**
> - **RSUs** — fixed 8×8 grid via `ns3::GridPositionAllocator`, origin (502, 195) m, spacing 322 m × 379 m (`mobility_scenario=0`). Stationary.
> - **Vehicles** — initial positions and speeds loaded from SUMO NS-2 TCL trace (`mobility_urban_30_200veh.tcl`) **for `attack_scenario=0` (baseline)**. Vehicles then move at their SUMO-derived initial speed using `ConstantVelocityMobilityModel`.
> - For attack scenarios (1–12), vehicle positions are set by `update_mobility()` (non-SUMO).
>
> **Channel TX power (urban, `mobility_scenario=0`, confirmed from source lines 144242–144299):**
> Ch 172/174/176 = 33 dBm · Ch 178 (CCH) = 44 dBm · Ch 180/182 = 23 dBm · Ch 184 = 40 dBm.
> The `power_dbm` column in `channel_delivery_analysis.csv` is cosmetically wrong (shows the rural static array). The LaTeX Table 1 values below are correct.

---

```latex
\subsection{Simulation Settings}

We selected an urban area for simulation by importing mobility traces generated using
SUMO (Simulation of Urban MObility) and OpenStreetMap tools. The road network covers
approximately 2.6\,km $\times$ 3.0\,km ($\approx$7.8\,km$^2$), and the vehicular network
is simulated using NS-3.35 on Linux. We simulate 200 vehicles and deploy 64 RSUs in a
fixed 8$\times$8 grid layout (spacing: 322\,m $\times$ 379\,m, origin at $(502, 195)$\,m),
giving 264 nodes in total. Adjacent RSUs are connected by point-to-point Ethernet links
(56 horizontal $+$ 56 vertical links). Vehicle initial positions and velocities are loaded
directly from SUMO mobility traces; the maximum vehicle speed is 30\,km/h (urban), and
the total simulation time is 240\,s.

DSRC (Dedicated Short-Range Communications) operating at 5.9\,GHz under the IEEE
802.11p standard is used for all V2V and V2R data-plane communication. The DSRC
spectrum is divided into seven 10\,MHz channels; the urban scenario
(\texttt{mobility\_scenario\,=\,0}) transmission power settings are listed in
Table~\ref{tab:dsrc_channels}. Channel 178 is the dedicated Control Channel (CCH)
used for topology beacons, while the remaining six are Service Channels (SCH).
The DSRC communication range is 300\,m, and the COST-231 Hata urban propagation
loss model (\texttt{ns3::Cost231PropagationLossModel}) is applied to all seven channels.

Each vehicle broadcasts topology beacons on all seven DSRC channels at 1\,Hz using
IEEE 802.11p with CSMA/CA MAC and real YANS PHY (actual backoff, CW adaptation, and
collision behaviour). Flow packets are delivered over CH\,178 using IEEE 802.11p
broadcast with per-packet next-hop filtering via a tag embedded in each packet; only
the intended next-hop (or the final destination) acts on the received packet. Relay
nodes forward packets hop-by-hop using the RL routing tables until the destination
is reached. This delivers a realistic packet delivery ratio determined by the
COST-231 Hata propagation model and CSMA/CA collision behaviour at 264-node scale
(baseline PDR $\approx$15--30\,\%). For the control plane, RSUs forward aggregated
topology reports to the SDN controller over CSMA Ethernet (10.1.1.0/24, UDP port 7777).

The proposed Reinforcement Learning routing algorithm
(\texttt{routing\_algorithm\,=\,4}) is compared against ECMP, QRSDN, RLMR, and
DCMR baselines. Three attack families are studied across four attacker-placement
variants each (12 scenarios total): TTW (Topology Time-Warp), BSHH (Beacon State
Heartbeat Hijack), and ME (Multipath Echo). By default, 20\,\% of vehicle nodes
act as attackers. Detection is performed by the PEM layer with anomaly score
threshold $\tau = 0.075$ and a detection latency budget of 100\,ms.
Performance is measured using MCC, AUROC, $T_{\mathrm{det}}$ (ms), PDR, and
$T_{e2e}$ (ms).

Simulation settings are summarised in Tables~\ref{tab:sim_settings}
and~\ref{tab:dsrc_channels}.

%% ── Table 1: DSRC Channel Power and Fanout ───────────────────────────────────
\begin{table}[htb]
    \begin{center}
        \caption{DSRC channel settings — urban scenario
                 (\texttt{mobility\_scenario\,=\,0}).
                 Fanout measured from baseline run
                 (200 vehicles + 64 RSUs, \texttt{simTime\,=\,10\,s}).}
        \vspace{-5pt}
        \label{tab:dsrc_channels}
        \begin{tabular}{| c | c | c | c | r | r | c |}
            \hline
            \textbf{Ch} & \textbf{Freq} & \textbf{Type} &
            \textbf{Tx Power} & \textbf{TX} & \textbf{RX} &
            \textbf{Avg Fanout} \\
            & \textbf{(GHz)} & & \textbf{(dBm)} &
            \textbf{count} & \textbf{count} & \\
            \hline
            172 & 5.860 & SCH & 33 & 1\,932 & 12\,756 & 6.60 \\
            \hline
            174 & 5.870 & SCH & 33 & 1\,956 & 13\,014 & 6.65 \\
            \hline
            176 & 5.880 & SCH & 33 & 1\,988 & 13\,308 & 6.69 \\
            \hline
            \textbf{178} & \textbf{5.890} & \textbf{CCH} & \textbf{44} &
            \textbf{2\,460} & \textbf{60\,897} & \textbf{24.75} \\
            \hline
            180 & 5.900 & SCH & 23 & 2\,000 & 4\,199 & 2.10 \\
            \hline
            182 & 5.910 & SCH & 23 & 2\,030 & 4\,261 & 2.10 \\
            \hline
            184 & 5.920 & SCH & 40 & 2\,144 & 33\,007 & 15.40 \\
            \hline
        \end{tabular}
    \end{center}
    \vspace{-10pt}
\end{table}

%% ── Table 2: General Simulation Settings ─────────────────────────────────────
\begin{table}[htb]
    \begin{center}
        \caption{Simulation settings.}
        \vspace{-5pt}
        \label{tab:sim_settings}
        \begin{tabular}{| m{3.5cm} | m{4.5cm} |}
            \hline
            \textbf{Parameter} & \textbf{Value} \\
            \hline
            Network simulation tool & NS-3.35 (Linux, Ubuntu) \\
            \hline
            Mobility trace extraction & SUMO, OpenStreetMap \\
            \hline
            Map area & Urban, $\approx$2.6\,km $\times$ 3.0\,km (7.8\,km$^2$) \\
            \hline
            Number of nodes & 264 (200 vehicles, 64 RSUs) \\
            \hline
            Vehicle placement & SUMO NS-2 trace (initial positions and speeds, \texttt{ConstantVelocityMobilityModel}) \\
            \hline
            RSU deployment & 8$\times$8 fixed grid, origin (502, 195)\,m, spacing 322\,m $\times$ 379\,m \\
            \hline
            RSU interconnect & P2P Ethernet (56 horiz.\ + 56 vert.\ links, 1\,Gbps, 10\,$\mu$s delay) \\
            \hline
            Simulation time & 240\,s \\
            \hline
            Maximum vehicle speed & 30\,km/h (urban) \\
            \hline
            Data plane & 5.9\,GHz DSRC / IEEE 802.11p (7 channels, Ch\,172--184) \\
            \hline
            MAC mode & IEEE 802.11p Ad-hoc (\texttt{AdhocWifiMac}, QoS enabled) \\
            \hline
            PHY data rate & 12\,Mbps (\texttt{OfdmRate12MbpsBW10MHz}) \\
            \hline
            Traffic class & Best effort (\texttt{qf}=1): CW$_{\min}$=15, CW$_{\max}$=127, AIFSN=6 \\
            \hline
            MAC timing & SIFS=12\,$\mu$s, $T_{\mathrm{slot}}$=20\,$\mu$s, AIFS=132\,$\mu$s \\
            \hline
            TXOP limit & 5\,ms; queue max 50\,000 packets \\
            \hline
            Flow delivery & IEEE 802.11p broadcast per-hop, CSMA/CA real PHY \\
            \hline
            Flow packet size & 750\,bytes \\
            \hline
            Number of flows & 4 instances (2 bidirectional pairs, \texttt{flows}=2) \\
            \hline
            Control plane & CSMA Ethernet, RSU $\to$ Controller, UDP port 7777 \\
            \hline
            DSRC comm.\ range & 300\,m \\
            \hline
            Propagation loss model & COST-231 Hata (urban V2V) \\
            \hline
            Beacon broadcast freq. & 1\,Hz per vehicle per channel \\
            \hline
            CCH (Ch\,178) Tx power & 44\,dBm \\
            \hline
            CCH avg.\ fanout (baseline) & 24.75 nodes/broadcast \\
            \hline
            Baseline flow PDR & 13--30\,\% (\texttt{simTime\,=\,10\,s}; real 802.11p multi-hop) \\
            \hline
            Baseline avg.\ $T_{e2e}$ & 1.2--2.8\,ms \\
            \hline
            Baseline avg.\ jitter & 14--37\,ms \\
            \hline
            RL cycle time & 22--28\,ms (264 active nodes) \\
            \hline
            RL learning rate $\alpha$ & 0.1 \\
            \hline
            RL discount factor $\gamma$ & 0.5 \\
            \hline
            RL iterations per cycle & 50 \\
            \hline
            Link-lifetime threshold & 0.4\,s \\
            \hline
            Attack families & TTW, BSHH, ME (3 $\times$ 4 = 12 scenarios) \\
            \hline
            Attacker percentage & 20\,\% of vehicle nodes \\
            \hline
            PEM score threshold $\tau$ & 0.075 \\
            \hline
            Detection latency budget & $<$100\,ms \\
            \hline
            Baseline routing algorithms & ECMP, QRSDN, RLMR, DCMR \\
            \hline
            Performance metrics & MCC, AUROC, $T_{\mathrm{det}}$, PDR, $T_{e2e}$ \\
            \hline
        \end{tabular}
    \end{center}
    \vspace{-15pt}
\end{table}
```

---

## Verified Baseline Run Results

**Command:** `./waf --run "scratch/routing --simTime=10 --N_Vehicles=200 --N_RSUs=64 --attack_scenario=0 --maxspeed=30 --mobility_scenario=0"`

| Metric | Value |
|--------|-------|
| SUMO vehicle positions loaded | 236 / 200 |
| RSU P2P links installed | 56 horizontal + 56 vertical (grid_width=8) |
| Flow PDR (baseline, real 802.11p) | **13–30 %** across RL cycles |
| Average $T_{e2e}$ | **1.2–2.8 ms** |
| Average jitter | **14–37 ms** |
| Load balance | ~100 % |
| RL cycle time | 22–28 ms (264 active nodes) |

> **Note on PDR range:** Values vary across 1-second RL cycles because the link-lifetime optimization
> runs once per cycle and reflects dynamic radio conditions. Short simTime=10 captures only ~7–8 RL cycles.
> A full simTime=240 run will give a more stable average.

---

## Channel Delivery Analysis

From `CHANNEL_DELIVERY_ANALYSIS/00_Baseline_No_Attack.csv` — latest run (N=264, simTime=10, real 802.11p):

| Channel | Actual TX power | TX count | RX count | Avg fanout |
|---------|----------------|----------|----------|------------|
| 172 | 33 dBm | 1 932 | 12 756 | 6.60 |
| 174 | 33 dBm | 1 956 | 13 014 | 6.65 |
| 176 | 33 dBm | 1 988 | 13 308 | 6.69 |
| **178 (CCH)** | **44 dBm** | **2 460** | **60 897** | **24.75** |
| 180 | 23 dBm | 2 000 | 4 199 | 2.10 |
| 182 | 23 dBm | 2 030 | 4 261 | 2.10 |
| 184 | 40 dBm | 2 144 | 33 007 | 15.40 |

> ⚠️ **Note for supervisor:** The `power_dbm` column in the CSV reports the **rural static-array values**
> (23, 26.5, 30, 33.5, 37, 40.5, 44 dBm), not the actual urban applied values. This is a known cosmetic
> bug in `WriteChannelAnalysisCsv()`. The **actual applied TX powers** for `mobility_scenario=0` are:
> Ch 172/174/176 = 33 dBm, Ch 178 (CCH) = 44 dBm, Ch 180/182 = 23 dBm, Ch 184 = 40 dBm,
> as confirmed by the fanout pattern in the table above.

> **Ch 178 higher TX count (2 460 vs ~1 900 for SCH):** Ch 178 carries both topology beacons
> (1 Hz per vehicle) AND real 802.11p flow delivery packets. Flow packets are broadcast on Ch 178
> with the RL routing algorithm, adding ~460 extra transmissions per 10-second run.

> **Ch 180/182 fanout ≈ 2.1 (not < 1):** At 23 dBm, short-range channels still reach ~2 nearby nodes.
> The earlier value of < 1 was from a different run with fewer vehicles.

---

## Implementation Summary

| Component | Status |
|-----------|--------|
| Topology beacons (7 channels, 1 Hz) | ✅ Real IEEE 802.11p CSMA/CA |
| Flow delivery (Ch 178) | ✅ Real IEEE 802.11p broadcast, per-hop filtered |
| RSU→Controller forwarding | ✅ CSMA Ethernet, UDP port 7777 |
| SUMO vehicle positions | ✅ 236 positions loaded from TCL trace |
| RSU 8×8 grid + P2P links | ✅ 56h + 56v links |
| Attack scenarios 1–12 | ❌ Not yet re-validated with new SUMO+real-802.11p setup |
| Full 240 s baseline run | ⏳ Pending |
| 5-run statistics (mean ± std) | ⏳ Pending |

---

## Items for Supervisor Review

| Issue | Detail |
|-------|--------|
| **RSU placement** | Confirmed fixed 8×8 grid. `ns3::GridPositionAllocator` with origin (502, 195) m, spacing 322 m × 379 m (code lines 143827–143833). RSUs are stationary (`ConstantVelocityMobilityModel`, velocity = 0). Grid exactly covers the SUMO urban area (X=341–2918 m, Y=5–3033 m), giving max vehicle-to-RSU distance ≈ 249 m < 300 m DSRC range. |
| **Vehicle placement** | Confirmed SUMO-based for baseline (`attack_scenario=0`). Code at line 143841 parses `/home/sdvn_echo_topology/mobility/mobility_urban_30_200veh.tcl` — reads `$node_(N) set X_/Y_` for initial positions and first `setdest` speed. Vehicles then move at that SUMO speed using `ConstantVelocityMobilityModel` (constant velocity, random direction). 236 of 200 requested vehicle positions found in TCL file. |
| **Channel TX power (urban)** | Code lines 144242–144299 set: Ch 172/174/176 = 33 dBm, Ch 178 (CCH) = 44 dBm, Ch 180/182 = 23 dBm, Ch 184 = 40 dBm. These are applied to the NS-3 PHY helpers. The LaTeX Table 1 values are correct. |
| **power_dbm CSV bug** | The `power_dbm` column in `channel_delivery_analysis.csv` shows the rural static-array values (`{23, 26.5, 30, 33.5, 37, 40.5, 44}` from line 419) instead of the actual urban applied values above. This is a cosmetic logging bug — the fanout pattern in the table confirms the correct powers were applied (Ch 178 at 44 dBm gives fanout=24.75 vs 2.10 for Ch 180/182 at 23 dBm). |
| **Baseline flow PDR 13–30 %** | End-to-end delivery ratio for vehicle-to-vehicle unicast data flows (source vehicle → multi-hop → destination vehicle, both dynamically selected each RL cycle from the 200 vehicles). Each hop uses real IEEE 802.11p broadcast + COST-231 Hata loss model. Beacon broadcast delivery is separate — measured by fanout (Ch 178 = 24.75 nodes/broadcast). |
| **PDR cycle variance** | Each 1-second RL cycle re-optimizes routing using the current link-lifetime matrix. PDR varies as the RL solution converges and radio conditions change. Expected to stabilize in a full 240 s run. |
| **Ch 178 higher TX count** | Flow packets sent on Ch 178 in addition to topology beacons, increasing TX and RX counts on that channel. |
| **LTE control plane** | Disabled (scheduling calls commented out). Only CSMA Ethernet active for RSU→Controller. |
