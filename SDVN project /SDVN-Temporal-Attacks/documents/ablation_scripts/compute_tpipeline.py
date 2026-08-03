#!/usr/bin/env python3
"""
compute_tpipeline.py — genuine Eq. 4.7 Tpipeline = Tdet + TPBFT + Texec + TFlowMod.

Per the PDF (Table [Texec row] and Section "Consensus and Execution Latency"):
Texec (smart-contract execution latency on Hyperledger Fabric) is explicitly an
EXTERNALLY-obtained empirical quantity ("obtained from Fabric deployment
measurements," literature range 50-200ms) -- not something derived from a
blocking call inside the NS-3 simulation loop. routing.cc's own
t_exec_flowmod_mean_ms column is a LOCAL std::chrono timer around in-process
C++ code (see its declaration comment) -- it approximates TFlowMod (RSU
OpenFlow propagation) plus negligible overhead, but it is NOT Texec, and must
not be used as Texec on its own.

This script merges the two genuinely separate measurements:
  - Tdet, TPBFT, TFlowMod: read from a simulation run's own PEM_RUN_SUMMARY.csv
    (t_fs_det_mean_ms, t_pbft_mean_ms, t_exec_flowmod_mean_ms respectively --
    the last one used here as the TFlowMod proxy, per the labeling fix above).
  - Texec: read from documents/T_EXEC_FABRIC_MEASURED.csv, the real empirical
    measurement collected by measure_texec_fabric.js against the actual
    running Fabric network (submit -> endorse -> order -> commit round trip).

Usage:
    python3 compute_tpipeline.py <run_dir> [scenario_id] [--channel CHANNEL]

<run_dir> is a routing.cc --output_root directory. Texec is taken from the
MOST RECENT row in T_EXEC_FABRIC_MEASURED.csv for the given channel (default
teta-channel-gwSDK, the SDK-connection-pattern channel used in the later,
stable measurements -- earlier teta-channel rows show 3-20s cold-start/
connection-warmup outliers and are not representative of steady-state
Fabric latency).
"""
import sys
import os
import glob
import csv

HOME = os.path.expanduser("~")
DOCUMENTS_DIR = "/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35/scratch/SDVN project /SDVN-Temporal-Attacks/documents"
TEXEC_CSV = os.path.join(DOCUMENTS_DIR, "T_EXEC_FABRIC_MEASURED.csv")


def read_run_summary(run_dir, scenario_id=None):
    pattern = os.path.join(run_dir, "PEM_RUN_SUMMARY", "*.csv") if scenario_id is None \
        else os.path.join(run_dir, "PEM_RUN_SUMMARY", f"{scenario_id:02d}_*.csv")
    matches = [m for m in glob.glob(pattern) if "COMBINED" not in os.path.basename(m)]
    if not matches:
        raise FileNotFoundError(f"No PEM_RUN_SUMMARY CSV found under {run_dir}")
    with open(matches[0], newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError(f"{matches[0]} has no data rows")
    return rows[-1]


def read_latest_texec(channel):
    if not os.path.exists(TEXEC_CSV):
        raise FileNotFoundError(
            f"{TEXEC_CSV} not found -- run measure_texec_fabric.js first "
            f"against the live Fabric network.")
    with open(TEXEC_CSV, newline="") as f:
        rows = [r for r in csv.DictReader(f) if r["channel"] == channel]
    if not rows:
        raise ValueError(f"No rows for channel='{channel}' in {TEXEC_CSV}")
    # Most recent row for this channel (file is append-only, chronological).
    return rows[-1]


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    run_dir = sys.argv[1]
    scenario_id = None
    channel = "teta-channel-gwSDK"
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--channel" and i + 1 < len(args):
            channel = args[i + 1]
            i += 2
        else:
            scenario_id = int(args[i])
            i += 1

    row = read_run_summary(run_dir, scenario_id)
    texec_row = read_latest_texec(channel)

    t_det = float(row.get("t_fs_det_mean_ms", 0.0) or 0.0)
    t_pbft = float(row.get("t_pbft_mean_ms", 0.0) or 0.0)
    t_flowmod = float(row.get("t_exec_flowmod_mean_ms", 0.0) or 0.0)
    t_exec = float(texec_row["mean_ms"])

    t_pipeline = t_det + t_pbft + t_exec + t_flowmod

    print(f"scenario={row.get('attack_scenario')}  seed={row.get('run_id')}")
    print(f"Tdet     (simulated)      = {t_det:.3f} ms")
    print(f"TPBFT    (simulated)      = {t_pbft:.3f} ms")
    print(f"Texec    (Fabric-measured, channel={channel}, n={texec_row['n_committed']}) = {t_exec:.3f} ms")
    print(f"TFlowMod (simulated proxy) = {t_flowmod:.3f} ms")
    print(f"Tpipeline (Eq. 4.7)       = {t_pipeline:.3f} ms")
    print(f"Within 100ms budget?      = {'YES' if t_pipeline <= 100.0 else 'NO'}")


if __name__ == "__main__":
    main()
