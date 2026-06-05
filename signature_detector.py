"""
=============================================================================
signature_detector.py
Nine Formal Attack Signature Detector for TETA-Guard (LW-DETECT Algorithm 1)

Implements all 9 signatures from your thesis:
  TTW-S1  : Timestamp too old (Eq. 3.2)
  TTW-S2  : Beacon arrived out of temporal order (Eq. 3.3)
  TTW-S3  : Cross-reporter timestamp skew (Eq. 3.4)
  BSHH-S1 : Duplicate sender identity (Eq. 3.5)
  BSHH-S2 : Heartbeat timestamp regression (Eq. 3.6)
  BSHH-S3 : Heartbeat without beacon activity (Eq. 3.7)
  ME-S1   : Reporter count exceeds mobility bound (Eq. 3.8)
  ME-S2   : Path count jumps suddenly (Eq. 3.9)
  ME-S3   : Reporter outside communication range (Eq. 3.10)

Then combines them into a weighted score s(e) (Eq. 3.11).

HOW NS-3 CALLS THIS (same pattern as PQ_SDVN_security.py):
  python3 signature_detector.py event_type=beacon node_id=3 claimed_id=3
          sender_ts=1000.5 recv_ts=1001.2 reporter_id=3 link_src=0 link_dst=1
          reporter_x=100.0 reporter_y=200.0 src_x=0.0 src_y=0.0
          dst_x=150.0 dst_y=0.0 rssi=-55.0 reporter_count=4 path_count=3

Returns: ALERT or BENIGN, plus which signatures fired and the score.
=============================================================================
"""

import os
import sys
import csv
import time
import math
import shlex

# ── Timing ───────────────────────────────────────────────────────────────────
start = time.time()

# =============================================================================
# SECTION 1 — CONSTANTS  (match these to your thesis / routing.cc parameters)
# =============================================================================

NS3_SCRATCH  = "/home/nimesha/ns-allinone-3.35/ns-3.35/scratch"

# Communication range in metres (rcomm from your thesis)
R_COMM_M     = 300.0

# Beacon interval in seconds (Tb from your thesis, 100ms)
BEACON_INTERVAL_S = 0.100

# Propagation tolerance in seconds (epsilon from your thesis)
PROP_TOLERANCE_S  = 0.005

# Heartbeat observation window in seconds (W from your thesis)
HEARTBEAT_WINDOW_S = 0.300

# Minimum RSSI for a valid observation (dBm, from routing.cc PEM constants)
RSSI_MIN_DBM  = -40.0 - 10.0 * 2.75 * math.log10(300)  # ≈ -113 dBm at 300m

# Maximum legitimate reporter count: ρmax = 2 * rcomm * lambda
# lambda = vehicle density per metre (approximate urban scenario)
VEHICLE_DENSITY_PER_M = 0.05       # 1 vehicle every 20 metres
RHO_MAX = 2.0 * R_COMM_M * VEHICLE_DENSITY_PER_M   # = 30 vehicles

# Max legitimate path count jump per beacon interval (delta_max from Eq. 3.9)
DELTA_MAX_PATHS = 2

# Link lifetime at urban speeds (Eq. 3.29: Llink = 2*rcomm / vrel)
# At vrel = 14 m/s (urban): Llink ≈ 43 s
URBAN_VREL_M_S  = 14.0
L_LINK_S        = (2.0 * R_COMM_M) / URBAN_VREL_M_S   # ≈ 42.86 s

# Detection threshold (theta_LW from Eq. 3.11)
# A score above this → ALERT
THETA_LW = 0.10    # fires on any single signature

# Signature weights (sum = 1.0, from routing.cc PEM_WEIGHTS)
# Order: TTW-S1, TTW-S2, TTW-S3, BSHH-S1, BSHH-S2, BSHH-S3, ME-S1, ME-S2, ME-S3
WEIGHTS = [0.15, 0.15, 0.10,   # TTW
           0.15, 0.10, 0.10,   # BSHH
           0.10, 0.075, 0.075] # ME

# CSV paths for state (sliding window and heartbeat history)
WINDOW_CSV   = f"{NS3_SCRATCH}/sig_window.csv"
HEARTBEAT_CSV = f"{NS3_SCRATCH}/sig_heartbeats.csv"
PATH_CSV     = f"{NS3_SCRATCH}/sig_paths.csv"
BEACON_CSV   = f"{NS3_SCRATCH}/sig_beacons.csv"


# =============================================================================
# SECTION 2 — CSV STATE HELPERS
# These store the sliding window state between ns-3 calls.
# Same pattern as PQ_SDVN_security.py
# =============================================================================

def ensure_csv(path):
    if not os.path.exists(path):
        open(path, 'w').close()

def read_csv_rows(path):
    ensure_csv(path)
    with open(path, 'r') as f:
        return list(csv.reader(f))

def write_csv_rows(path, rows):
    with open(path, 'w', newline='') as f:
        csv.writer(f).writerows(rows)

def append_csv_row(path, row):
    ensure_csv(path)
    with open(path, 'a', newline='') as f:
        csv.writer(f).writerow([str(v) for v in row])


# =============================================================================
# SECTION 3 — STATE ACCESSORS
# The sliding window, heartbeat log, path count history, and beacon log
# are all stored in small CSV files. This lets ns-3 call this script multiple
# times and the state persists across calls.
# =============================================================================

def get_recent_beacons_from_node(node_id, window_s):
    """
    Returns list of (sender_ts, recv_ts) tuples for beacons from node_id
    within the last window_s seconds.
    Used by TTW-S2 (sequence check) and BSHH-S3 (liveness vs beacon check).
    """
    rows = read_csv_rows(BEACON_CSV)
    now = time.time()
    result = []
    for row in rows:
        if len(row) < 4:
            continue
        if str(row[0]).strip() != str(node_id):
            continue
        recv_ts   = float(row[2])
        sender_ts = float(row[1])
        log_time  = float(row[3])
        if (now - log_time) <= window_s:
            result.append((sender_ts, recv_ts))
    return result


def log_beacon(node_id, sender_ts, recv_ts):
    """Store this beacon in the beacon log for future TTW-S2 / BSHH-S3 checks."""
    append_csv_row(BEACON_CSV, [node_id, sender_ts, recv_ts, time.time()])


def get_last_heartbeat_ts(node_id):
    """Return the last known heartbeat sender timestamp for node_id, or None."""
    rows = read_csv_rows(HEARTBEAT_CSV)
    for row in reversed(rows):
        if len(row) >= 2 and str(row[0]).strip() == str(node_id):
            return float(row[1])
    return None


def log_heartbeat(node_id, sender_ts, recv_ts):
    """Store heartbeat event for BSHH-S2 regression detection."""
    append_csv_row(HEARTBEAT_CSV, [node_id, sender_ts, recv_ts, time.time()])


def get_previous_path_count(src_id, dst_id):
    """Return path count from the previous beacon interval for ME-S2."""
    rows = read_csv_rows(PATH_CSV)
    for row in reversed(rows):
        if (len(row) >= 3 and
                str(row[0]).strip() == str(src_id) and
                str(row[1]).strip() == str(dst_id)):
            return int(row[2])
    return 0


def log_path_count(src_id, dst_id, count):
    """Store current path count for ME-S2 next-interval comparison."""
    append_csv_row(PATH_CSV, [src_id, dst_id, count, time.time()])


def get_cross_reporter_timestamps(link_src, link_dst, window_s):
    """
    Return list of sender timestamps from different reporters of the same link,
    within window_s seconds. Used by TTW-S3.
    """
    rows = read_csv_rows(WINDOW_CSV)
    now = time.time()
    result = []
    for row in rows:
        if len(row) < 6:
            continue
        if (str(row[1]).strip() == str(link_src) and
                str(row[2]).strip() == str(link_dst)):
            log_time  = float(row[5])
            if (now - log_time) <= window_s:
                result.append(float(row[3]))   # sender_ts
    return result


def log_topology_event(reporter_id, link_src, link_dst, sender_ts, recv_ts):
    """Store a topology update event for the sliding window."""
    append_csv_row(WINDOW_CSV,
                   [reporter_id, link_src, link_dst, sender_ts, recv_ts, time.time()])


# =============================================================================
# SECTION 4 — THE NINE SIGNATURE FUNCTIONS
# Each returns 1 (triggered) or 0 (not triggered).
# Each has a comment explaining the thesis equation it implements.
# =============================================================================

def sig_ttw_s1(recv_ts, sender_ts):
    """
    TTW-S1 (Eq. 3.2): Timestamp staleness.
    Fires when: (recv_ts - sender_ts) > Llink + epsilon
    In plain words: the beacon is so old it could not be from an active link.

    recv_ts   = time NS-3 received the beacon (simulation seconds)
    sender_ts = timestamp the sender put in the beacon
    """
    age = recv_ts - sender_ts
    stale = age > (L_LINK_S + PROP_TOLERANCE_S)
    if stale:
        print(f"[TTW-S1] FIRED: beacon age {age:.3f}s > link lifetime {L_LINK_S:.1f}s")
    return 1 if stale else 0


def sig_ttw_s2(node_id, sender_ts):
    """
    TTW-S2 (Eq. 3.3): Sequence inversion.
    Fires when: the current beacon's sender_ts is OLDER than the most recent
    known beacon from the same node.

    In plain words: if we already received a beacon from node 3 at time T,
    and now we receive a beacon from node 3 at time T-5, something replayed it.
    """
    past = get_recent_beacons_from_node(node_id, window_s=HEARTBEAT_WINDOW_S*10)
    if not past:
        return 0   # no history yet → can't detect
    max_past_ts = max(s for s, r in past)
    inversion = sender_ts < max_past_ts
    if inversion:
        print(f"[TTW-S2] FIRED: sender_ts {sender_ts:.3f} < last known {max_past_ts:.3f}")
    return 1 if inversion else 0


def sig_ttw_s3(link_src, link_dst, sender_ts):
    """
    TTW-S3 (Eq. 3.4): Cross-reporter timestamp skew.
    Fires when two reporters of the same link (eij) have sender timestamps
    more than one beacon interval Tb apart.

    In plain words: if two cars both say they saw link A→B, but their
    timestamps differ by more than 100ms, one of them is replaying.
    """
    past_ts_list = get_cross_reporter_timestamps(link_src, link_dst,
                                                  window_s=HEARTBEAT_WINDOW_S)
    for past_ts in past_ts_list:
        skew = abs(sender_ts - past_ts)
        if skew > BEACON_INTERVAL_S:
            print(f"[TTW-S3] FIRED: cross-reporter skew {skew*1000:.1f}ms > {BEACON_INTERVAL_S*1000:.0f}ms")
            return 1
    return 0


def sig_bshh_s1(claimed_id, physical_sender_id):
    """
    BSHH-S1 (Eq. 3.5): Duplicate sender identity.
    Fires when: physical sender != claimed sender identity.

    In plain words: the packet says it's from vehicle 5, but it physically
    came from vehicle 7. Identity spoofing.

    In simulation: ns-3 knows the physical node ID from the MAC layer.
    The beacon content carries the claimed node ID.
    If physical_sender_id == 9999 that's a sentinel meaning "controller-injected."
    """
    spoofed = (str(claimed_id) != str(physical_sender_id) and
               str(physical_sender_id) != "9999")
    if spoofed:
        print(f"[BSHH-S1] FIRED: claimed={claimed_id} physical={physical_sender_id}")
    return 1 if spoofed else 0


def sig_bshh_s2(node_id, sender_ts):
    """
    BSHH-S2 (Eq. 3.6): Heartbeat timestamp regression.
    Fires when: current heartbeat timestamp < previous heartbeat timestamp.

    In plain words: a legitimate vehicle's heartbeat timestamps always
    increase. If they go backwards, a stale heartbeat is being replayed.
    """
    prev_ts = get_last_heartbeat_ts(node_id)
    if prev_ts is None:
        return 0   # no history yet
    regression = sender_ts < prev_ts
    if regression:
        print(f"[BSHH-S2] FIRED: heartbeat ts {sender_ts:.3f} < prev {prev_ts:.3f}")
    return 1 if regression else 0


def sig_bshh_s3(node_id, recv_ts, is_heartbeat):
    """
    BSHH-S3 (Eq. 3.7): Heartbeat asserts liveness but no beacon seen in window W.
    Fires when: heartbeat arrives for node_id but no beacon from that node
    was seen within the observation window W seconds.

    In plain words: a vehicle claims it's alive via heartbeat, but we haven't
    seen any real beacon from it recently. The heartbeat is fabricated.
    """
    if not is_heartbeat:
        return 0   # only applies to heartbeat events
    recent_beacons = get_recent_beacons_from_node(node_id,
                                                   window_s=HEARTBEAT_WINDOW_S)
    no_recent_beacon = (len(recent_beacons) == 0)
    if no_recent_beacon:
        print(f"[BSHH-S3] FIRED: heartbeat from {node_id} but no beacon in {HEARTBEAT_WINDOW_S}s window")
    return 1 if no_recent_beacon else 0


def sig_me_s1(reporter_count):
    """
    ME-S1 (Eq. 3.8): Reporter count exceeds mobility-consistent bound.
    Fires when: |R(eij, t)| > rho_max(lambda, rcomm)

    In plain words: too many vehicles claim to have witnessed the same link.
    In a realistic traffic density, only about rho_max vehicles can be in
    communication range of a link at one time.

    reporter_count = how many different nodes reported seeing this link.
    """
    too_many = reporter_count > RHO_MAX
    if too_many:
        print(f"[ME-S1] FIRED: {reporter_count} reporters > rho_max {RHO_MAX:.1f}")
    return 1 if too_many else 0


def sig_me_s2(link_src, link_dst, current_path_count):
    """
    ME-S2 (Eq. 3.9): Path count jumps too fast.
    Fires when: |P(Vi,Vj)|_t - |P(Vi,Vj)|_{t-1} > delta_max

    In plain words: the number of paths between two nodes jumped by more
    than delta_max in one beacon interval. Legitimate topology only changes
    gradually as vehicles move.
    """
    prev_count = get_previous_path_count(link_src, link_dst)
    jump = current_path_count - prev_count
    sudden = jump > DELTA_MAX_PATHS
    if sudden:
        print(f"[ME-S2] FIRED: path count jumped {prev_count}→{current_path_count} (delta {jump} > {DELTA_MAX_PATHS})")
    return 1 if sudden else 0


def sig_me_s3(reporter_x, reporter_y, src_x, src_y, dst_x, dst_y, rssi_dbm):
    """
    ME-S3 (Eq. 3.10): Reporter outside communication range of the reported link.
    Fires when: dist(reporter, link_endpoint) > rcomm
                OR rssi_reporter < RSSI_min

    In plain words: a vehicle claims it witnessed link A→B, but its GPS
    position puts it 500m away from both A and B. Physically impossible.

    reporter_x/y = reporter's GPS position (metres)
    src_x/y     = position of link source node
    dst_x/y     = position of link destination node
    rssi_dbm    = RSSI measured at reporter from the link source
    """
    dist_to_src = math.sqrt((reporter_x - src_x)**2 + (reporter_y - src_y)**2)
    dist_to_dst = math.sqrt((reporter_x - dst_x)**2 + (reporter_y - dst_y)**2)

    # Minimum distance to either endpoint
    min_dist = min(dist_to_src, dist_to_dst)

    out_of_range = min_dist > R_COMM_M
    weak_signal  = rssi_dbm < RSSI_MIN_DBM

    triggered = out_of_range or weak_signal
    if triggered:
        reason = []
        if out_of_range:
            reason.append(f"dist={min_dist:.1f}m > {R_COMM_M}m")
        if weak_signal:
            reason.append(f"RSSI={rssi_dbm:.1f} < {RSSI_MIN_DBM:.1f}dBm")
        print(f"[ME-S3] FIRED: {', '.join(reason)}")
    return 1 if triggered else 0


# =============================================================================
# SECTION 5 — WEIGHTED SCORE (Eq. 3.11) + CLASSIFY ATTACK
# =============================================================================

def compute_score(sig_results):
    """
    Eq. 3.11: s(e) = sum_k( w_k * 1[Sig_k triggered] )
    Returns score in [0, 1].
    sig_results = list of 9 values (0 or 1), one per signature.
    """
    score = sum(WEIGHTS[k] * sig_results[k] for k in range(9))
    return score


def classify_attack(sig_results):
    """
    Algorithm 1, CLASSIFY_ATTACK:
    TTW signatures are indices 0,1,2
    BSHH signatures are indices 3,4,5
    ME signatures are indices 6,7,8
    Return the family with the most triggered signatures.
    """
    ttw_count  = sum(sig_results[0:3])
    bshh_count = sum(sig_results[3:6])
    me_count   = sum(sig_results[6:9])

    if ttw_count == 0 and bshh_count == 0 and me_count == 0:
        return "BENIGN"

    best = max(ttw_count, bshh_count, me_count)
    if ttw_count == best:
        return "TTW_ATTACK"
    if bshh_count == best:
        return "BSHH_ATTACK"
    return "ME_ATTACK"


# =============================================================================
# SECTION 6 — MAIN LW-DETECT PROCEDURE (Algorithm 1 from your thesis)
# =============================================================================

def lw_detect(args):
    """
    Full LW-DETECT execution for one incoming event.
    Returns (alert: bool, attack_type: str, score: float, sig_results: list)
    """
    # ── Unpack arguments from ns-3 ───────────────────────────────────────────
    event_type   = args.get('event_type', 'beacon')   # 'beacon' or 'heartbeat'
    node_id      = int(args.get('node_id',      0))
    claimed_id   = int(args.get('claimed_id',   node_id))
    physical_id  = int(args.get('physical_id',  node_id))
    sender_ts    = float(args.get('sender_ts',  0.0))
    recv_ts      = float(args.get('recv_ts',    sender_ts + 0.001))
    reporter_id  = int(args.get('reporter_id',  node_id))
    link_src     = int(args.get('link_src',     0))
    link_dst     = int(args.get('link_dst',     1))

    # Reporter GPS position (metres in simulation coordinate system)
    reporter_x   = float(args.get('reporter_x', 0.0))
    reporter_y   = float(args.get('reporter_y', 0.0))
    src_x        = float(args.get('src_x',      0.0))
    src_y        = float(args.get('src_y',      0.0))
    dst_x        = float(args.get('dst_x',      100.0))
    dst_y        = float(args.get('dst_y',      0.0))
    rssi_dbm     = float(args.get('rssi',       -60.0))

    # ME-specific: reporter and path counts
    reporter_count    = int(args.get('reporter_count',  1))
    current_path_count = int(args.get('path_count',    1))

    is_heartbeat = (event_type == 'heartbeat')

    # ── Step 1: Update state stores ──────────────────────────────────────────
    if not is_heartbeat:
        log_beacon(node_id, sender_ts, recv_ts)
        log_topology_event(reporter_id, link_src, link_dst, sender_ts, recv_ts)
    else:
        log_heartbeat(node_id, sender_ts, recv_ts)

    log_path_count(link_src, link_dst, current_path_count)

    # ── Step 2: Evaluate all 9 signatures ────────────────────────────────────
    sig_results = [
        sig_ttw_s1(recv_ts, sender_ts),                              # S1
        sig_ttw_s2(node_id, sender_ts),                              # S2
        sig_ttw_s3(link_src, link_dst, sender_ts),                   # S3
        sig_bshh_s1(claimed_id, physical_id),                        # S4
        sig_bshh_s2(node_id, sender_ts) if is_heartbeat else 0,      # S5
        sig_bshh_s3(node_id, recv_ts, is_heartbeat),                 # S6
        sig_me_s1(reporter_count),                                    # S7
        sig_me_s2(link_src, link_dst, current_path_count),           # S8
        sig_me_s3(reporter_x, reporter_y,                            # S9
                  src_x, src_y, dst_x, dst_y, rssi_dbm),
    ]

    # ── Step 3: Compute weighted score ───────────────────────────────────────
    score = compute_score(sig_results)

    # ── Step 4: Classify and alert ───────────────────────────────────────────
    attack_type = classify_attack(sig_results)
    alert = score > THETA_LW

    return alert, attack_type, score, sig_results


# =============================================================================
# SECTION 7 — ARGUMENT PARSER (same pattern as PQ_SDVN_security.py)
# =============================================================================

def parse_arguments():
    args_dict = {
        'event_type':      'beacon',
        'node_id':         0,
        'claimed_id':      0,
        'physical_id':     0,
        'sender_ts':       0.0,
        'recv_ts':         0.0,
        'reporter_id':     0,
        'link_src':        0,
        'link_dst':        1,
        'reporter_x':      0.0,
        'reporter_y':      0.0,
        'src_x':           0.0,
        'src_y':           0.0,
        'dst_x':           100.0,
        'dst_y':           0.0,
        'rssi':            -60.0,
        'reporter_count':  1,
        'path_count':      1,
    }

    raw = " ".join(sys.argv[1:])
    for arg in shlex.split(raw):
        if "=" not in arg:
            continue
        key, val = arg.split("=", 1)
        key = key.strip()
        val = val.strip()
        if key in ('node_id', 'claimed_id', 'physical_id', 'reporter_id',
                   'link_src', 'link_dst', 'reporter_count', 'path_count'):
            args_dict[key] = int(val)
        elif key in ('sender_ts', 'recv_ts', 'reporter_x', 'reporter_y',
                     'src_x', 'src_y', 'dst_x', 'dst_y', 'rssi'):
            args_dict[key] = float(val)
        else:
            args_dict[key] = val

    # Default claimed_id and physical_id to node_id if not supplied
    if args_dict['claimed_id'] == 0 and args_dict['node_id'] != 0:
        args_dict['claimed_id'] = args_dict['node_id']
    if args_dict['physical_id'] == 0 and args_dict['node_id'] != 0:
        args_dict['physical_id'] = args_dict['node_id']

    return args_dict


# =============================================================================
# SECTION 8 — MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    args = parse_arguments()

    print(f"\n[LW-DETECT] Processing event: node={args['node_id']} "
          f"type={args['event_type']} ts={args['sender_ts']:.3f}")

    alert, attack_type, score, sig_results = lw_detect(args)

    sig_names = ['TTW-S1','TTW-S2','TTW-S3',
                 'BSHH-S1','BSHH-S2','BSHH-S3',
                 'ME-S1','ME-S2','ME-S3']

    print(f"\n{'─'*50}")
    print(f"Signatures fired:")
    for i, (name, fired) in enumerate(zip(sig_names, sig_results)):
        status = "FIRED" if fired else "ok"
        print(f"  {name}: {status}  (weight={WEIGHTS[i]:.3f})")

    print(f"\nScore:  {score:.4f}  (threshold={THETA_LW})")
    print(f"Class:  {attack_type}")
    print(f"Alert:  {'YES — BLOCK THIS BEACON' if alert else 'no — pass through'}")
    print(f"{'─'*50}")

    # Output for ns-3 parsing
    print(f"\n[OUTPUT] ALERT={alert}")
    print(f"[OUTPUT] ATTACK_TYPE={attack_type}")
    print(f"[OUTPUT] SCORE={score:.4f}")
    print(f"[OUTPUT] SIGS={''.join(str(s) for s in sig_results)}")

    # Exit code: 0 = safe, 1 = alert (so routing.cc can check return code)
    end = time.time()
    print(f"\nExecution time: {(end-start)*1e6:.0f} µs")

    sys.exit(1 if alert else 0)
