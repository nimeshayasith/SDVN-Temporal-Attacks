#!/usr/bin/env python3
"""
Link lifetime solver for routing_algorithm=4 (Proposed RL).

Reads optimization_link_lifetime_data.csv (per-node positions/velocities from NS-3),
computes pairwise DSRC link lifetimes, and writes link_lifetime_solution.csv.

Output format per line: "<pair_idx> <lifetime>,0"
  - pair_idx = i*total_size + j  (link from node i to node j)
  - lifetime  > 0.0  → link is alive (used by NS-3 routing)
  - lifetime == 0.0  → link is dead

The C++ parser (read_lifetime_from_csv) does:
    fin >> temp          # reads "<pair_idx>" token
    getline(fin, line)   # reads " <lifetime>,0"
    strtok(line, ",")    # first token " <lifetime>" → link_lifetime_vector[j]
"""

import math
from pathlib import Path

BASE   = Path('/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35/scratch')
IN     = BASE / 'optimization_link_lifetime_data.csv'
OUT    = BASE / 'link_lifetime_solution.csv'

DSRC_RANGE = 300.0   # metres — matches TTW_COMM_RANGE in routing.cc
DEFAULT_LIFETIME = 1.0

# ── Parse node positions from input CSV ──────────────────────────────────────
# Format: total_size, nodeid, pos_x, pos_y, vel_x, vel_y, accel_x, accel_y,
#         mobility_scenario, N_Vehicles, N_RSUs
total_size = 100
n_vehicles = 0
n_rsus = 0
nodes = {}   # {nodeid: (pos_x, pos_y, vel_x, vel_y)}

if IN.exists():
    with IN.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 4:
                continue
            try:
                ts   = int(parts[0])
                nid  = int(parts[1])
                px   = float(parts[2])
                py   = float(parts[3])
                vx   = float(parts[4]) if len(parts) > 4 else 0.0
                vy   = float(parts[5]) if len(parts) > 5 else 0.0
                nv   = int(parts[9])  if len(parts) > 9  else 0
                nr   = int(parts[10]) if len(parts) > 10 else 0
                total_size = ts
                if nv > 0:
                    n_vehicles = nv
                if nr > 0:
                    n_rsus = nr
                nodes[nid] = (px, py, vx, vy)
            except (ValueError, IndexError):
                continue

# Number of nodes that actually have physical DSRC devices in NS-3.
# Only nodes with index 0..(n_active-1) exist in wifidevices container.
n_active = n_vehicles + n_rsus
if n_active == 0:
    n_active = total_size  # fallback: treat all as active

n_pairs = total_size * total_size

# ── Compute pairwise link lifetimes ──────────────────────────────────────────
def link_lifetime(i, j):
    """Return link lifetime in seconds for the i→j DSRC link.

    Nodes with index >= n_active have no physical DSRC device — always 0.
    If positions are all zero (data not yet populated) default to DEFAULT_LIFETIME.
    Any pair whose Euclidean distance exceeds DSRC_RANGE is treated as 0.
    """
    if i == j:
        return 0.0   # no self-loop

    # Guard: non-existent physical nodes must have lifetime 0 so routing never
    # tries to call wifidevices.Get(i) or dsrc_Nodes.Get(i) out of bounds.
    if i >= n_active or j >= n_active:
        return 0.0

    di = nodes.get(i)
    dj = nodes.get(j)

    if di is None or dj is None:
        return DEFAULT_LIFETIME

    px_i, py_i, vx_i, vy_i = di
    px_j, py_j, vx_j, vy_j = dj

    # If either node has (0,0) position the SUMO data hasn't arrived yet
    # (e.g. attacker placeholder or uninitialized entry). Default to alive
    # so the routing algorithm can bootstrap without phantom dead links.
    if (px_i == 0 and py_i == 0) or (px_j == 0 and py_j == 0):
        return DEFAULT_LIFETIME

    dx = px_i - px_j
    dy = py_i - py_j
    dist = math.sqrt(dx*dx + dy*dy)

    if dist > DSRC_RANGE:
        return 0.0

    # Estimate time until link breaks using relative velocity.
    # Solve |pos_rel + t * vel_rel|² = R² for the smaller positive root.
    dvx = vx_i - vx_j
    dvy = vy_i - vy_j
    rel_speed_sq = dvx*dvx + dvy*dvy

    if rel_speed_sq < 1e-9:
        # Nodes are effectively stationary relative to each other → link persists.
        return DEFAULT_LIFETIME

    # Quadratic: rel_speed_sq * t² + 2*(dx*dvx + dy*dvy)*t + (dist²−R²) = 0
    a = rel_speed_sq
    b = 2.0 * (dx*dvx + dy*dvy)
    c = dist*dist - DSRC_RANGE*DSRC_RANGE
    discriminant = b*b - 4*a*c

    if discriminant < 0:
        return DEFAULT_LIFETIME   # nodes stay within range indefinitely

    sqrt_disc = math.sqrt(discriminant)
    t1 = (-b - sqrt_disc) / (2*a)
    t2 = (-b + sqrt_disc) / (2*a)

    # We want the smallest positive root (first exit time).
    positive_roots = [t for t in (t1, t2) if t > 1e-6]
    if not positive_roots:
        return DEFAULT_LIFETIME

    return max(0.0, min(positive_roots))

# ── Write output ──────────────────────────────────────────────────────────────
with OUT.open('w', encoding='utf-8') as f:
    for pair_idx in range(n_pairs):
        i = pair_idx // total_size
        j = pair_idx % total_size
        lt = link_lifetime(i, j)
        # Format: "<pair_idx> <lifetime>,0\n"
        # C++ parser: fin>>temp reads pair_idx, getline reads " <lt>,0",
        # strtok splits on "," → first field " <lt>" → dou_val = lt
        f.write(f'{pair_idx} {lt:.6f},0\n')

print(f'Wrote {n_pairs} rows → {OUT}')
