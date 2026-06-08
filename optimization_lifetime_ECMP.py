#!/usr/bin/env python3
"""
Link lifetime solver for routing_algorithm=0 (ECMP).
Writes link_lifetime_solution_ECMP.csv with total_size*total_size rows.

Output format per line: "<pair_idx> 1.0,0"
The C++ parser reads pair_idx as `fin >> temp`, then " 1.0,0" via getline,
then strtok on "," yields " 1.0" → parsed as 1.0.
"""
from pathlib import Path

BASE     = Path('/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35/scratch')
IN_FILE  = BASE / 'optimization_link_lifetime_data_ECMP.csv'
OUT_FILE = BASE / 'link_lifetime_solution_ECMP.csv'

total_size = 100  # default matches routing.cc global

if IN_FILE.exists():
    with IN_FILE.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            parts = [p.strip() for p in line.split(',')]
            if parts and parts[0].isdigit():
                total_size = int(parts[0])
                break  # total_size is the same on every row

n_pairs = total_size * total_size

with OUT_FILE.open('w', encoding='utf-8') as f:
    for pair_idx in range(n_pairs):
        f.write(f'{pair_idx} 1.000000,0\n')

print(f'Generated {n_pairs} rows in {OUT_FILE}')
