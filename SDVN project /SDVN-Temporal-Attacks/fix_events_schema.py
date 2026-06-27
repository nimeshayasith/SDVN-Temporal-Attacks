#!/usr/bin/env python3
"""Post-processing: remove injected seed_id column from new rows in all_events.csv."""
import sys, os

def fix_events_csv(path):
    with open(path) as f:
        lines = f.readlines()
    header = lines[0]
    header_cols = header.count(",") + 1
    print(f"[fix] Header has {header_cols} columns.")
    fixed_lines = [header]
    n_fixed = n_kept = 0
    for line in lines[1:]:
        line = line.rstrip("
")
        if not line:
            continue
        cols = line.split(",")
        if len(cols) == header_cols + 1:
            cols.pop(1)
            fixed_lines.append(",".join(cols) + "
")
            n_fixed += 1
        else:
            fixed_lines.append(line + "
")
            n_kept += 1
    backup = path + ".bak"
    os.rename(path, backup)
    with open(path, "w") as f:
        f.writelines(fixed_lines)
    print(f"[fix] Done: {n_kept} kept, {n_fixed} seed_id stripped. Total rows: {len(fixed_lines)-1}. Backup: {backup}")

if __name__ == "__main__":
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "scratch/SDVN project /SDVN-Temporal-Attacks/training_data/all_events.csv"
    fix_events_csv(csv_path)
