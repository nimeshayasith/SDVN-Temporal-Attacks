#!/bin/bash
# Runs knn_bagging_detector.py on every collected pairs CSV (13 scenarios x
# 6 attack percentages = 78 points), extracting each point's holdout MCC.
set -e
DIR="/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35/scratch/SDVN project /SDVN-Temporal-Attacks/existing_methods"
PAIRS_DIR="$HOME/comparison_sweep/veremi/pairs"
OUT_DIR="$HOME/comparison_sweep/knn_bagging"
mkdir -p "$OUT_DIR/logs"

RESULTS="$OUT_DIR/knn_bagging_summary.csv"
echo "attack_scenario,attack_percentage,mcc" > "$RESULTS"

for f in "$PAIRS_DIR"/pairs_sc*.csv; do
  base=$(basename "$f" .csv)
  # base looks like: pairs_sc6_p40
  sc=$(echo "$base" | sed -E 's/pairs_sc([0-9]+)_p([0-9]+)/\1/')
  pct=$(echo "$base" | sed -E 's/pairs_sc([0-9]+)_p([0-9]+)/\2/')
  echo "=== KNN+Bagging scenario=$sc pct=$pct ==="
  logfile="$OUT_DIR/logs/${base}.log"
  python3 "$DIR/knn_bagging_detector.py" "$f" --holdout-only > "$logfile" 2>&1 || true

  # Extract KNN+Bagging's own MCC — holdout table row format:
  # KNN+Bagging  Acc%  Prec  Recall  F1  MCC  AUROC  Tdet  TP  FP  FN  N_test
  # (col 1 = classifier name, col 6 = MCC)
  mcc=$(grep -E "^[[:space:]]*KNN\+Bagging[[:space:]]" "$logfile" | tail -1 | awk '{print $6}')
  if [ -z "$mcc" ]; then mcc="NA"; fi
  echo "$sc,$pct,$mcc" >> "$RESULTS"
  echo "  -> mcc=$mcc"
done

echo ""
echo "=== KNN+Bagging batch complete: $RESULTS ==="
cat "$RESULTS"
