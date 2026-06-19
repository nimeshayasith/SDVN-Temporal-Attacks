#!/usr/bin/env python3
"""
temporal_knn_detector.py
------------------------
Multi-classifier ensemble detector for Temporal-Echo topology poisoning
attack detection in SDVNs (TTW / BSHH / ME attack families).

Based on: Mekonen, H.D.; Bitew, M.A.; Kifle, M.
  "VeReMi Dataset-Based Detection of Position Falsification Attacks
   Using K-Nearest Neighbor and Bagging Ensemble Learning in IoV."
  PLOS ONE 2025

Adapts the VeReMi KNN+Bagging framework to classify Temporal-Echo
attacks using 9 consecutive-event-pair temporal features extracted by
temporal_veremi_detector.cc.

Implements all 4 classifiers from Table 5:
  1. Decision Tree  + Bagging
  2. Random Forest  + Bagging
  3. KNN            + Bagging  (n_neighbors=3, weights='distance')
  4. MLP            + Bagging

5-fold stratified cross-validation (paper Figures 6-13 pattern).

Usage:
  python3 temporal_knn_detector.py [temporal_veremi_pairs.csv] [options]

Options:
  --test-split   FLOAT   Test fraction for holdout eval (default: 0.30)
  --n-estimators INT     Bagging ensemble size (default: 10)
  --n-neighbors  INT     KNN k value (default: 3)
  --n-folds      INT     Cross-validation folds (default: 5)
  --cv-only              Run only cross-validation (skip holdout table)
  --holdout-only         Run only holdout evaluation (skip CV)

Input CSV columns (from temporal_veremi_detector.cc):
  vehicle_id, attack_scenario, sim_time_s,
  ev_ts1, ev_ts2, ts_delta,
  rx_time1, rx_time2, time_interval,
  rx_delay2, identity_match, reporter_count,
  label

The 9 classification features:
  ev_ts1, ev_ts2, ts_delta,
  rx_time1, rx_time2, time_interval,
  rx_delay2, identity_match, reporter_count

Feature semantics:
  ev_ts1         — previous event's claimed timestamp
  ev_ts2         — current  event's claimed timestamp
  ts_delta       — ev_ts2 - ev_ts1 (claimed-time progression)
  rx_time1       — previous reception time (wall-clock at controller)
  rx_time2       — current  reception time
  time_interval  — rx_time2 - rx_time1 (actual inter-arrival interval)
  rx_delay2      — rx_time2 - ev_ts2   (current-packet staleness)
  identity_match — 1.0 = physical_sender == claimed; 0.0 = mismatch (BSHH)
  reporter_count — distinct reporters for this link/entity (ME)

Output:
  Console table matching Mekonen et al. Table 5 format (all 4 classifiers)
  temporal_knn_results.csv  — per-scenario holdout metrics (all classifiers)
  temporal_cv_results.csv   — 5-fold CV mean ± std metrics

Requirements:
  pip install scikit-learn pandas numpy
  scikit-learn >= 1.2 required (uses 'estimator=' in BaggingClassifier)
"""

import sys
import argparse
import numpy as np
import pandas as pd

try:
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.ensemble import BaggingClassifier, RandomForestClassifier
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
    from sklearn.metrics import (precision_score, recall_score,
                                 accuracy_score, f1_score,
                                 confusion_matrix, make_scorer)
    import sklearn
    _sklearn_ok = True
except ImportError:
    _sklearn_ok = False

# ─────────────────────────────────────────────────────────────
# Attack scenario labels (matches routing.cc / temporal_*_detector.cc)
# ─────────────────────────────────────────────────────────────
SCENARIO_NAMES = {
    0:  "Baseline (no attack)",
    1:  "TTW-S1 — Malicious Vehicle, No RSU",
    2:  "TTW-S2 — Malicious RSU",
    3:  "TTW-S3 — Malicious Controller, No RSU",
    4:  "TTW-S4 — Malicious Controller, With RSU",
    5:  "BSHH-S1 — Malicious Vehicle, No RSU",
    6:  "BSHH-S2 — Malicious RSU",
    7:  "BSHH-S3 — Malicious Controller, No RSU",
    8:  "BSHH-S4 — Malicious Controller, With RSU",
    9:  "ME-S1 — Malicious Vehicles, No RSU",
    10: "ME-S2 — Malicious RSU",
    11: "ME-S3 — Malicious Controller, No RSU",
    12: "ME-S4 — Malicious Controller, With RSU",
}

# Attack family labels for grouping
FAMILY_NAMES = {
    "TTW":  "TTW (Topology Time-Warp)",
    "BSHH": "BSHH (Beacon-State Heartbeat Hijack)",
    "ME":   "ME (Multipath Echo)",
}

# ─────────────────────────────────────────────────────────────
# The 9 temporal features extracted from consecutive event pairs
# Column names must match temporal_veremi_pairs.csv header written
# by temporal_veremi_detector.cc
# ─────────────────────────────────────────────────────────────
FEATURE_COLS = [
    "ev_ts1", "ev_ts2", "ts_delta",
    "rx_time1", "rx_time2", "time_interval",
    "rx_delay2", "identity_match", "reporter_count",
]

# Classifier display order (matches Mekonen et al. Table 5 column order)
CLF_ORDER = ["DT+Bagging", "RF+Bagging", "KNN+Bagging", "MLP+Bagging"]


# ─────────────────────────────────────────────────────────────
def _make_bagging(base, n_estimators):
    """
    Wrap a base estimator in BaggingClassifier.
    Handles sklearn >= 1.2 API change (estimator= vs base_estimator=).
    """
    sk_major, sk_minor = (int(x) for x in sklearn.__version__.split(".")[:2])
    kwargs = dict(n_estimators=n_estimators, random_state=42)
    if (sk_major, sk_minor) >= (1, 2):
        return BaggingClassifier(estimator=base, **kwargs)
    else:
        return BaggingClassifier(base_estimator=base, **kwargs)


def build_classifiers(n_estimators, n_neighbors):
    """
    Return an ordered dict of name -> Pipeline for all 4 classifiers.
    Parameters match the Mekonen et al. paper:
        DT:  DecisionTreeClassifier (default criterion=gini)
        RF:  RandomForestClassifier(n_estimators=10)
        KNN: KNeighborsClassifier(n_neighbors=3, weights='distance')
        MLP: MLPClassifier(hidden_layer_sizes=(100,), max_iter=500)
    """
    dt_bag  = _make_bagging(
        DecisionTreeClassifier(random_state=42),
        n_estimators
    )
    rf_bag  = _make_bagging(
        RandomForestClassifier(n_estimators=10, random_state=42),
        n_estimators
    )
    knn_bag = _make_bagging(
        KNeighborsClassifier(n_neighbors=n_neighbors, weights="distance"),
        n_estimators
    )
    mlp_bag = _make_bagging(
        MLPClassifier(hidden_layer_sizes=(100,), max_iter=500, random_state=42),
        n_estimators
    )

    return {
        "DT+Bagging":  Pipeline([("scaler", StandardScaler()), ("clf", dt_bag)]),
        "RF+Bagging":  Pipeline([("scaler", StandardScaler()), ("clf", rf_bag)]),
        "KNN+Bagging": Pipeline([("scaler", StandardScaler()), ("clf", knn_bag)]),
        "MLP+Bagging": Pipeline([("scaler", StandardScaler()), ("clf", mlp_bag)]),
    }


# ─────────────────────────────────────────────────────────────
def balance_dataset(df_legit, df_attack):
    """
    Create a balanced combined dataset.
    Keeps up to 3x as many legit rows as attack rows to limit class imbalance.
    Returns None if insufficient data for either class.
    """
    n_attack = len(df_attack)
    if n_attack == 0:
        return None
    n_legit_sample = min(len(df_legit), n_attack * 3)
    if n_legit_sample == 0:
        return None
    df_legit_sample = df_legit.sample(n=n_legit_sample, random_state=42)
    df_combined = pd.concat([df_legit_sample, df_attack], ignore_index=True)
    return df_combined.sample(frac=1, random_state=42).reset_index(drop=True)


# ─────────────────────────────────────────────────────────────
def evaluate_holdout(df_combined, scenario, classifiers, test_split):
    """
    70/30 holdout split evaluation for all 4 classifiers.
    Matches the train/test split in Mekonen et al.
    Returns a list of result dicts (one per classifier).
    """
    missing = [c for c in FEATURE_COLS if c not in df_combined.columns]
    if missing:
        print(f"  [ERROR] Missing feature columns: {missing}")
        return []

    X = df_combined[FEATURE_COLS].values
    y = df_combined["label"].values

    if len(np.unique(y)) < 2:
        print(f"  [Scenario {scenario}] Only one class — skipping holdout.")
        return []

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_split, random_state=42, stratify=y
    )

    results = []
    for clf_name, clf in classifiers.items():
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        results.append({
            "scenario":    scenario,
            "attack_name": SCENARIO_NAMES.get(scenario, f"Scenario {scenario}"),
            "classifier":  clf_name,
            "n_train":     int(len(X_train)),
            "n_test":      int(len(X_test)),
            "tp":          int(tp),
            "tn":          int(tn),
            "fp":          int(fp),
            "fn":          int(fn),
            "accuracy":    float(accuracy_score (y_test, y_pred) * 100.0),
            "precision":   float(precision_score(y_test, y_pred, zero_division=0)),
            "recall":      float(recall_score   (y_test, y_pred, zero_division=0)),
            "f1":          float(f1_score       (y_test, y_pred, zero_division=0)),
        })
    return results


# ─────────────────────────────────────────────────────────────
def evaluate_cv(df_combined, scenario, classifiers, n_folds):
    """
    n-fold stratified cross-validation for all 4 classifiers.
    Returns a list of result dicts with mean ± std metrics.
    """
    missing = [c for c in FEATURE_COLS if c not in df_combined.columns]
    if missing:
        print(f"  [ERROR] Missing feature columns: {missing}")
        return []

    X = df_combined[FEATURE_COLS].values
    y = df_combined["label"].values

    if len(np.unique(y)) < 2:
        print(f"  [Scenario {scenario}] Only one class — skipping CV.")
        return []

    if len(X) < n_folds:
        print(f"  [Scenario {scenario}] Too few samples ({len(X)}) for {n_folds}-fold CV — skipping.")
        return []

    cv = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)

    scoring = {
        "accuracy":  make_scorer(accuracy_score),
        "precision": make_scorer(precision_score, zero_division=0),
        "recall":    make_scorer(recall_score,    zero_division=0),
        "f1":        make_scorer(f1_score,        zero_division=0),
    }

    results = []
    for clf_name, clf in classifiers.items():
        scores = cross_validate(
            clf, X, y,
            cv=cv,
            scoring=scoring,
            n_jobs=1,
            return_train_score=False,
        )
        acc_arr  = scores["test_accuracy"]  * 100.0
        prec_arr = scores["test_precision"]
        rec_arr  = scores["test_recall"]
        f1_arr   = scores["test_f1"]

        results.append({
            "scenario":     scenario,
            "attack_name":  SCENARIO_NAMES.get(scenario, f"Scenario {scenario}"),
            "classifier":   clf_name,
            "n_samples":    int(len(X)),
            "n_folds":      n_folds,
            "acc_mean":     float(acc_arr.mean()),
            "acc_std":      float(acc_arr.std()),
            "prec_mean":    float(prec_arr.mean()),
            "prec_std":     float(prec_arr.std()),
            "recall_mean":  float(rec_arr.mean()),
            "recall_std":   float(rec_arr.std()),
            "f1_mean":      float(f1_arr.mean()),
            "f1_std":       float(f1_arr.std()),
            "acc_per_fold": acc_arr.tolist(),
            "f1_per_fold":  f1_arr.tolist(),
        })
    return results


# ─────────────────────────────────────────────────────────────
def print_holdout_table(results, n_estimators, n_neighbors):
    """
    Print holdout results in Mekonen et al. Table 5 format,
    grouped by attack scenario.
    """
    scenarios = sorted({r["scenario"] for r in results if r["scenario"] != -1})

    W = 95
    print(f"\n{'='*W}")
    print(f"  Table 5 — Holdout Evaluation  (70 % train / 30 % test)")
    print(f"  n_estimators={n_estimators}   KNN k={n_neighbors} (weights='distance')")
    print(f"  Reference: Mekonen et al., PLOS ONE 2025  |  Adapted for Temporal-Echo attacks")
    print(f"{'='*W}")

    hdr = (f"  {'Attack Scenario':<30} {'Classifier':<16}"
           f"{'Acc%':>7}{'Prec':>8}{'Recall':>8}{'F1':>8}"
           f"{'TP':>6}{'FP':>6}{'FN':>6}{'N_test':>8}")

    for sc in scenarios:
        name = SCENARIO_NAMES.get(sc, f"Scenario {sc}")
        print(f"\n  ── {name} ──")
        print(hdr)
        print(f"  {'-'*(W-2)}")
        for clf_name in CLF_ORDER:
            r = next((x for x in results
                      if x["scenario"] == sc and x["classifier"] == clf_name), None)
            if r is None:
                continue
            print(f"  {'':30} {clf_name:<16}"
                  f"{r['accuracy']:>7.1f}"
                  f"{r['precision']:>8.3f}"
                  f"{r['recall']:>8.3f}"
                  f"{r['f1']:>8.3f}"
                  f"{r['tp']:>6}"
                  f"{r['fp']:>6}"
                  f"{r['fn']:>6}"
                  f"{r['n_test']:>8}")

    # All scenarios combined
    combined = [r for r in results if r["scenario"] == -1]
    if combined:
        print(f"\n  ── ALL SCENARIOS COMBINED ──")
        print(hdr)
        print(f"  {'-'*(W-2)}")
        for clf_name in CLF_ORDER:
            r = next((x for x in combined if x["classifier"] == clf_name), None)
            if r is None:
                continue
            print(f"  {'ALL COMBINED':<30} {clf_name:<16}"
                  f"{r['accuracy']:>7.1f}"
                  f"{r['precision']:>8.3f}"
                  f"{r['recall']:>8.3f}"
                  f"{r['f1']:>8.3f}"
                  f"{r['tp']:>6}"
                  f"{r['fp']:>6}"
                  f"{r['fn']:>6}"
                  f"{r['n_test']:>8}")

    print(f"\n{'='*W}")


# ─────────────────────────────────────────────────────────────
def print_cv_table(cv_results, n_folds):
    """
    Print n-fold CV mean ± std table.
    """
    scenarios = sorted({r["scenario"] for r in cv_results if r["scenario"] != -1})

    W = 95
    print(f"\n{'='*W}")
    print(f"  {n_folds}-Fold Stratified Cross-Validation Results")
    print(f"  Reference: Mekonen et al., PLOS ONE 2025 — Figures 6-13  |  Temporal-Echo adaptation")
    print(f"{'='*W}")

    for sc in scenarios:
        name = SCENARIO_NAMES.get(sc, f"Scenario {sc}")
        print(f"\n  ── {name} ──")
        print(f"  {'Classifier':<16}"
              f"{'Acc% mean±std':>18}"
              f"{'Prec mean±std':>18}"
              f"{'Recall mean±std':>18}"
              f"{'F1 mean±std':>18}")
        print(f"  {'-'*(W-2)}")
        for clf_name in CLF_ORDER:
            r = next((x for x in cv_results
                      if x["scenario"] == sc and x["classifier"] == clf_name), None)
            if r is None:
                continue
            print(f"  {clf_name:<16}"
                  f"  {r['acc_mean']:>6.1f} ± {r['acc_std']:>4.1f}  "
                  f"  {r['prec_mean']:>5.3f} ± {r['prec_std']:>5.3f}  "
                  f"  {r['recall_mean']:>5.3f} ± {r['recall_std']:>5.3f}  "
                  f"  {r['f1_mean']:>5.3f} ± {r['f1_std']:>5.3f}")

        # Per-fold breakdown
        print(f"\n  Per-fold accuracy (%):")
        for clf_name in CLF_ORDER:
            r = next((x for x in cv_results
                      if x["scenario"] == sc and x["classifier"] == clf_name), None)
            if r is None:
                continue
            fold_str = "  ".join(f"F{i+1}:{v:.1f}" for i, v in enumerate(r["acc_per_fold"]))
            print(f"    {clf_name:<14} {fold_str}")

    # All combined
    combined_cv = [r for r in cv_results if r["scenario"] == -1]
    if combined_cv:
        print(f"\n  ── ALL SCENARIOS COMBINED ──")
        print(f"  {'Classifier':<16}"
              f"{'Acc% mean±std':>18}"
              f"{'Prec mean±std':>18}"
              f"{'Recall mean±std':>18}"
              f"{'F1 mean±std':>18}")
        print(f"  {'-'*(W-2)}")
        for clf_name in CLF_ORDER:
            r = next((x for x in combined_cv if x["classifier"] == clf_name), None)
            if r is None:
                continue
            print(f"  {clf_name:<16}"
                  f"  {r['acc_mean']:>6.1f} ± {r['acc_std']:>4.1f}  "
                  f"  {r['prec_mean']:>5.3f} ± {r['prec_std']:>5.3f}  "
                  f"  {r['recall_mean']:>5.3f} ± {r['recall_std']:>5.3f}  "
                  f"  {r['f1_mean']:>5.3f} ± {r['f1_std']:>5.3f}")

    print(f"\n{'='*W}")


# ─────────────────────────────────────────────────────────────
def main():
    if not _sklearn_ok:
        print("ERROR: scikit-learn is not installed.")
        print("  pip install scikit-learn pandas numpy")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description=(
            "Multi-classifier Temporal-Echo detector — Mekonen et al. PLOS ONE 2025\n"
            "Classifiers: DT+Bagging, RF+Bagging, KNN+Bagging, MLP+Bagging\n"
            "Features:    9 temporal event-pair features (ev_ts1..reporter_count)\n"
            "Evaluation:  70/30 holdout split + 5-fold stratified CV"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "csv_file", nargs="?", default="temporal_veremi_pairs.csv",
        help="Temporal event-pair CSV from temporal_veremi_detector.cc "
             "(default: temporal_veremi_pairs.csv)"
    )
    parser.add_argument(
        "--test-split", type=float, default=0.30,
        help="Holdout test fraction (default: 0.30)"
    )
    parser.add_argument(
        "--n-estimators", type=int, default=10,
        help="Bagging ensemble size (default: 10)"
    )
    parser.add_argument(
        "--n-neighbors", type=int, default=3,
        help="KNN k (default: 3)"
    )
    parser.add_argument(
        "--n-folds", type=int, default=5,
        help="Cross-validation folds (default: 5)"
    )
    parser.add_argument(
        "--cv-only", action="store_true",
        help="Run only cross-validation, skip holdout table"
    )
    parser.add_argument(
        "--holdout-only", action="store_true",
        help="Run only holdout evaluation, skip CV"
    )
    args = parser.parse_args()

    run_cv      = not args.holdout_only
    run_holdout = not args.cv_only

    # ── Load CSV ──────────────────────────────────────────────────────────
    try:
        df = pd.read_csv(args.csv_file)
    except FileNotFoundError:
        print(f"ERROR: '{args.csv_file}' not found.")
        print("  Generate it first:")
        print("    ./waf --run \"scratch/temporal_veremi_detector "
              "--simTime=60 --N_Vehicles=6 --N_RSUs=0 --attack_scenario=1\"")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR reading '{args.csv_file}': {e}")
        sys.exit(1)

    if df.empty:
        print(f"ERROR: '{args.csv_file}' is empty.")
        sys.exit(1)

    print(f"\n{'='*72}")
    print(f"  Temporal-Echo Multi-Classifier Detector")
    print(f"  Reference: Mekonen et al., PLOS ONE 2025  (temporal adaptation)")
    print(f"{'='*72}")
    print(f"  Input CSV       : {args.csv_file}")
    print(f"  Total pairs     : {len(df)}")
    attack_count = int(df["label"].sum()) if "label" in df.columns else 0
    print(f"  Attack pairs    : {attack_count}")
    print(f"  Legit pairs     : {len(df) - attack_count}")
    if run_holdout:
        print(f"  Test split      : {args.test_split * 100:.0f}%")
    if run_cv:
        print(f"  CV folds        : {args.n_folds}")
    print(f"  n_estimators    : {args.n_estimators}")
    print(f"  KNN k           : {args.n_neighbors}  (weights='distance')")
    print(f"  Classifiers     : {', '.join(CLF_ORDER)}")
    print(f"  Features        : {', '.join(FEATURE_COLS)}")
    print(f"  sklearn version : {sklearn.__version__}")
    print(f"{'='*72}\n")

    # ── Validate columns ─────────────────────────────────────────────────
    required = FEATURE_COLS + ["label", "attack_scenario"]
    missing  = [c for c in required if c not in df.columns]
    if missing:
        print(f"ERROR: Missing columns in CSV: {missing}")
        print(f"  Expected: {required}")
        sys.exit(1)

    # ── Separate legit and attack subsets ─────────────────────────────────
    df_legit  = df[df["label"] == 0].copy()
    df_attack = df[df["label"] == 1].copy()

    scenarios_present = sorted(
        [int(s) for s in df["attack_scenario"].unique() if s != 0]
    )

    if not scenarios_present:
        print("No attack scenarios found in CSV (all label=0).")
        print("Run temporal_veremi_detector with attack_scenario != 0 (e.g. 1..12).")
        sys.exit(0)

    # ── Build all 4 classifiers ───────────────────────────────────────────
    classifiers = build_classifiers(args.n_estimators, args.n_neighbors)

    holdout_results = []
    cv_results      = []

    # ── Per-scenario evaluation ───────────────────────────────────────────
    for sc in scenarios_present:
        name = SCENARIO_NAMES.get(sc, f"Scenario {sc}")
        df_sc       = df_attack[df_attack["attack_scenario"] == sc]
        df_combined = balance_dataset(df_legit, df_sc)

        if df_combined is None:
            print(f"  [{name}] Insufficient data — skipped.")
            continue

        print(f"  {name}")
        print(f"    {len(df_sc)} attack pairs | {len(df_legit)} legit | "
              f"{len(df_combined)} balanced total")

        if run_holdout:
            print(f"    Holdout (70/30) …", end="  ", flush=True)
            h = evaluate_holdout(df_combined, sc, classifiers, args.test_split)
            holdout_results.extend(h)
            for r in h:
                print(f"{r['classifier']}:{r['accuracy']:.0f}%", end="  ")
            print()

        if run_cv:
            print(f"    {args.n_folds}-fold CV    …", end="  ", flush=True)
            c = evaluate_cv(df_combined, sc, classifiers, args.n_folds)
            cv_results.extend(c)
            for r in c:
                print(f"{r['classifier']}:{r['acc_mean']:.0f}%±{r['acc_std']:.1f}", end="  ")
            print()

        print()

    # ── All scenarios combined (if multiple present) ──────────────────────
    if len(scenarios_present) > 1 and len(df_attack) > 0:
        df_combined_all = balance_dataset(df_legit, df_attack.copy())
        if df_combined_all is not None:
            print(f"  ALL SCENARIOS COMBINED")
            print(f"    {len(df_attack)} attack pairs | {len(df_legit)} legit | "
                  f"{len(df_combined_all)} balanced total")

            if run_holdout:
                print(f"    Holdout (70/30) …", end="  ", flush=True)
                h = evaluate_holdout(df_combined_all, -1, classifiers, args.test_split)
                for r in h:
                    r["attack_name"] = "ALL SCENARIOS COMBINED"
                holdout_results.extend(h)
                for r in h:
                    print(f"{r['classifier']}:{r['accuracy']:.0f}%", end="  ")
                print()

            if run_cv:
                print(f"    {args.n_folds}-fold CV    …", end="  ", flush=True)
                c = evaluate_cv(df_combined_all, -1, classifiers, args.n_folds)
                for r in c:
                    r["attack_name"] = "ALL SCENARIOS COMBINED"
                cv_results.extend(c)
                for r in c:
                    print(f"{r['classifier']}:{r['acc_mean']:.0f}%±{r['acc_std']:.1f}", end="  ")
                print()

            print()

    if not holdout_results and not cv_results:
        print("\nNo results to report — check input data.")
        sys.exit(0)

    # ── Print tables ──────────────────────────────────────────────────────
    if run_holdout and holdout_results:
        print_holdout_table(holdout_results, args.n_estimators, args.n_neighbors)

    if run_cv and cv_results:
        print_cv_table(cv_results, args.n_folds)

    # ── Save holdout CSV ──────────────────────────────────────────────────
    if run_holdout and holdout_results:
        out_csv = "temporal_knn_results.csv"
        rows = []
        for r in holdout_results:
            rows.append({
                "attack_scenario":  r["scenario"],
                "attack_name":      r["attack_name"],
                "classifier":       r["classifier"],
                "n_train":          r["n_train"],
                "n_test":           r["n_test"],
                "tp":               r["tp"],
                "tn":               r["tn"],
                "fp":               r["fp"],
                "fn":               r["fn"],
                "accuracy_pct":     round(r["accuracy"],  3),
                "precision":        round(r["precision"], 3),
                "recall":           round(r["recall"],    3),
                "f1":               round(r["f1"],        3),
            })
        pd.DataFrame(rows).to_csv(out_csv, index=False)
        print(f"\n  Holdout results saved to : {out_csv}")

    # ── Save CV CSV ───────────────────────────────────────────────────────
    if run_cv and cv_results:
        cv_csv = "temporal_cv_results.csv"
        rows = []
        for r in cv_results:
            fold_acc = r.get("acc_per_fold", [])
            fold_f1  = r.get("f1_per_fold",  [])
            row = {
                "attack_scenario":  r["scenario"],
                "attack_name":      r["attack_name"],
                "classifier":       r["classifier"],
                "n_samples":        r["n_samples"],
                "n_folds":          r["n_folds"],
                "acc_mean_pct":     round(r["acc_mean"],    3),
                "acc_std_pct":      round(r["acc_std"],     3),
                "prec_mean":        round(r["prec_mean"],   3),
                "prec_std":         round(r["prec_std"],    3),
                "recall_mean":      round(r["recall_mean"], 3),
                "recall_std":       round(r["recall_std"],  3),
                "f1_mean":          round(r["f1_mean"],     3),
                "f1_std":           round(r["f1_std"],      3),
            }
            for i, (a, f) in enumerate(zip(fold_acc, fold_f1), start=1):
                row[f"fold{i}_acc_pct"] = round(a, 3)
                row[f"fold{i}_f1"]      = round(f, 3)
            rows.append(row)
        pd.DataFrame(rows).to_csv(cv_csv, index=False)
        print(f"  CV results saved to      : {cv_csv}")

    print(f"\n  Tip — to build a full comparison across all 12 scenarios,")
    print(f"  run temporal_veremi_detector for each scenario then merge:")
    print(f"    # Linux/Mac:")
    print(f"    head -1 temporal_veremi_pairs.csv > all_pairs.csv")
    print(f"    tail -n+2 -q temporal_veremi_pairs_s*.csv >> all_pairs.csv")
    print(f"    python3 temporal_knn_detector.py all_pairs.csv")
    print()


# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
