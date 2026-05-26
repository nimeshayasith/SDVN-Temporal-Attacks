#!/usr/bin/env python3
"""
knn_bagging_detector.py
-----------------------
Multi-classifier ensemble detector for VeReMi position falsification
attack detection in Internet-of-Vehicles (IoV).

Based on: Mekonen, H.D.; Bitew, M.A.; Kifle, M.
  "VeReMi Dataset-Based Detection of Position Falsification Attacks
   Using K-Nearest Neighbor and Bagging Ensemble Learning in IoV."
  PLOS ONE 2025

Implements all 4 classifiers from Table 5:
  1. Decision Tree  + Bagging
  2. Random Forest  + Bagging
  3. KNN            + Bagging  (n_neighbors=3, weights='distance')
  4. MLP            + Bagging

5-fold stratified cross-validation (paper Figures 6–13).

Usage:
  python3 knn_bagging_detector.py [veremi_pairs.csv] [options]

Options:
  --test-split   FLOAT   Test fraction for holdout eval (default: 0.30)
  --n-estimators INT     Bagging ensemble size (default: 10)
  --n-neighbors  INT     KNN k value (default: 3)
  --n-folds      INT     Cross-validation folds (default: 5)
  --cv-only              Run only cross-validation (skip holdout table)
  --holdout-only         Run only holdout evaluation (skip CV)

Input CSV columns (from veremi_attacks.cc):
  vehicle_id, attack_type, sim_time_s,
  pos_x1, pos_y1, spd_x1, spd_y1,
  pos_x2, pos_y2, spd_x2, spd_y2,
  time_interval, label

The 9 classification features (Section 4 of the paper):
  pos_x1, pos_y1, spd_x1, spd_y1,
  pos_x2, pos_y2, spd_x2, spd_y2,
  time_interval

Output:
  Console table matching Mekonen et al. Table 5 format (all 4 classifiers)
  veremi_knn_results.csv   — per-type holdout metrics (all classifiers)
  veremi_cv_results.csv    — 5-fold CV mean ± std metrics

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
# VeReMi attack type labels
# ─────────────────────────────────────────────────────────────
TYPE_NAMES = {
    0:  "Baseline (legit only)",
    1:  "Type 1  — Constant Position",
    2:  "Type 2  — Constant Offset",
    4:  "Type 4  — Random Position",
    8:  "Type 8  — Random Offset",
    16: "Type 16 — Eventual Stop",
}

# ─────────────────────────────────────────────────────────────
# The 9 features extracted from consecutive BSM pairs
# Column names must match veremi_pairs.csv header written by veremi_attacks.cc
# ─────────────────────────────────────────────────────────────
FEATURE_COLS = [
    "pos_x1", "pos_y1", "spd_x1", "spd_y1",
    "pos_x2", "pos_y2", "spd_x2", "spd_y2",
    "time_interval",
]

# Classifier display order (matches Mekonen et al. Table 5 column order)
CLF_ORDER = ["DT+Bagging", "RF+Bagging", "KNN+Bagging", "MLP+Bagging"]


# ─────────────────────────────────────────────────────────────
def _make_bagging(base, n_estimators):
    """
    Wrap a base estimator in BaggingClassifier, handling
    sklearn >= 1.2 API change (estimator= vs base_estimator=).
    """
    sk_major, sk_minor = (int(x) for x in sklearn.__version__.split(".")[:2])
    kwargs = dict(n_estimators=n_estimators, random_state=42)
    if (sk_major, sk_minor) >= (1, 2):
        return BaggingClassifier(estimator=base, **kwargs)
    else:
        return BaggingClassifier(base_estimator=base, **kwargs)


def build_classifiers(n_estimators, n_neighbors):
    """
    Return an ordered dict of name -> Pipeline for all 4 classifiers
    used in Mekonen et al. Table 5.

    All pipelines use StandardScaler preprocessing followed by a
    BaggingClassifier wrapping the respective base learner.

    Parameters match the paper:
        DT:   DecisionTreeClassifier (default criterion=gini)
        RF:   RandomForestClassifier(n_estimators=10)
        KNN:  KNeighborsClassifier(n_neighbors=3, weights='distance')
        MLP:  MLPClassifier(hidden_layer_sizes=(100,), max_iter=500)
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
    Keeps up to 3× as many legit rows as attack rows to limit class imbalance.
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
def evaluate_holdout(df_combined, attack_type, classifiers, test_split):
    """
    70/30 holdout split evaluation for all 4 classifiers.
    Matches the train/test split in Mekonen et al. (Training 70%, Testing 30%).

    Returns a list of result dicts (one per classifier).
    """
    missing = [c for c in FEATURE_COLS if c not in df_combined.columns]
    if missing:
        print(f"  [ERROR] Missing feature columns: {missing}")
        return []

    X = df_combined[FEATURE_COLS].values
    y = df_combined["label"].values

    if len(np.unique(y)) < 2:
        print(f"  [Type {attack_type}] Only one class — skipping holdout.")
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
            "attack_type": attack_type,
            "type_name":   TYPE_NAMES.get(attack_type, f"Type {attack_type}"),
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
def evaluate_cv(df_combined, attack_type, classifiers, n_folds):
    """
    n-fold stratified cross-validation for all 4 classifiers.
    Matches the evaluation approach in Mekonen et al. Figures 6–13
    which show per-fold accuracy and F1 for each attack type.

    Returns a list of result dicts with mean ± std metrics.
    """
    missing = [c for c in FEATURE_COLS if c not in df_combined.columns]
    if missing:
        print(f"  [ERROR] Missing feature columns: {missing}")
        return []

    X = df_combined[FEATURE_COLS].values
    y = df_combined["label"].values

    if len(np.unique(y)) < 2:
        print(f"  [Type {attack_type}] Only one class — skipping CV.")
        return []

    if len(X) < n_folds:
        print(f"  [Type {attack_type}] Too few samples ({len(X)}) for {n_folds}-fold CV — skipping.")
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
            n_jobs=1,                  # set to -1 for parallel if desired
            return_train_score=False,
        )
        acc_arr  = scores["test_accuracy"]  * 100.0
        prec_arr = scores["test_precision"]
        rec_arr  = scores["test_recall"]
        f1_arr   = scores["test_f1"]

        results.append({
            "attack_type":  attack_type,
            "type_name":    TYPE_NAMES.get(attack_type, f"Type {attack_type}"),
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
            "acc_per_fold": acc_arr.tolist(),   # for Figures 6–13 style plots
            "f1_per_fold":  f1_arr.tolist(),
        })
    return results


# ─────────────────────────────────────────────────────────────
def print_holdout_table(results, n_estimators, n_neighbors):
    """
    Print holdout results in Mekonen et al. Table 5 format.
    Shows all 4 classifiers grouped by attack type.
    """
    attack_types = sorted({r["attack_type"] for r in results
                           if r["attack_type"] != -1})

    W = 90
    print(f"\n{'='*W}")
    print(f"  Table 5 — Holdout Evaluation  (70 % train / 30 % test)")
    print(f"  n_estimators={n_estimators}   KNN k={n_neighbors} (weights='distance')")
    print(f"  Reference: Mekonen et al., PLOS ONE 2025")
    print(f"{'='*W}")

    hdr = (f"  {'Attack Type':<26} {'Classifier':<16}"
           f"{'Acc%':>7}{'Prec':>8}{'Recall':>8}{'F1':>8}"
           f"{'TP':>6}{'FP':>6}{'FN':>6}{'N_test':>8}")

    for at in attack_types:
        type_name = TYPE_NAMES.get(at, f"Type {at}")
        print(f"\n  ── {type_name} ──")
        print(hdr)
        print(f"  {'-'*(W-2)}")
        for clf_name in CLF_ORDER:
            r = next((x for x in results
                      if x["attack_type"] == at and x["classifier"] == clf_name), None)
            if r is None:
                continue
            tname = ""   # blank for 2nd–4th row; type shown in section header
            print(f"  {tname:<26} {clf_name:<16}"
                  f"{r['accuracy']:>7.1f}"
                  f"{r['precision']:>8.3f}"
                  f"{r['recall']:>8.3f}"
                  f"{r['f1']:>8.3f}"
                  f"{r['tp']:>6}"
                  f"{r['fp']:>6}"
                  f"{r['fn']:>6}"
                  f"{r['n_test']:>8}")

    # All-types combined
    combined = [r for r in results if r["attack_type"] == -1]
    if combined:
        print(f"\n  ── ALL TYPES COMBINED ──")
        print(hdr)
        print(f"  {'-'*(W-2)}")
        for clf_name in CLF_ORDER:
            r = next((x for x in combined if x["classifier"] == clf_name), None)
            if r is None:
                continue
            print(f"  {'ALL COMBINED':<26} {clf_name:<16}"
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
    Print 5-fold CV mean ± std table.
    Reproduces the information in Mekonen et al. Figures 6–13
    (per-fold accuracy and F1 for each attack type / classifier).
    """
    attack_types = sorted({r["attack_type"] for r in cv_results
                           if r["attack_type"] != -1})

    W = 90
    print(f"\n{'='*W}")
    print(f"  {n_folds}-Fold Stratified Cross-Validation Results")
    print(f"  Reference: Mekonen et al., PLOS ONE 2025 — Figures 6–13")
    print(f"{'='*W}")

    for at in attack_types:
        type_name = TYPE_NAMES.get(at, f"Type {at}")
        print(f"\n  ── {type_name} ──")
        print(f"  {'Classifier':<16}"
              f"{'Acc% mean±std':>18}"
              f"{'Prec mean±std':>18}"
              f"{'Recall mean±std':>18}"
              f"{'F1 mean±std':>18}")
        print(f"  {'-'*(W-2)}")
        for clf_name in CLF_ORDER:
            r = next((x for x in cv_results
                      if x["attack_type"] == at and x["classifier"] == clf_name), None)
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
                      if x["attack_type"] == at and x["classifier"] == clf_name), None)
            if r is None:
                continue
            fold_str = "  ".join(f"F{i+1}:{v:.1f}" for i, v in enumerate(r["acc_per_fold"]))
            print(f"    {clf_name:<14} {fold_str}")

    # All-types combined
    combined_cv = [r for r in cv_results if r["attack_type"] == -1]
    if combined_cv:
        print(f"\n  ── ALL TYPES COMBINED ──")
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
            "Multi-classifier VeReMi detector — Mekonen et al. PLOS ONE 2025\n"
            "Classifiers: DT+Bagging, RF+Bagging, KNN+Bagging, MLP+Bagging\n"
            "Evaluation:  70/30 holdout split + 5-fold stratified CV"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "csv_file", nargs="?", default="veremi_pairs.csv",
        help="Consecutive BSM pair CSV from veremi_attacks.cc (default: veremi_pairs.csv)"
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
        print("    ./waf --run \"scratch/veremi_attacks --simTime=60 "
              "--N_Vehicles=6 --N_RSUs=1 --attack_scenario=21\"")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR reading '{args.csv_file}': {e}")
        sys.exit(1)

    if df.empty:
        print(f"ERROR: '{args.csv_file}' is empty.")
        sys.exit(1)

    print(f"\n{'='*72}")
    print(f"  VeReMi Multi-Classifier Detector  —  Mekonen et al. PLOS ONE 2025")
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
    print(f"  sklearn version : {sklearn.__version__}")
    print(f"{'='*72}\n")

    # ── Validate columns ─────────────────────────────────────────────────
    required = FEATURE_COLS + ["label", "attack_type"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        print(f"ERROR: Missing columns in CSV: {missing}")
        print(f"  Expected: {required}")
        sys.exit(1)

    # ── Separate legit and attack subsets ─────────────────────────────────
    df_legit  = df[df["label"] == 0].copy()
    df_attack = df[df["label"] == 1].copy()

    attack_types_present = sorted(
        [t for t in df["attack_type"].unique() if t != 0]
    )

    if not attack_types_present:
        print("No attack types found in CSV (all label=0).")
        print("Run veremi_attacks with attack_scenario != 0 (e.g. 21, 22, 24, 28, 36).")
        sys.exit(0)

    # ── Build all 4 classifiers ───────────────────────────────────────────
    classifiers = build_classifiers(args.n_estimators, args.n_neighbors)

    holdout_results = []
    cv_results      = []

    # ── Per-type evaluation ───────────────────────────────────────────────
    for at in attack_types_present:
        type_name = TYPE_NAMES.get(int(at), f"Type {at}")
        df_at = df_attack[df_attack["attack_type"] == at]
        df_combined = balance_dataset(df_legit, df_at)

        if df_combined is None:
            print(f"  [{type_name}] Insufficient data — skipped.")
            continue

        print(f"  {type_name}")
        print(f"    {len(df_at)} attack pairs | {len(df_legit)} legit | "
              f"{len(df_combined)} balanced total")

        if run_holdout:
            print(f"    Holdout (70/30) …", end="  ", flush=True)
            h = evaluate_holdout(df_combined, int(at), classifiers, args.test_split)
            holdout_results.extend(h)
            for r in h:
                print(f"{r['classifier']}:{r['accuracy']:.0f}%", end="  ")
            print()

        if run_cv:
            print(f"    {args.n_folds}-fold CV    …", end="  ", flush=True)
            c = evaluate_cv(df_combined, int(at), classifiers, args.n_folds)
            cv_results.extend(c)
            for r in c:
                print(f"{r['classifier']}:{r['acc_mean']:.0f}%±{r['acc_std']:.1f}", end="  ")
            print()

        print()

    # ── All types combined (if multiple types present) ────────────────────
    if len(attack_types_present) > 1 and len(df_attack) > 0:
        df_combined_all = balance_dataset(df_legit, df_attack.copy())
        if df_combined_all is not None:
            print(f"  ALL TYPES COMBINED")
            print(f"    {len(df_attack)} attack pairs | {len(df_legit)} legit | "
                  f"{len(df_combined_all)} balanced total")

            if run_holdout:
                print(f"    Holdout (70/30) …", end="  ", flush=True)
                h = evaluate_holdout(df_combined_all, -1, classifiers, args.test_split)
                for r in h:
                    r["type_name"] = "ALL TYPES COMBINED"
                holdout_results.extend(h)
                for r in h:
                    print(f"{r['classifier']}:{r['accuracy']:.0f}%", end="  ")
                print()

            if run_cv:
                print(f"    {args.n_folds}-fold CV    …", end="  ", flush=True)
                c = evaluate_cv(df_combined_all, -1, classifiers, args.n_folds)
                for r in c:
                    r["type_name"] = "ALL TYPES COMBINED"
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
        out_csv = "veremi_knn_results.csv"
        rows = []
        for r in holdout_results:
            rows.append({
                "attack_type":   r["attack_type"],
                "type_name":     r["type_name"],
                "classifier":    r["classifier"],
                "n_train":       r["n_train"],
                "n_test":        r["n_test"],
                "tp":            r["tp"],
                "tn":            r["tn"],
                "fp":            r["fp"],
                "fn":            r["fn"],
                "accuracy_pct":  round(r["accuracy"],  3),
                "precision":     round(r["precision"], 3),
                "recall":        round(r["recall"],    3),
                "f1":            round(r["f1"],        3),
            })
        pd.DataFrame(rows).to_csv(out_csv, index=False)
        print(f"\n  Holdout results saved to : {out_csv}")

    # ── Save CV CSV ───────────────────────────────────────────────────────
    if run_cv and cv_results:
        cv_csv = "veremi_cv_results.csv"
        rows = []
        for r in cv_results:
            fold_acc = r.get("acc_per_fold", [])
            fold_f1  = r.get("f1_per_fold",  [])
            row = {
                "attack_type":    r["attack_type"],
                "type_name":      r["type_name"],
                "classifier":     r["classifier"],
                "n_samples":      r["n_samples"],
                "n_folds":        r["n_folds"],
                "acc_mean_pct":   round(r["acc_mean"],    3),
                "acc_std_pct":    round(r["acc_std"],     3),
                "prec_mean":      round(r["prec_mean"],   3),
                "prec_std":       round(r["prec_std"],    3),
                "recall_mean":    round(r["recall_mean"], 3),
                "recall_std":     round(r["recall_std"],  3),
                "f1_mean":        round(r["f1_mean"],     3),
                "f1_std":         round(r["f1_std"],      3),
            }
            for i, (a, f) in enumerate(zip(fold_acc, fold_f1), start=1):
                row[f"fold{i}_acc_pct"] = round(a, 3)
                row[f"fold{i}_f1"]      = round(f, 3)
            rows.append(row)
        pd.DataFrame(rows).to_csv(cv_csv, index=False)
        print(f"  CV results saved to      : {cv_csv}")

    print(f"\n  Tip — merge CSVs from all 5 types to get a full comparison table:")
    print(f"    cat veremi_pairs_type*.csv > veremi_pairs_all.csv")
    print(f"    python3 knn_bagging_detector.py veremi_pairs_all.csv")
    print()


# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
