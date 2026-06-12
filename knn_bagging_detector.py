#!/usr/bin/env python3
"""
knn_bagging_detector.py
-----------------------
Multi-classifier ensemble detector for VeReMi position falsification
attack detection in VANETs.

Based on: Mekonen BK, Bane L, Fite NB (2025)
  "Detection of false position attacks in VANETs through bagging ensemble learning."
  PLoS ONE 20(8): e0328829. https://doi.org/10.1371/journal.pone.0328829

Implements Algorithm 1 from the paper:
  Step 2 — Preprocess_BSM_Data: normalize position/speed, handle missing values
  Step 3 — Feature_Engineering: compute vel_computed, dir_change,
            path_deviation (Distance from Predicted Path), anomalous_pattern
  Step 4 — Train all 4 classifiers from Table 5 with Bagging:
              1. Decision Tree  + Bagging   (Gini criterion, Eq. 1)
              2. Random Forest  + Bagging   (random feature selection, Eq. 2-3)
              3. KNN            + Bagging   (n_neighbors=3, weights='distance', Eq. 4-5)
              4. MLP            + Bagging   (ReLU/Sigmoid activation, Eq. 6-7)
  Step 5 — Detect_Position_Falsification: classify and flag malicious vehicles

Features — 13 total (Section 4.3.1, Algorithm 1 Step 3):
  Base (9):    pos_x1, pos_y1, spd_x1, spd_y1,
               pos_x2, pos_y2, spd_x2, spd_y2, time_interval
  Derived (4): vel_computed, dir_change, path_deviation, anomalous_pattern

Permutation importance (Section 4.3.1, Table 3) uses 9 BASE features only.

Hyperparameter tuning (Section 4.5):
  Grid search: n_neighbors(1-10) × weights(uniform, distance) × n_estimators(5-20)
  Optimal found by paper: n_neighbors=3, weights='distance', n_estimators=10

Evaluation: 70/30 holdout split + 5-fold stratified cross-validation.

Usage:
  python3 knn_bagging_detector.py [veremi_pairs.csv] [options]

Options:
  --test-split          FLOAT  Test fraction for holdout eval (default: 0.30)
  --n-estimators        INT    Bagging ensemble size (default: 10)
  --n-neighbors         INT    KNN k value (default: 3)
  --n-folds             INT    Cross-validation folds (default: 5)
  --cv-only                    Run only cross-validation (skip holdout table)
  --holdout-only               Run only holdout evaluation (skip CV)
  --permutation-importance     Run Section 4.3.1 permutation importance (Table 3)
  --perm-repeats        INT    Repeats for permutation importance (default: 10)
  --grid-search                Run Section 4.5 hyperparameter grid search

Input CSV (from veremi_attacks.cc):
  vehicle_id, attack_type, sim_time_s,
  pos_x1, pos_y1, spd_x1, spd_y1,
  pos_x2, pos_y2, spd_x2, spd_y2,
  time_interval, label

Output:
  Console table matching Mekonen et al. Table 5 format (all 4 classifiers)
  veremi_knn_results.csv   — per-type holdout metrics (accuracy, precision, recall,
                             f1, MCC, AUROC, tdet_ms)
  veremi_cv_results.csv    — 5-fold CV mean ± std metrics

Requirements:
  pip install scikit-learn pandas numpy
  scikit-learn >= 1.2 required
"""

import sys
import argparse
import warnings
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore", category=UserWarning, message=".*Maximum iterations.*")

try:
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.ensemble import BaggingClassifier, RandomForestClassifier
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import (train_test_split, StratifiedKFold,
                                          cross_validate, GridSearchCV)
    from sklearn.inspection import permutation_importance as sk_perm_importance
    from sklearn.metrics import (precision_score, recall_score,
                                 accuracy_score, f1_score,
                                 confusion_matrix, make_scorer,
                                 matthews_corrcoef, roc_auc_score)
    import sklearn
    _sklearn_ok = True
except ImportError:
    _sklearn_ok = False

# ─────────────────────────────────────────────────────────────
# VeReMi attack type labels (Table 2 of paper)
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
# Full 13-feature set for classifier training (Algorithm 1 Step 3)
#
# 9 base features from consecutive BSM pairs (Section 4.3.1, Table 3):
#   pos_x1, pos_y1, spd_x1, spd_y1 — BSM at time t
#   pos_x2, pos_y2, spd_x2, spd_y2 — BSM at time t+1
#   time_interval                   — sendtime_2 - sendtime_1
#
# 4 derived features (Algorithm 1 Step 3):
#   vel_computed    — ΔPosition/ΔTime
#   dir_change      — Directional Change (Heading) between consecutive BSMs
#   path_deviation  — Distance from Predicted Path = |actual_pos2 - predicted_pos2|
#   anomalous_pattern — |Predicted Position - Actual Position| (same as path_deviation)
# ─────────────────────────────────────────────────────────────
FEATURE_COLS = [
    "pos_x1", "pos_y1", "spd_x1", "spd_y1",
    "pos_x2", "pos_y2", "spd_x2", "spd_y2",
    "time_interval",
    "vel_computed",
    "dir_change",
    "path_deviation",
    "anomalous_pattern",
]

# 9 base features only — used for permutation importance (Section 4.3.1, Table 3).
# Paper Table 3 lists exactly these 9; the 4 derived features are not in Table 3.
PERM_FEATURE_COLS = [
    "pos_x1", "pos_y1", "spd_x1", "spd_y1",
    "pos_x2", "pos_y2", "spd_x2", "spd_y2",
    "time_interval",
]

# Classifier display order (matches Mekonen et al. Table 5)
CLF_ORDER = ["DT+Bagging", "RF+Bagging", "KNN+Bagging", "MLP+Bagging"]


# ─────────────────────────────────────────────────────────────
def engineer_features(df):
    """
    Algorithm 1 Step 3 — Feature Engineering (Mekonen et al., PLOS ONE 2025).

    Computes 4 derived features from the 9 base consecutive-BSM-pair columns:

    vel_computed    — ΔPosition / ΔTime (actual positional speed in m/s)
                      Paper: "Velocity = ΔTime / ΔPosition"

    dir_change      — |arctan2(spd_y2, spd_x2) − arctan2(spd_y1, spd_x1)|
                      Angular heading change between consecutive BSMs (radians)
                      Paper: "Directional Change (Heading)"

    path_deviation  — ||(pos_x2, pos_y2) − (pos_x1 + spd_x1·dt, pos_y1 + spd_y1·dt)||
                      Euclidean distance between actual and linearly-predicted position
                      Paper: "Distance from Predicted Path = |Pospredicted − Posactual|"

    anomalous_pattern — Same as path_deviation.
                        Paper: "Anomalous Pattern = |Predicted Position − Actual Position|"
    """
    df = df.copy()
    ti = df["time_interval"].clip(lower=1e-6)

    # vel_computed: Euclidean displacement / time interval
    dx = df["pos_x2"] - df["pos_x1"]
    dy = df["pos_y2"] - df["pos_y1"]
    df["vel_computed"] = np.sqrt(dx**2 + dy**2) / ti

    # dir_change: absolute angular heading change between consecutive BSMs
    df["dir_change"] = np.abs(
        np.arctan2(df["spd_y2"], df["spd_x2"]) -
        np.arctan2(df["spd_y1"], df["spd_x1"])
    )

    # path_deviation: distance between actual pos2 and linearly-predicted pos2
    pred_x = df["pos_x1"] + df["spd_x1"] * ti
    pred_y = df["pos_y1"] + df["spd_y1"] * ti
    df["path_deviation"] = np.sqrt(
        (df["pos_x2"] - pred_x)**2 + (df["pos_y2"] - pred_y)**2
    )

    # anomalous_pattern = path_deviation (paper defines both identically)
    df["anomalous_pattern"] = df["path_deviation"]

    return df


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
    Algorithm 1 Step 4: Train_Machine_Learning_Models (Table 5).

    Parameters match Mekonen et al. Section 4.5 optimal hyperparameters:
        DT:   DecisionTreeClassifier(criterion='gini')     — Eq. 1
        RF:   RandomForestClassifier(n_estimators=10)      — Eq. 2-3
        KNN:  KNeighborsClassifier(n_neighbors=3, weights='distance')  — Eq. 4-5
        MLP:  MLPClassifier(hidden_layer_sizes=(100,))     — Eq. 6-7
    """
    dt_bag = _make_bagging(
        DecisionTreeClassifier(criterion='gini', random_state=42),
        n_estimators
    )
    rf_bag = _make_bagging(
        RandomForestClassifier(n_estimators=10, random_state=42),
        n_estimators
    )
    knn_bag = _make_bagging(
        KNeighborsClassifier(n_neighbors=n_neighbors, weights="distance"),
        n_estimators
    )
    mlp_bag = _make_bagging(
        MLPClassifier(hidden_layer_sizes=(100,), max_iter=2000, random_state=42),
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
    Create a balanced dataset: up to 3× as many legit rows as attack rows.
    Returns None if insufficient data.
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
    Matches the train/test split in Mekonen et al. (Section 4.5, Fig 6-13).
    Metrics: Accuracy, Precision, Recall, F1, MCC, AUROC, Tdet.
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

    # Tdet: time of first TP minus time of first attack pair (ms)
    if "sim_time_s" in df_combined.columns:
        sim_times = df_combined["sim_time_s"].values
        _, sim_times_test = train_test_split(
            sim_times, test_size=test_split, random_state=42, stratify=y
        )
        _attack_mask = (y_test == 1)
        _t_attack_start = (float(sim_times_test[_attack_mask].min())
                           if _attack_mask.any() else -1.0)
    else:
        sim_times_test  = None
        _t_attack_start = -1.0

    results = []
    for clf_name, clf in classifiers.items():
        try:
            clf.fit(X_train, y_train)
        except Exception as e:
            print(f"\n    [{clf_name}] training failed: {e} — skipped")
            continue
        y_pred = clf.predict(X_test)

        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        # MCC with epsilon-stabilised denominator (avoids division by zero)
        _tp, _tn, _fp, _fn = float(tp), float(tn), float(fp), float(fn)
        _eps = 1e-9
        _d   = ((_tp+_fp+_eps)*(_tp+_fn+_eps)*(_tn+_fp+_eps)*(_tn+_fn+_eps))**0.5
        mcc  = (_tp*_tn - _fp*_fn) / _d

        # AUROC
        try:
            y_prob = clf.predict_proba(X_test)[:, 1]
            auroc  = float(roc_auc_score(y_test, y_prob))
        except Exception:
            auroc = 0.5

        # Tdet
        if sim_times_test is not None and _t_attack_start >= 0.0:
            tp_mask = (y_test == 1) & (y_pred == 1)
            tdet_ms = ((float(sim_times_test[tp_mask].min()) - _t_attack_start) * 1000.0
                       if tp_mask.any() else -1.0)
        else:
            tdet_ms = -1.0

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
            "mcc":         mcc,
            "auroc":       auroc,
            "tdet_ms":     tdet_ms,
        })
    return results


# ─────────────────────────────────────────────────────────────
def evaluate_cv(df_combined, attack_type, classifiers, n_folds):
    """
    n-fold stratified cross-validation for all 4 classifiers.
    Matches Mekonen et al. Figures 6-13 (per-fold accuracy and F1).
    Adds MCC and AUROC per fold.
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
        print(f"  [Type {attack_type}] Too few samples ({len(X)}) for {n_folds}-fold CV.")
        return []

    cv = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)

    scoring = {
        "accuracy":  make_scorer(accuracy_score),
        "precision": make_scorer(precision_score, zero_division=0),
        "recall":    make_scorer(recall_score,    zero_division=0),
        "f1":        make_scorer(f1_score,        zero_division=0),
        "mcc":       make_scorer(matthews_corrcoef),
        "auroc":     "roc_auc",
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
        acc_arr   = scores["test_accuracy"]  * 100.0
        prec_arr  = scores["test_precision"]
        rec_arr   = scores["test_recall"]
        f1_arr    = scores["test_f1"]
        mcc_arr   = scores["test_mcc"]
        auroc_arr = scores["test_auroc"]

        results.append({
            "attack_type":    attack_type,
            "type_name":      TYPE_NAMES.get(attack_type, f"Type {attack_type}"),
            "classifier":     clf_name,
            "n_samples":      int(len(X)),
            "n_folds":        n_folds,
            "acc_mean":       float(acc_arr.mean()),
            "acc_std":        float(acc_arr.std()),
            "prec_mean":      float(prec_arr.mean()),
            "prec_std":       float(prec_arr.std()),
            "recall_mean":    float(rec_arr.mean()),
            "recall_std":     float(rec_arr.std()),
            "f1_mean":        float(f1_arr.mean()),
            "f1_std":         float(f1_arr.std()),
            "mcc_mean":       float(mcc_arr.mean()),
            "mcc_std":        float(mcc_arr.std()),
            "auroc_mean":     float(auroc_arr.mean()),
            "auroc_std":      float(auroc_arr.std()),
            "acc_per_fold":   acc_arr.tolist(),
            "f1_per_fold":    f1_arr.tolist(),
            "mcc_per_fold":   mcc_arr.tolist(),
            "auroc_per_fold": auroc_arr.tolist(),
        })
    return results


# ─────────────────────────────────────────────────────────────
def run_permutation_importance(df_combined, attack_type, n_estimators, n_neighbors,
                                n_repeats=10, test_split=0.30):
    """
    Section 4.3.1 — Permutation importance (Table 3 of Mekonen et al.).

    Uses the 9 BASE features only (PERM_FEATURE_COLS), matching Table 3 exactly.
    A fresh KNN+Bagging pipeline trained on these 9 features is used.
    Permutation importance = decrease in accuracy when feature is shuffled.
    10 repeats (per paper Section 4.3.1).
    """
    X = df_combined[PERM_FEATURE_COLS].values
    y = df_combined["label"].values

    if len(np.unique(y)) < 2:
        return None

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_split, random_state=42, stratify=y
    )

    knn_pipe_9 = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", _make_bagging(
            KNeighborsClassifier(n_neighbors=n_neighbors, weights="distance"),
            n_estimators,
        )),
    ])
    knn_pipe_9.fit(X_train, y_train)

    result = sk_perm_importance(
        knn_pipe_9, X_test, y_test,
        n_repeats=n_repeats, random_state=42, scoring='accuracy',
    )

    return {
        "attack_type":     attack_type,
        "type_name":       TYPE_NAMES.get(attack_type, f"Type {attack_type}"),
        "feature_names":   PERM_FEATURE_COLS,
        "importance_mean": result.importances_mean.tolist(),
        "importance_std":  result.importances_std.tolist(),
    }


# ─────────────────────────────────────────────────────────────
def run_grid_search(df_combined, attack_type, n_folds=5):
    """
    Section 4.5 — Hyperparameter grid search for KNN+Bagging.

    Grid (identical to paper):
      n_neighbors  : 1–10
      weights      : 'uniform', 'distance'
      n_estimators : 5, 10, 15, 20

    Paper optimum: n_neighbors=3, weights='distance', n_estimators=10.
    """
    X = df_combined[FEATURE_COLS].values
    y = df_combined["label"].values

    if len(np.unique(y)) < 2:
        return None

    sk_major, sk_minor = (int(x) for x in sklearn.__version__.split(".")[:2])
    base_knn = KNeighborsClassifier()
    if (sk_major, sk_minor) >= (1, 2):
        bag     = BaggingClassifier(estimator=base_knn, random_state=42)
        est_key = "clf__estimator"
    else:
        bag     = BaggingClassifier(base_estimator=base_knn, random_state=42)
        est_key = "clf__base_estimator"

    pipeline = Pipeline([("scaler", StandardScaler()), ("clf", bag)])

    param_grid = {
        f"{est_key}__n_neighbors": list(range(1, 11)),
        f"{est_key}__weights":     ["uniform", "distance"],
        "clf__n_estimators":       [5, 10, 15, 20],
    }

    cv = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)
    gs = GridSearchCV(
        pipeline, param_grid, cv=cv,
        scoring=["accuracy", "f1"], refit="accuracy",
        n_jobs=1, verbose=0,
    )
    gs.fit(X, y)

    best = {}
    for k, v in gs.best_params_.items():
        short_k = (k.replace(f"{est_key}__", "knn__")
                    .replace("clf__n_estimators", "bag__n_estimators"))
        best[short_k] = v

    return {
        "attack_type":   attack_type,
        "type_name":     TYPE_NAMES.get(attack_type, f"Type {attack_type}"),
        "best_params":   best,
        "best_accuracy": float(gs.best_score_ * 100.0),
    }


# ─────────────────────────────────────────────────────────────
def print_holdout_table(results, n_estimators, n_neighbors):
    """Print holdout results in Mekonen et al. Table 5 format."""
    attack_types = sorted({r["attack_type"] for r in results if r["attack_type"] != -1})

    W = 120
    print(f"\n{'='*W}")
    print(f"  Table 5 — Holdout Evaluation  (70% train / 30% test)")
    print(f"  n_estimators={n_estimators}   KNN k={n_neighbors} (weights='distance')")
    print(f"  Reference: Mekonen et al., PLOS ONE 2025")
    print(f"{'='*W}")

    hdr = (f"  {'Attack Type':<26} {'Classifier':<16}"
           f"{'Acc%':>7}{'Prec':>8}{'Recall':>8}{'F1':>8}"
           f"{'MCC':>8}{'AUROC':>8}{'Tdet(ms)':>10}"
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
            print(f"  {'':26} {clf_name:<16}"
                  f"{r['accuracy']:>7.1f}"
                  f"{r['precision']:>8.3f}"
                  f"{r['recall']:>8.3f}"
                  f"{r['f1']:>8.3f}"
                  f"{r.get('mcc',   0.0):>8.3f}"
                  f"{r.get('auroc', 0.5):>8.3f}"
                  f"{r.get('tdet_ms', -1.0):>10.1f}"
                  f"{r['tp']:>6}"
                  f"{r['fp']:>6}"
                  f"{r['fn']:>6}"
                  f"{r['n_test']:>8}")

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
                  f"{r.get('mcc',   0.0):>8.3f}"
                  f"{r.get('auroc', 0.5):>8.3f}"
                  f"{r.get('tdet_ms', -1.0):>10.1f}"
                  f"{r['tp']:>6}"
                  f"{r['fp']:>6}"
                  f"{r['fn']:>6}"
                  f"{r['n_test']:>8}")

    print(f"\n{'='*W}")


# ─────────────────────────────────────────────────────────────
def print_cv_table(cv_results, n_folds):
    """Print n-fold CV mean ± std table including MCC and AUROC."""
    attack_types = sorted({r["attack_type"] for r in cv_results if r["attack_type"] != -1})

    W = 120
    print(f"\n{'='*W}")
    print(f"  {n_folds}-Fold Stratified Cross-Validation Results")
    print(f"  Reference: Mekonen et al., PLOS ONE 2025 — Figures 6–13")
    print(f"{'='*W}")

    col_hdr = (f"  {'Classifier':<16}"
               f"{'Acc% mean±std':>20}"
               f"{'Prec mean±std':>18}"
               f"{'Recall mean±std':>20}"
               f"{'F1 mean±std':>16}"
               f"{'MCC mean±std':>16}"
               f"{'AUROC mean±std':>18}")

    for at in attack_types:
        type_name = TYPE_NAMES.get(at, f"Type {at}")
        print(f"\n  ── {type_name} ──")
        print(col_hdr)
        print(f"  {'-'*(W-2)}")
        for clf_name in CLF_ORDER:
            r = next((x for x in cv_results
                      if x["attack_type"] == at and x["classifier"] == clf_name), None)
            if r is None:
                continue
            print(f"  {clf_name:<16}"
                  f"  {r['acc_mean']:>6.1f} ± {r['acc_std']:>4.1f}    "
                  f"  {r['prec_mean']:>5.3f} ± {r['prec_std']:>5.3f}  "
                  f"  {r['recall_mean']:>5.3f} ± {r['recall_std']:>5.3f}    "
                  f"  {r['f1_mean']:>5.3f} ± {r['f1_std']:>5.3f}  "
                  f"  {r['mcc_mean']:>5.3f} ± {r['mcc_std']:>5.3f}  "
                  f"  {r['auroc_mean']:>5.3f} ± {r['auroc_std']:>5.3f}")

        print(f"\n  Per-fold accuracy (%):")
        for clf_name in CLF_ORDER:
            r = next((x for x in cv_results
                      if x["attack_type"] == at and x["classifier"] == clf_name), None)
            if r is None:
                continue
            fold_str = "  ".join(f"F{i+1}:{v:.1f}" for i, v in enumerate(r["acc_per_fold"]))
            print(f"    {clf_name:<14} {fold_str}")

        print(f"\n  Per-fold MCC:")
        for clf_name in CLF_ORDER:
            r = next((x for x in cv_results
                      if x["attack_type"] == at and x["classifier"] == clf_name), None)
            if r is None:
                continue
            fold_str = "  ".join(f"F{i+1}:{v:.3f}" for i, v in enumerate(r["mcc_per_fold"]))
            print(f"    {clf_name:<14} {fold_str}")

    combined_cv = [r for r in cv_results if r["attack_type"] == -1]
    if combined_cv:
        print(f"\n  ── ALL TYPES COMBINED ──")
        print(col_hdr)
        print(f"  {'-'*(W-2)}")
        for clf_name in CLF_ORDER:
            r = next((x for x in combined_cv if x["classifier"] == clf_name), None)
            if r is None:
                continue
            print(f"  {clf_name:<16}"
                  f"  {r['acc_mean']:>6.1f} ± {r['acc_std']:>4.1f}    "
                  f"  {r['prec_mean']:>5.3f} ± {r['prec_std']:>5.3f}  "
                  f"  {r['recall_mean']:>5.3f} ± {r['recall_std']:>5.3f}    "
                  f"  {r['f1_mean']:>5.3f} ± {r['f1_std']:>5.3f}  "
                  f"  {r['mcc_mean']:>5.3f} ± {r['mcc_std']:>5.3f}  "
                  f"  {r['auroc_mean']:>5.3f} ± {r['auroc_std']:>5.3f}")

    print(f"\n{'='*W}")


# ─────────────────────────────────────────────────────────────
def print_permutation_table(perm_results):
    """Print permutation importance in Mekonen et al. Table 3 format."""
    W = 108
    print(f"\n{'='*W}")
    print(f"  Table 3 — Normalized Feature Importance (KNN+Bagging, 9 base features)")
    print(f"  Section 4.3.1 — Mekonen et al., PLOS ONE 2025 (10 repeats, accuracy scoring)")
    print(f"{'='*W}")
    for r in perm_results:
        if r is None:
            continue
        print(f"\n  ── {r['type_name']} ──")
        print(f"  {'Feature':<12} {'Importance Mean':>18} {'Importance Std':>16}")
        print(f"  {'-'*(W-2)}")
        for feat, mean, std in zip(r["feature_names"], r["importance_mean"], r["importance_std"]):
            print(f"  {feat:<12} {mean:>18.4f} {std:>16.4f}")
    print(f"\n{'='*W}")


# ─────────────────────────────────────────────────────────────
def print_grid_search_results(gs_results):
    """Print grid search results (Section 4.5 of paper)."""
    W = 108
    print(f"\n{'='*W}")
    print(f"  Section 4.5 — Hyperparameter Grid Search (KNN+Bagging)")
    print(f"  Grid: n_neighbors(1-10) × weights(uniform,distance) × n_estimators(5,10,15,20)")
    print(f"  Paper optimum: knn__n_neighbors=3, knn__weights='distance', bag__n_estimators=10")
    print(f"{'='*W}")
    print(f"  {'Attack Type':<35} {'Best Params':<45} {'Best Acc%':>9}")
    print(f"  {'-'*(W-2)}")
    for r in gs_results:
        if r is None:
            continue
        params_str = "  ".join(f"{k}={v}" for k, v in sorted(r["best_params"].items()))
        print(f"  {r['type_name']:<35} {params_str:<45} {r['best_accuracy']:>9.2f}")
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
            "13 features (9 base + 4 derived, Algorithm 1 Step 3)\n"
            "Classifiers: DT+Bagging, RF+Bagging, KNN+Bagging, MLP+Bagging\n"
            "Evaluation: 70/30 holdout + 5-fold stratified CV + permutation importance"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "csv_file", nargs="?", default="veremi_pairs.csv",
        help="Consecutive BSM pair CSV from veremi_attacks.cc (default: veremi_pairs.csv)"
    )
    parser.add_argument("--test-split", type=float, default=0.30,
                        help="Holdout test fraction (default: 0.30)")
    parser.add_argument("--n-estimators", type=int, default=10,
                        help="Bagging ensemble size (default: 10)")
    parser.add_argument("--n-neighbors", type=int, default=3,
                        help="KNN k (default: 3, paper optimum)")
    parser.add_argument("--n-folds", type=int, default=5,
                        help="Cross-validation folds (default: 5)")
    parser.add_argument("--cv-only", action="store_true",
                        help="Run only cross-validation, skip holdout table")
    parser.add_argument("--holdout-only", action="store_true",
                        help="Run only holdout evaluation, skip CV")
    parser.add_argument("--permutation-importance", action="store_true",
                        help="Run Section 4.3.1 permutation importance analysis (Table 3)")
    parser.add_argument("--perm-repeats", type=int, default=10,
                        help="Repeats for permutation importance (default: 10)")
    parser.add_argument("--grid-search", action="store_true",
                        help="Run Section 4.5 hyperparameter grid search")
    args = parser.parse_args()

    run_cv      = not args.holdout_only
    run_holdout = not args.cv_only

    # ── Load CSV ──────────────────────────────────────────────────────────
    try:
        df = pd.read_csv(args.csv_file)
    except FileNotFoundError:
        print(f"ERROR: '{args.csv_file}' not found.")
        print("  Generate it with:")
        print("    ./waf --run \"scratch/veremi_attacks --simTime=60 "
              "--N_Vehicles=6 --N_RSUs=1 --attack_scenario=21\"")
        print("  Or download from: https://doi.org/10.6084/m9.figshare.29322179")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR reading '{args.csv_file}': {e}")
        sys.exit(1)

    if df.empty:
        print(f"ERROR: '{args.csv_file}' is empty.")
        sys.exit(1)

    # Algorithm 1 Step 3: compute all 4 derived features
    df = engineer_features(df)

    print(f"\n{'='*72}")
    print(f"  VeReMi Multi-Classifier Detector  —  Mekonen et al. PLOS ONE 2025")
    print(f"  Algorithm 1: 13 features (9 base + vel_computed, dir_change,")
    print(f"               path_deviation, anomalous_pattern)")
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
    required_base = PERM_FEATURE_COLS + ["label", "attack_type"]
    missing = [c for c in required_base if c not in df.columns]
    if missing:
        print(f"ERROR: Missing columns in CSV: {missing}")
        sys.exit(1)

    # ── Separate legit and attack subsets ─────────────────────────────────
    df_legit  = df[df["label"] == 0].copy()
    df_attack = df[df["label"] == 1].copy()

    attack_types_present = sorted([t for t in df["attack_type"].unique() if t != 0])

    if not attack_types_present:
        print("No attack types found in CSV (all label=0).")
        print("Run veremi_attacks with attack_scenario != 0 (e.g. 21, 22, 24, 28, 36).")
        sys.exit(0)

    # ── Build all 4 classifiers ───────────────────────────────────────────
    classifiers = build_classifiers(args.n_estimators, args.n_neighbors)

    holdout_results = []
    cv_results      = []
    perm_results    = []
    gs_results      = []

    # ── Per-type evaluation ───────────────────────────────────────────────
    for at in attack_types_present:
        type_name   = TYPE_NAMES.get(int(at), f"Type {at}")
        df_at       = df_attack[df_attack["attack_type"] == at]
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
                print(f"{r['classifier']}:{r['accuracy']:.0f}%(MCC={r['mcc']:.3f})", end="  ")
            print()

        if run_cv:
            print(f"    {args.n_folds}-fold CV    …", end="  ", flush=True)
            c = evaluate_cv(df_combined, int(at), classifiers, args.n_folds)
            cv_results.extend(c)
            for r in c:
                print(f"{r['classifier']}:{r['acc_mean']:.0f}%(MCC={r['mcc_mean']:.3f})", end="  ")
            print()

        if args.permutation_importance:
            print(f"    Permutation importance …", end="  ", flush=True)
            r = run_permutation_importance(df_combined, int(at),
                                           args.n_estimators, args.n_neighbors,
                                           args.perm_repeats, args.test_split)
            if r is not None:
                perm_results.append(r)
            print("done")

        if args.grid_search:
            print(f"    Grid search …", end="  ", flush=True)
            r = run_grid_search(df_combined, int(at), args.n_folds)
            if r is not None:
                gs_results.append(r)
            print("done")

        print()

    # ── All types combined ────────────────────────────────────────────────
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
                    print(f"{r['classifier']}:{r['acc_mean']:.0f}%", end="  ")
                print()

            print()

    # ── Print tables ──────────────────────────────────────────────────────
    if run_holdout and holdout_results:
        print_holdout_table(holdout_results, args.n_estimators, args.n_neighbors)
    if run_cv and cv_results:
        print_cv_table(cv_results, args.n_folds)
    if perm_results:
        print_permutation_table(perm_results)
    if gs_results:
        print_grid_search_results(gs_results)

    # ── Save holdout CSV ──────────────────────────────────────────────────
    if run_holdout and holdout_results:
        out_csv = "veremi_knn_results.csv"
        cols = ["attack_type", "type_name", "classifier",
                "n_train", "n_test", "tp", "tn", "fp", "fn",
                "accuracy", "precision", "recall", "f1", "mcc", "auroc", "tdet_ms"]
        pd.DataFrame(holdout_results)[cols].to_csv(out_csv, index=False)
        print(f"\n  Holdout results saved to : {out_csv}")

    # ── Save CV CSV ───────────────────────────────────────────────────────
    if run_cv and cv_results:
        cv_csv = "veremi_cv_results.csv"
        cols = ["attack_type", "type_name", "classifier", "n_samples", "n_folds",
                "acc_mean", "acc_std", "prec_mean", "prec_std",
                "recall_mean", "recall_std", "f1_mean", "f1_std",
                "mcc_mean", "mcc_std", "auroc_mean", "auroc_std"]
        pd.DataFrame(cv_results)[cols].to_csv(cv_csv, index=False)
        print(f"  CV results saved to      : {cv_csv}")

    # ── Save permutation importance ───────────────────────────────────────
    if perm_results:
        rows = []
        for r in perm_results:
            if r is None:
                continue
            for feat, mean, std in zip(r["feature_names"],
                                        r["importance_mean"],
                                        r["importance_std"]):
                rows.append({"attack_type": r["attack_type"], "type_name": r["type_name"],
                              "feature": feat, "importance_mean": mean, "importance_std": std})
        pd.DataFrame(rows).to_csv("veremi_permutation_importance.csv", index=False)
        print(f"  Permutation importance saved to: veremi_permutation_importance.csv")

    # ── Save grid search ──────────────────────────────────────────────────
    if gs_results:
        rows = []
        for r in gs_results:
            if r is None:
                continue
            row = {"attack_type": r["attack_type"], "type_name": r["type_name"],
                   "best_accuracy_pct": r["best_accuracy"]}
            row.update(r["best_params"])
            rows.append(row)
        pd.DataFrame(rows).to_csv("veremi_grid_search.csv", index=False)
        print(f"  Grid search results saved to: veremi_grid_search.csv")

    print(f"\n  Tip — run with all attack types in one CSV for combined Table 5:")
    print(f"    cat veremi_pairs_type*.csv > veremi_pairs_all.csv")
    print(f"    python3 knn_bagging_detector.py veremi_pairs_all.csv "
          f"--permutation-importance --grid-search")
    print()


if __name__ == "__main__":
    main()
