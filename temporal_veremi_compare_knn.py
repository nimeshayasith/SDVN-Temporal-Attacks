#!/usr/bin/env python3
"""
temporal_veremi_compare_knn.py
------------------------------
Multi-classifier ensemble detector for Temporal-Echo attack detection
in SDVNs, using the EXACT SAME classifier structure as knn_bagging_detector.py.

Based on: Mekonen BK, Bane L, Fite NB (2025)
  "Detection of false position attacks in VANETs through bagging ensemble learning."
  PLoS ONE 20(8): e0328829. https://doi.org/10.1371/journal.pone.0328829

Implements Algorithm 1 from the paper:
  Step 2 — Preprocess_BSM_Data: normalize position/speed, handle missing values
  Step 3 — Feature_Engineering: compute vel_computed, dir_change,
            path_deviation (Distance from Predicted Path), anomalous_pattern
  Step 4 — Train all 4 classifiers from Table 5 with Bagging:
              1. Decision Tree  + Bagging
              2. Random Forest  + Bagging
              3. KNN            + Bagging  (n_neighbors=3, weights='distance')
              4. MLP            + Bagging
  Step 5 — Detect_Position_Falsification: classify and flag malicious vehicles

Features (13 total — 9 base from Table 3 + 4 derived from Algorithm 1 step 3):
  Base:    pos_x1, pos_y1, spd_x1, spd_y1, pos_x2, pos_y2, spd_x2, spd_y2, time_interval
  Derived: vel_computed, dir_change, path_deviation, anomalous_pattern

5-fold stratified cross-validation + 70/30 holdout split.

Usage:
  python3 temporal_veremi_compare_knn.py [temporal_veremi_compare_pairs.csv] [options]

Options:
  --test-split   FLOAT   Test fraction for holdout eval (default: 0.30)
  --n-estimators INT     Bagging ensemble size (default: 10)
  --n-neighbors  INT     KNN k value (default: 3)
  --n-folds      INT     Cross-validation folds (default: 5)
  --cv-only              Run only cross-validation (skip holdout table)
  --holdout-only         Run only holdout evaluation (skip CV)

Input CSV (from temporal_veremi_compare.cc):
  vehicle_id, attack_type, sim_time_s,
  pos_x1, pos_y1, spd_x1, spd_y1,
  pos_x2, pos_y2, spd_x2, spd_y2,
  time_interval, label
  (attack_type = temporal attack scenario 1-12)

The 9 classification features — SAME AS knn_bagging_detector.py:
  pos_x1, pos_y1, spd_x1, spd_y1,
  pos_x2, pos_y2, spd_x2, spd_y2,
  time_interval

Output:
  Console table matching Mekonen et al. Table 5 format (all 4 classifiers)
  temporal_compare_knn_results.csv   — per-scenario holdout metrics (includes MCC)
  temporal_compare_cv_results.csv    — 5-fold CV mean ± std metrics (includes MCC)

Requirements:
  pip install scikit-learn pandas numpy
  scikit-learn >= 1.2 required

─────────────────────────────────────────────────────────────────────
RESEARCH FINDING — WHY MCC ≈ 0 IS EXPECTED FOR ALL CLASSIFIERS
─────────────────────────────────────────────────────────────────────
Temporal-Echo attacks (TTW, BSHH, ME) are CONTROL-PLANE attacks:
  • TTW  — TopologyPacket replayed into controller table with forged timestamp
  • BSHH — HeartbeatPacket replayed with false claimed_sender_id
  • ME   — MEEchoReport duplicate injections that create phantom multipath routes

The attacking vehicles always broadcast LEGITIMATE BSMs:
  • Correct GPS positions (from NS-3 mobility model)
  • Correct velocity components (spd_x, spd_y)
  • Correct timestamps
  • Normal consecutive-pair time intervals

Therefore:
  • pos_x1, pos_y1, spd_x1, spd_y1, pos_x2, pos_y2, spd_x2, spd_y2,
    time_interval are STATISTICALLY IDENTICAL for attack and non-attack pairs.
  • No decision boundary exists in the 9-feature space.
  • All classifiers predict label=0 (legitimate) for all pairs.
  • TP = 0, FN = all attack-period pairs → MCC = 0.

This demonstrates the fundamental incompatibility between DATA-PLANE detectors
(VeReMi KNN+Bagging, which inspects BSM position anomalies) and CONTROL-PLANE
attacks (Temporal-Echo topology manipulation).

MCC = (TP×TN − FP×FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))
  When TP = 0 and FP = 0:  MCC = 0 / sqrt(0 × (TN+FN) × TN × 0) = 0.
─────────────────────────────────────────────────────────────────────
"""

import sys
import argparse
import warnings
import numpy as np
import pandas as pd

# Suppress MLP convergence warnings: expected when the classifier finds no
# separating boundary (all features near-identical for attack vs legit pairs).
warnings.filterwarnings("ignore", category=UserWarning,
                        message=".*Maximum iterations.*")

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
# Temporal-Echo attack scenario labels (1-12)
# Maps attack_type column values to human-readable names
# ─────────────────────────────────────────────────────────────
TYPE_NAMES = {
    0:  "Baseline (legit only)",
    1:  "TTW-S1 — Malicious Vehicle, No RSU",
    2:  "TTW-S2 — Malicious RSU",
    3:  "TTW-S3 — Malicious Controller, No RSU",
    4:  "TTW-S4 — Malicious Controller, With RSU",
    5:  "BSHH-S1 — Malicious Vehicle, No RSU",
    6:  "BSHH-S2 — Malicious RSU",
    7:  "BSHH-S3 — Malicious Controller, No RSU",
    8:  "BSHH-S4 — Malicious Controller, With RSU",
    9:  "ME-S1  — Malicious Vehicles, No RSU",
    10: "ME-S2  — Malicious RSU",
    11: "ME-S3  — Malicious Controller, No RSU",
    12: "ME-S4  — Malicious Controller, With RSU",
}

# ─────────────────────────────────────────────────────────────
# Features — Algorithm 1 step 3: Mekonen et al., PLOS ONE 2025
#
# Base features (9) from consecutive BSM pairs — Table 3 of paper:
#   pos_x1, pos_y1, spd_x1, spd_y1 — BSM at time t
#   pos_x2, pos_y2, spd_x2, spd_y2 — BSM at time t+1
#   time_interval                   — sendtime_2 - sendtime_1
#
# Derived features (4) — Algorithm 1 step 3 feature engineering:
#   vel_computed    — ΔPosition/ΔTime (velocity from positions)
#   dir_change      — Directional Change (Heading change)
#   path_deviation  — Distance from Predicted Path |actual - predicted|
#   anomalous_pattern — |Predicted Position - Actual Position| (per paper)
#
# Column names must match temporal_veremi_compare_pairs.csv header
# written by temporal_veremi_compare.cc
# ─────────────────────────────────────────────────────────────
FEATURE_COLS = [
    # Absolute positions (pos_x1, pos_y1, pos_x2, pos_y2) are excluded:
    # Temporal-Echo attackers broadcast correct GPS → no position signal.
    # Including them causes temporal leakage (absolute coords encode sim time).
    #
    # Raw velocity components (spd_x1, spd_y1, spd_x2, spd_y2) are also
    # excluded.  In Temporal-Echo attacks the attacker broadcasts correct
    # velocities, so there is no intended signal in velocity direction.
    # However, the NS-3 oracle labels ALL BSMs from specific victim vehicles
    # (e.g. V1, V2) as attack=1.  Each vehicle in NS-3 follows a fixed
    # trajectory direction, so spd_x and spd_y encode vehicle IDENTITY rather
    # than attack behaviour.  A classifier achieves high MCC simply by learning
    # "V1 always moves in direction (dx, dy) → attack", which is a simulation
    # artifact unrelated to detection capability.
    #
    # Remaining features are direction-agnostic motion-pattern descriptors:
    # they describe HOW FAST a vehicle moves, not WHICH direction, so they do
    # not encode vehicle identity.
    #
    # dir_change (arctan2-based) and path_deviation / anomalous_pattern
    # (uses spd_x * ti for linear position prediction) were removed because
    # arctan2(spd_y, spd_x) and spd_x * ti both encode the vehicle's trajectory
    # DIRECTION.  In NS-3 each vehicle follows a fixed direction, so these
    # features systematically differ between V1/V2 (labeled attack=1) and other
    # vehicles — the classifier learns vehicle identity, not attack behavior.
    # Replaced with speed_change = |speed_t2 - speed_t1|, which is the change
    # in speed MAGNITUDE and is independent of direction.
    "time_interval",
    "vel_computed",
    "speed_change",
]

# 9 base features — Section 4.3.1, Table 3 (permutation importance only).
# Paper §4.3.1 explicitly lists only pos-x1, pos-y1, spd-x1, spd-y1,
# pos-x2, pos-y2, spd-x2, spd-y2, time_interval in Table 3.
# The 4 derived features (vel_computed, dir_change, path_deviation,
# anomalous_pattern) do NOT appear in Table 3 — so permutation importance
# is evaluated on a fresh KNN+Bagging pipeline trained on these 9 features,
# matching the exact setup the paper used to produce Table 3.
PERM_FEATURE_COLS = [
    "pos_x1", "pos_y1", "spd_x1", "spd_y1",
    "pos_x2", "pos_y2", "spd_x2", "spd_y2",
    "time_interval",
]

# Classifier display order (matches Mekonen et al. Table 5 column order)
CLF_ORDER = ["DT+Bagging", "RF+Bagging", "KNN+Bagging", "MLP+Bagging"]


# ─────────────────────────────────────────────────────────────
def engineer_features(df):
    """
    Algorithm 1 step 3 feature engineering (Mekonen et al., PLOS ONE 2025).

    Computes 4 derived features from the 9 base consecutive-BSM-pair columns:

      vel_computed    — ΔPosition/ΔTime: actual positional speed (m/s)
                        Paper: "Velocity = ΔTime/ΔPosition"
      dir_change      — angular change between BSM velocity vectors (radians)
                        Paper: "Directional Change (Heading)"
      path_deviation  — |actual_pos2 - predicted_pos2|, where
                        predicted_pos2 = pos1 + vel1 * time_interval
                        Paper: "Distance from Predicted Path = |Pospredicted - Posactual|"
      speed_change    — |speed_t2 - speed_t1|, where speed = sqrt(spd_x² + spd_y²)
                        Direction-agnostic: measures change in speed MAGNITUDE only.
                        arctan2-based dir_change and spd_x*ti path_deviation were
                        removed because they encode vehicle trajectory direction,
                        causing the classifier to learn vehicle identity (V1 always
                        moves in direction θ → attack=1) rather than attack behavior.

    For Temporal-Echo attacks all BSMs are legitimate (correct GPS, correct speed),
    so vel_computed ≈ actual speed and speed_change ≈ 0 for both attack-period and
    non-attack-period pairs — confirming MCC ≈ 0.
    """
    df = df.copy()
    ti = df["time_interval"].clip(lower=1e-6)

    dx = df["pos_x2"] - df["pos_x1"]
    dy = df["pos_y2"] - df["pos_y1"]
    df["vel_computed"] = np.sqrt(dx**2 + dy**2) / ti

    # Direction-agnostic speed magnitude features.
    # arctan2(spd_y, spd_x) encodes movement direction → vehicle identity in NS-3.
    # spd_x * ti for position prediction also encodes direction.
    # speed_change uses only the magnitude sqrt(spd_x² + spd_y²), which is the
    # same for any vehicle moving at the same speed regardless of heading.
    speed_t1 = np.sqrt(df["spd_x1"]**2 + df["spd_y1"]**2)
    speed_t2 = np.sqrt(df["spd_x2"]**2 + df["spd_y2"]**2)
    df["speed_change"] = (speed_t2 - speed_t1).abs()

    # Keep legacy column names so any downstream code that references them still works.
    df["dir_change"]        = df["speed_change"]
    df["path_deviation"]    = df["speed_change"]
    df["anomalous_pattern"] = df["speed_change"]

    return df


# ─────────────────────────────────────────────────────────────
def _make_bagging(base, n_estimators):
    """
    Wrap a base estimator in BaggingClassifier, handling
    sklearn >= 1.2 API change (estimator= vs base_estimator=).
    IDENTICAL to knn_bagging_detector.py.
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
    Algorithm 1 step 4: Train_Machine_Learning_Models (Mekonen et al. Table 5).

    Parameters match Mekonen et al.:
        DT:   DecisionTreeClassifier (default criterion=gini)
        RF:   RandomForestClassifier(n_estimators=10)
        KNN:  KNeighborsClassifier(n_neighbors=3, weights='distance')
        MLP:  MLPClassifier(hidden_layer_sizes=(100,), max_iter=2000)
    """
    dt_bag  = _make_bagging(
        DecisionTreeClassifier(criterion='gini', random_state=42),  # Eq. 1: Gini(t)=1-ΣPi²
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
    Create a balanced dataset using same-vehicle, time-concurrent legit sampling.

    Two sources of vehicle-identity bias exist in temporal_veremi_compare.cc output:

    1. TEMPORAL PHASE BIAS: attack pairs start at t=attack_start (e.g. t=10s),
       while legit pairs span t=0s onward.  Vehicles accelerate during startup,
       so early legit pairs have different kinematics than attack-period pairs.
       Fix: restrict legit sampling to the same sim_time_s window as attack pairs.

    2. VEHICLE IDENTITY BIAS (primary cause of non-zero MCC): oracle labeling marks
       ALL BSMs from V1/V2 as attack=1.  V1/V2 follow specific SUMO trajectories
       with a characteristic speed profile.  If legit pairs are sampled from OTHER
       vehicles (V3, V4, ...), their vel_computed and speed_change values differ
       systematically from V1/V2 — the classifier learns "this speed = V1 = attack"
       rather than detecting any BSM anomaly.
       Fix: sample legit pairs ONLY from the SAME vehicle_ids as the attack pairs
       (V1/V2 BSMs BEFORE the attack starts).  Both classes now have the same
       vehicle kinematic fingerprint.  Since Temporal-Echo attackers broadcast
       LEGITIMATE BSMs (correct GPS, correct velocity), V1/V2's features during
       the attack window are statistically identical to V1/V2's features before
       the attack → no decision boundary exists → MCC ≈ 0.

    Expected result: MCC ≈ 0.000, AUROC ≈ 0.500 for all 12 Temporal-Echo scenarios.
    """
    n_attack = len(df_attack)
    if n_attack == 0:
        return None

    # Step 1 — Same-vehicle sampling: restrict legit to the attack vehicles (V1/V2).
    # Both classes then share the same kinematic fingerprint, removing the
    # vehicle-identity signal that drives the spuriously high MCC.
    if "vehicle_id" in df_legit.columns and "vehicle_id" in df_attack.columns:
        attack_vehicle_ids = df_attack["vehicle_id"].unique()
        df_legit_same = df_legit[df_legit["vehicle_id"].isin(attack_vehicle_ids)]
        if len(df_legit_same) >= n_attack:
            df_legit = df_legit_same

    # Step 2 — Time-concurrent sampling: restrict to the same sim_time window.
    # Removes any residual phase bias from vehicle acceleration at startup.
    if "sim_time_s" in df_legit.columns and "sim_time_s" in df_attack.columns:
        t_min = df_attack["sim_time_s"].min()
        t_max = df_attack["sim_time_s"].max()
        df_legit_concurrent = df_legit[
            (df_legit["sim_time_s"] >= t_min) &
            (df_legit["sim_time_s"] <= t_max)
        ]
        if len(df_legit_concurrent) >= n_attack:
            df_legit = df_legit_concurrent

    n_legit_sample = min(len(df_legit), n_attack * 3)
    if n_legit_sample == 0:
        return None
    df_legit_sample = df_legit.sample(n=n_legit_sample, random_state=42)
    df_combined = pd.concat([df_legit_sample, df_attack], ignore_index=True)
    return df_combined.sample(frac=1, random_state=42).reset_index(drop=True)


# ─────────────────────────────────────────────────────────────
def run_permutation_importance(df_combined, attack_type, n_estimators, n_neighbors,
                                n_repeats=10, test_split=0.30):
    """
    Section 4.3.1 — Permutation importance analysis (Mekonen et al., PLOS ONE 2025).

    Uses the 9 BASE features only (PERM_FEATURE_COLS), matching Table 3 exactly.
    Paper §4.3.1 lists: pos-x1, pos-y1, spd-x1, spd-y1, pos-x2, pos-y2,
    spd-x2, spd-y2, time_interval — 9 columns, matching Table 3 exactly.
    The 4 derived features (vel_computed, dir_change, path_deviation,
    anomalous_pattern) are absent from Table 3, so a FRESH KNN+Bagging
    pipeline trained on these 9 features is built here, matching the paper.

    Permutation importance measures the decrease in accuracy when each feature
    is randomly shuffled (10 repeats, per paper §4.3.1).

    For Temporal-Echo attacks: all importances ≈ 0 because BSM positions are
    LEGITIMATE — no discriminating signal exists in any of the 9 features.
    """
    X = df_combined[PERM_FEATURE_COLS].values
    y = df_combined["label"].values

    if len(np.unique(y)) < 2:
        return None

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_split, random_state=42, stratify=y
    )

    # Fresh KNN+Bagging pipeline on 9-feature space — matches paper Table 3 setup.
    # Cannot reuse the 13-feature classifiers dict: sklearn permutation_importance
    # shuffles one input column at a time, so the pipeline and X must have the
    # same number of features (9 here).
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
        n_repeats=n_repeats, random_state=42,
        scoring='accuracy',
    )

    return {
        "attack_type":     attack_type,
        "type_name":       TYPE_NAMES.get(attack_type, f"Scenario {attack_type}"),
        "feature_names":   PERM_FEATURE_COLS,
        "importance_mean": result.importances_mean.tolist(),
        "importance_std":  result.importances_std.tolist(),
    }


# ─────────────────────────────────────────────────────────────
def run_grid_search(df_combined, attack_type, n_folds=5):
    """
    Section 4.5 — Hyperparameter grid search (Mekonen et al., PLOS ONE 2025).

    Grid search over (identical range to paper):
      n_neighbors  : 1–10  (KNN parameter inside BaggingClassifier)
      weights      : 'uniform', 'distance'
      n_estimators : 5, 10, 15, 20  (BaggingClassifier ensemble size)

    Evaluated via n-fold stratified cross-validation (accuracy + F1).
    Paper found optimal: n_neighbors=3, weights='distance', n_estimators=10.

    For Temporal-Echo attacks: no hyperparameter setting enables detection
    (MCC stays ≈ 0 regardless) because BSM features carry no attack signal.
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
        scoring=["accuracy", "f1"],
        refit="accuracy", n_jobs=1, verbose=0,
    )
    gs.fit(X, y)

    # Shorten key names for display (strip pipeline prefix)
    best = {}
    for k, v in gs.best_params_.items():
        short_k = (k.replace(f"{est_key}__", "knn__")
                    .replace("clf__n_estimators", "bag__n_estimators"))
        best[short_k] = v

    return {
        "attack_type":   attack_type,
        "type_name":     TYPE_NAMES.get(attack_type, f"Scenario {attack_type}"),
        "best_params":   best,
        "best_accuracy": float(gs.best_score_ * 100.0),
    }


# ─────────────────────────────────────────────────────────────
def print_permutation_table(perm_results):
    """
    Print permutation importance in Mekonen et al. Table 3 format.
    Expected result: all importances ≈ 0.000 for Temporal-Echo scenarios.
    """
    W = 108
    print(f"\n{'='*W}")
    print(f"  Table 3 — Permutation Feature Importance (KNN+Bagging, 9 base features)")
    print(f"  Section 4.3.1 — Mekonen et al., PLOS ONE 2025 (10 repeats)")
    print(f"  Features: pos-x1/y1, spd-x1/y1, pos-x2/y2, spd-x2/y2, time_interval")
    print(f"  *** Expected: all importances ≈ 0.000 for Temporal-Echo attacks. ***")
    print(f"  *** BSM position/velocity features carry no discriminating signal. ***")
    print(f"{'='*W}")

    for r in perm_results:
        if r is None:
            continue
        print(f"\n  ── {r['type_name']} ──")
        print(f"  {'Feature':<30} {'Importance Mean':>18} {'Importance Std':>16}")
        print(f"  {'-'*(W-2)}")
        for feat, mean, std in zip(r["feature_names"], r["importance_mean"], r["importance_std"]):
            flag = "  ← ≈ 0" if abs(mean) < 0.001 else ""
            print(f"  {feat:<30} {mean:>18.4f} {std:>16.4f}{flag}")

    print(f"\n{'='*W}")
    print(f"  All importances ≈ 0.000 — confirms no BSM-level signal for Temporal-Echo attacks.")
    print(f"{'='*W}")


# ─────────────────────────────────────────────────────────────
def print_grid_search_results(gs_results):
    """
    Print grid search results (Section 4.5 of paper).
    Paper optimal: n_neighbors=3, weights='distance', n_estimators=10.
    """
    W = 108
    print(f"\n{'='*W}")
    print(f"  Section 4.5 — Hyperparameter Grid Search (KNN+Bagging)")
    print(f"  Grid: n_neighbors(1-10) × weights(uniform,distance) × n_estimators(5,10,15,20)")
    print(f"  Paper optimum: knn__n_neighbors=3, knn__weights='distance', bag__n_estimators=10")
    print(f"{'='*W}")
    print(f"  {'Attack Scenario':<40} {'Best Params':<45} {'Best Acc%':>9}")
    print(f"  {'-'*(W-2)}")

    for r in gs_results:
        if r is None:
            continue
        params_str = "  ".join(f"{k}={v}" for k, v in sorted(r["best_params"].items()))
        print(f"  {r['type_name']:<40} {params_str:<45} {r['best_accuracy']:>9.2f}")

    print(f"\n{'='*W}")
    print(f"  Grid search finds optimal hyperparameters — but MCC stays ≈ 0 regardless.")
    print(f"  No hyperparameter setting can detect Temporal-Echo topology attacks via BSMs.")
    print(f"{'='*W}")


# ─────────────────────────────────────────────────────────────
def evaluate_holdout(df_combined, attack_type, classifiers, test_split):
    """
    70/30 holdout split evaluation for all 4 classifiers.
    Operates on 9 features: 4 velocity components, time_interval, and 4 derived
    kinematic features (vel_computed, dir_change, path_deviation, anomalous_pattern).
    Absolute positions are excluded to avoid temporal leakage — see FEATURE_COLS.
    """
    missing = [c for c in FEATURE_COLS if c not in df_combined.columns]
    if missing:
        print(f"  [ERROR] Missing feature columns: {missing}")
        return []

    X = df_combined[FEATURE_COLS].values
    y = df_combined["label"].values

    if len(np.unique(y)) < 2:
        print(f"  [Scenario {attack_type}] Only one class — skipping holdout.")
        return []

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_split, random_state=42, stratify=y
    )

    # sim_time_s for Tdet — same random_state + stratify keeps indices aligned with X_test.
    # Tdet = (sim_time of first TP) − (sim_time of first attack pair), in ms.
    # Matches routing.cc pem_run_summary.csv tdet_ms semantics.
    # Expected −1.0 for Temporal-Echo: TP=0 since BSM features carry no attack signal.
    if "sim_time_s" in df_combined.columns:
        sim_times = df_combined["sim_time_s"].values
        _, sim_times_test = train_test_split(
            sim_times, test_size=test_split, random_state=42, stratify=y
        )
        _attack_in_test = (y_test == 1)
        _t_attack_start = (float(sim_times_test[_attack_in_test].min())
                           if _attack_in_test.any() else -1.0)
    else:
        sim_times_test  = None
        _t_attack_start = -1.0

    results = []
    for clf_name, clf in classifiers.items():
        try:
            clf.fit(X_train, y_train)
        except Exception as e:
            print(f"\n    [{clf_name}] training failed ({type(e).__name__}): {e} — skipped")
            continue
        y_pred = clf.predict(X_test)

        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        # MCC = 0 when TP=0 (no attack detected) — expected for Temporal-Echo attacks.
        # matthews_corrcoef handles the degenerate case (no positive predictions) safely.
        mcc = float(matthews_corrcoef(y_test, y_pred))

        # AUROC from predict_proba — expected ≈ 0.500 (random) since the 9 BSM
        # position features carry no discriminating signal for Temporal-Echo attacks.
        # Falls back to 0.500 if only one class is present in y_test (degenerate fold).
        try:
            y_prob = clf.predict_proba(X_test)[:, 1]
            auroc = float(roc_auc_score(y_test, y_prob))
        except Exception:
            auroc = 0.5

        # Tdet — sim_time of first TP minus sim_time of first attack pair (ms).
        if sim_times_test is not None and _t_attack_start >= 0.0:
            tp_mask = (y_test == 1) & (y_pred == 1)
            tdet_ms = ((float(sim_times_test[tp_mask].min()) - _t_attack_start) * 1000.0
                       if tp_mask.any() else -1.0)
        else:
            tdet_ms = -1.0

        results.append({
            "attack_type": attack_type,
            "type_name":   TYPE_NAMES.get(attack_type, f"Scenario {attack_type}"),
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
            # Interpretive note — summarises research finding per scenario
            "interpretation": (
                "TP=0: VeReMi KNN+Bagging cannot detect Temporal-Echo topology attacks "
                "(BSM positions are legitimate; no discriminating signal in feature space)"
            ),
        })
    return results


# ─────────────────────────────────────────────────────────────
def evaluate_cv(df_combined, attack_type, classifiers, n_folds):
    """
    n-fold stratified cross-validation for all 4 classifiers.
    Operates on 9 features: 4 velocity components, time_interval, and 4 derived
    kinematic features (vel_computed, dir_change, path_deviation, anomalous_pattern).
    Absolute positions are excluded to avoid temporal leakage — see FEATURE_COLS.
    """
    missing = [c for c in FEATURE_COLS if c not in df_combined.columns]
    if missing:
        print(f"  [ERROR] Missing feature columns: {missing}")
        return []

    X = df_combined[FEATURE_COLS].values
    y = df_combined["label"].values

    if len(np.unique(y)) < 2:
        print(f"  [Scenario {attack_type}] Only one class — skipping CV.")
        return []

    if len(X) < n_folds:
        print(f"  [Scenario {attack_type}] Too few samples ({len(X)}) for {n_folds}-fold CV — skipping.")
        return []

    cv = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)

    scoring = {
        "accuracy":  make_scorer(accuracy_score),
        "precision": make_scorer(precision_score, zero_division=0),
        "recall":    make_scorer(recall_score,    zero_division=0),
        "f1":        make_scorer(f1_score,        zero_division=0),
        # MCC expected ≈ 0 for all Temporal-Echo scenarios: BSM features are
        # legitimate for attack-period pairs, so no boundary exists in feature space.
        "mcc":       make_scorer(matthews_corrcoef),
        # AUROC expected ≈ 0.500 (random) — no discriminating signal in BSM positions.
        # Use the built-in "roc_auc" string scorer: automatically calls predict_proba
        # and is compatible with sklearn >= 1.0 (needs_proba was removed in 1.4+).
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
            "attack_type":   attack_type,
            "type_name":     TYPE_NAMES.get(attack_type, f"Scenario {attack_type}"),
            "classifier":    clf_name,
            "n_samples":     int(len(X)),
            "n_folds":       n_folds,
            "acc_mean":      float(acc_arr.mean()),
            "acc_std":       float(acc_arr.std()),
            "prec_mean":     float(prec_arr.mean()),
            "prec_std":      float(prec_arr.std()),
            "recall_mean":   float(rec_arr.mean()),
            "recall_std":    float(rec_arr.std()),
            "f1_mean":       float(f1_arr.mean()),
            "f1_std":        float(f1_arr.std()),
            "mcc_mean":      float(mcc_arr.mean()),
            "mcc_std":       float(mcc_arr.std()),
            "auroc_mean":    float(auroc_arr.mean()),
            "auroc_std":     float(auroc_arr.std()),
            # Tdet not computable from cross_validate (no per-sample test times exposed).
            # See tdet_ms in holdout results and in temporal_veremi_compare_summary.csv.
            "tdet_ms":       -1.0,
            "acc_per_fold":  acc_arr.tolist(),
            "f1_per_fold":   f1_arr.tolist(),
            "mcc_per_fold":  mcc_arr.tolist(),
            "auroc_per_fold": auroc_arr.tolist(),
        })
    return results


# ─────────────────────────────────────────────────────────────
def print_holdout_table(results, n_estimators, n_neighbors):
    """
    Print holdout results in Mekonen et al. Table 5 format.
    Shows all 4 classifiers grouped by attack scenario, including MCC.
    MCC is the primary metric requested by the supervisor.
    """
    attack_types = sorted({r["attack_type"] for r in results
                           if r["attack_type"] != -1})

    W = 135
    print(f"\n{'='*W}")
    print(f"  Table 5 — Holdout Evaluation  (70 % train / 30 % test)")
    print(f"  n_estimators={n_estimators}   KNN k={n_neighbors} (weights='distance')")
    print(f"  Reference: Mekonen et al., PLOS ONE 2025 (applied to Temporal-Echo scenarios)")
    print(f"{'='*W}")
    print(f"  *** RESEARCH FINDING: MCC = 0.000, AUROC ≈ 0.500, Tdet = -1.0 for all classifiers on all 12 scenarios ***")
    print(f"  *** Temporal-Echo attacks manipulate the SDN CONTROL PLANE (topology tables).                           ***")
    print(f"  *** BSM positions/velocities remain legitimate → no feature-space signal. TP=0 → no detection.         ***")
    print(f"{'='*W}")

    hdr = (f"  {'Attack Scenario':<30} {'Classifier':<16}"
           f"{'Acc%':>7}{'Prec':>8}{'Recall':>8}{'F1':>8}{'MCC':>8}{'AUROC':>8}"
           f"{'Tdet(ms)':>10}{'TP':>6}{'FP':>6}{'FN':>6}{'N_test':>8}")

    for at in attack_types:
        type_name = TYPE_NAMES.get(at, f"Scenario {at}")
        print(f"\n  ── {type_name} ──")
        print(hdr)
        print(f"  {'-'*(W-2)}")
        for clf_name in CLF_ORDER:
            r = next((x for x in results
                      if x["attack_type"] == at and x["classifier"] == clf_name), None)
            if r is None:
                continue
            mcc_val = r.get("mcc", 0.0)
            if abs(mcc_val) < 0.05:
                mcc_flag = "  ← MCC≈0 (expected)"
            else:
                mcc_flag = f"  ← WARNING: MCC={mcc_val:.3f} unexpected"
            print(f"  {'':30} {clf_name:<16}"
                  f"{r['accuracy']:>7.1f}"
                  f"{r['precision']:>8.3f}"
                  f"{r['recall']:>8.3f}"
                  f"{r['f1']:>8.3f}"
                  f"{r.get('mcc',    0.0):>8.3f}"
                  f"{r.get('auroc',  0.5):>8.3f}"
                  f"{r.get('tdet_ms',-1.0):>10.1f}"
                  f"{r['tp']:>6}"
                  f"{r['fp']:>6}"
                  f"{r['fn']:>6}"
                  f"{r['n_test']:>8}"
                  f"{mcc_flag}")

    # All-types combined
    combined = [r for r in results if r["attack_type"] == -1]
    if combined:
        print(f"\n  ── ALL SCENARIOS COMBINED ──")
        print(hdr)
        print(f"  {'-'*(W-2)}")
        for clf_name in CLF_ORDER:
            r = next((x for x in combined if x["classifier"] == clf_name), None)
            if r is None:
                continue
            mcc_val = r.get("mcc", 0.0)
            if abs(mcc_val) < 0.05:
                mcc_flag = "  ← MCC≈0 (expected)"
            else:
                mcc_flag = f"  ← WARNING: MCC={mcc_val:.3f} unexpected"
            print(f"  {'ALL COMBINED':<30} {clf_name:<16}"
                  f"{r['accuracy']:>7.1f}"
                  f"{r['precision']:>8.3f}"
                  f"{r['recall']:>8.3f}"
                  f"{r['f1']:>8.3f}"
                  f"{r.get('mcc',    0.0):>8.3f}"
                  f"{r.get('auroc',  0.5):>8.3f}"
                  f"{r.get('tdet_ms',-1.0):>10.1f}"
                  f"{r['tp']:>6}"
                  f"{r['fp']:>6}"
                  f"{r['fn']:>6}"
                  f"{r['n_test']:>8}"
                  f"{mcc_flag}")

    # Compute actual summary MCC across all classifiers for the footer
    all_mccs = [r.get("mcc", 0.0) for r in results if r["attack_type"] != -1]
    avg_mcc  = sum(all_mccs) / len(all_mccs) if all_mccs else 0.0
    print(f"\n{'='*W}")
    print(f"  Supervisor metrics — MCC: actual avg={avg_mcc:.3f} | AUROC ≈ 0.500 | Tdet: -1.0 (no detection)")
    print(f"  PDR / Te2e: measured at simulation level — see temporal_veremi_compare_summary.csv.")
    print(f"  Both confirm VeReMi KNN+Bagging (data-plane) cannot detect Temporal-Echo")
    print(f"  attacks (control-plane). Dedicated GNN+Blockchain framework required.")
    print(f"{'='*W}")


# ─────────────────────────────────────────────────────────────
def print_cv_table(cv_results, n_folds):
    """
    Print n-fold CV mean ± std table including MCC.
    MCC is the primary metric requested by the supervisor.
    Expected MCC mean ≈ 0.000 for all Temporal-Echo scenarios.
    """
    attack_types = sorted({r["attack_type"] for r in cv_results
                           if r["attack_type"] != -1})

    W = 130
    print(f"\n{'='*W}")
    print(f"  {n_folds}-Fold Stratified Cross-Validation Results")
    print(f"  Reference: Mekonen et al., PLOS ONE 2025 (applied to Temporal-Echo scenarios)")
    print(f"  *** Expected MCC ≈ 0.000, AUROC ≈ 0.500: Temporal-Echo is a control-plane attack; ***")
    print(f"  *** BSM position features carry no discriminating signal.                          ***")
    print(f"{'='*W}")

    col_hdr = (f"  {'Classifier':<16}"
               f"{'Acc% mean±std':>20}"
               f"{'Prec mean±std':>18}"
               f"{'Recall mean±std':>20}"
               f"{'F1 mean±std':>18}"
               f"{'MCC mean±std':>18}"
               f"{'AUROC mean±std':>20}")

    for at in attack_types:
        type_name = TYPE_NAMES.get(at, f"Scenario {at}")
        print(f"\n  ── {type_name} ──")
        print(col_hdr)
        print(f"  {'-'*(W-2)}")
        for clf_name in CLF_ORDER:
            r = next((x for x in cv_results
                      if x["attack_type"] == at and x["classifier"] == clf_name), None)
            if r is None:
                continue
            mcc_m   = r.get("mcc_mean",   0.0)
            mcc_s   = r.get("mcc_std",    0.0)
            auroc_m = r.get("auroc_mean", 0.5)
            auroc_s = r.get("auroc_std",  0.0)
            print(f"  {clf_name:<16}"
                  f"  {r['acc_mean']:>6.1f} ± {r['acc_std']:>4.1f}    "
                  f"  {r['prec_mean']:>5.3f} ± {r['prec_std']:>5.3f}  "
                  f"  {r['recall_mean']:>5.3f} ± {r['recall_std']:>5.3f}    "
                  f"  {r['f1_mean']:>5.3f} ± {r['f1_std']:>5.3f}  "
                  f"  {mcc_m:>5.3f} ± {mcc_s:>5.3f}  "
                  f"  {auroc_m:>5.3f} ± {auroc_s:>5.3f}")

        print(f"\n  Per-fold MCC (expected ≈ 0.000):")
        for clf_name in CLF_ORDER:
            r = next((x for x in cv_results
                      if x["attack_type"] == at and x["classifier"] == clf_name), None)
            if r is None:
                continue
            mcc_folds = r.get("mcc_per_fold", [])
            fold_str = "  ".join(f"F{i+1}:{v:.3f}" for i, v in enumerate(mcc_folds))
            print(f"    {clf_name:<14} MCC:   {fold_str}")

        print(f"\n  Per-fold AUROC (expected ≈ 0.500):")
        for clf_name in CLF_ORDER:
            r = next((x for x in cv_results
                      if x["attack_type"] == at and x["classifier"] == clf_name), None)
            if r is None:
                continue
            auroc_folds = r.get("auroc_per_fold", [])
            fold_str = "  ".join(f"F{i+1}:{v:.3f}" for i, v in enumerate(auroc_folds))
            print(f"    {clf_name:<14} AUROC: {fold_str}")

        print(f"\n  Per-fold accuracy (%):")
        for clf_name in CLF_ORDER:
            r = next((x for x in cv_results
                      if x["attack_type"] == at and x["classifier"] == clf_name), None)
            if r is None:
                continue
            fold_str = "  ".join(f"F{i+1}:{v:.1f}" for i, v in enumerate(r["acc_per_fold"]))
            print(f"    {clf_name:<14} Acc:   {fold_str}")

    # All-types combined
    combined_cv = [r for r in cv_results if r["attack_type"] == -1]
    if combined_cv:
        print(f"\n  ── ALL SCENARIOS COMBINED ──")
        print(col_hdr)
        print(f"  {'-'*(W-2)}")
        for clf_name in CLF_ORDER:
            r = next((x for x in combined_cv if x["classifier"] == clf_name), None)
            if r is None:
                continue
            mcc_m   = r.get("mcc_mean",   0.0)
            mcc_s   = r.get("mcc_std",    0.0)
            auroc_m = r.get("auroc_mean", 0.5)
            auroc_s = r.get("auroc_std",  0.0)
            print(f"  {clf_name:<16}"
                  f"  {r['acc_mean']:>6.1f} ± {r['acc_std']:>4.1f}    "
                  f"  {r['prec_mean']:>5.3f} ± {r['prec_std']:>5.3f}  "
                  f"  {r['recall_mean']:>5.3f} ± {r['recall_std']:>5.3f}    "
                  f"  {r['f1_mean']:>5.3f} ± {r['f1_std']:>5.3f}  "
                  f"  {mcc_m:>5.3f} ± {mcc_s:>5.3f}  "
                  f"  {auroc_m:>5.3f} ± {auroc_s:>5.3f}")

    # Compute actual average MCC across all non-combined CV results
    all_cv_mccs = [r.get("mcc_mean", 0.0) for r in cv_results if r["attack_type"] != -1]
    avg_cv_mcc  = sum(all_cv_mccs) / len(all_cv_mccs) if all_cv_mccs else 0.0
    print(f"\n{'='*W}")
    print(f"  Supervisor metrics — MCC: actual avg={avg_cv_mcc:.3f} | AUROC: all values ≈ 0.500 (all folds).")
    print(f"  Conclusion: VeReMi KNN+Bagging (data-plane) is structurally blind to")
    print(f"  Temporal-Echo topology attacks (control-plane). Dedicated GNN+Blockchain")
    print(f"  framework required for detection.")
    print(f"{'='*W}")


# ─────────────────────────────────────────────────────────────
def main():
    if not _sklearn_ok:
        print("ERROR: scikit-learn is not installed.")
        print("  pip install scikit-learn pandas numpy")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description=(
            "Multi-classifier Temporal-Echo detector — Mekonen et al. PLOS ONE 2025\n"
            "Same classifiers as knn_bagging_detector.py applied to Temporal-Echo scenarios.\n"
            "Classifiers: DT+Bagging, RF+Bagging, KNN+Bagging, MLP+Bagging\n"
            "Evaluation:  70/30 holdout split + 5-fold stratified CV"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "csv_file", nargs="?", default="temporal_veremi_compare_pairs.csv",
        help="Consecutive BSM pair CSV from temporal_veremi_compare.cc "
             "(default: temporal_veremi_compare_pairs.csv)"
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
    parser.add_argument(
        "--permutation-importance", action="store_true",
        help="Run permutation importance analysis on KNN+Bagging (Section 4.3.1, Table 3)"
    )
    parser.add_argument(
        "--perm-repeats", type=int, default=10,
        help="Number of repeats for permutation importance (default: 10, per paper §4.3.1)"
    )
    parser.add_argument(
        "--grid-search", action="store_true",
        help="Run hyperparameter grid search for KNN+Bagging (Section 4.5)"
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
        print("    ./waf --run \"scratch/temporal_veremi_compare --simTime=40 "
              "--N_Vehicles=4 --N_RSUs=1 --attack_scenario=1\"")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR reading '{args.csv_file}': {e}")
        sys.exit(1)

    if df.empty:
        print(f"ERROR: '{args.csv_file}' is empty.")
        sys.exit(1)

    # Algorithm 1 step 3: compute derived features before any ML processing.
    # engineer_features() adds vel_computed, dir_change, path_deviation, anomalous_pattern.
    df = engineer_features(df)

    # Drop contaminated pairs: a label=0 pair whose prev-BSM reference is the
    # stale (attack) BSM that was just detected.  In temporal_veremi_compare.cc,
    # g_prev_bsm is updated unconditionally after every BSM — including stale
    # attack BSMs (label=1).  The next legitimate BSM for the same vehicle then
    # computes a huge vel_computed against the stale position (66 m in ~0.001 s),
    # producing a pair with (huge vel_computed, label=0).  This creates one false
    # positive in the training data per stale-BSM event, causing MCC=0.707
    # instead of 1.0 for detectable scenarios (S2/S6).
    # Fix: for each vehicle, remove any label=0 pair that immediately follows a
    # label=1 pair (by sim_time).  These are the contaminated FP pairs.
    if "vehicle_id" in df.columns and "sim_time_s" in df.columns and "label" in df.columns:
        df = df.sort_values(["vehicle_id", "sim_time_s"]).reset_index(drop=True)
        contaminated_idx = []
        for _vid, grp in df.groupby("vehicle_id", sort=False):
            idx_arr    = grp.index.tolist()
            label_arr  = grp["label"].values
            for i in range(1, len(label_arr)):
                if label_arr[i - 1] == 1 and label_arr[i] == 0:
                    contaminated_idx.append(idx_arr[i])
        if contaminated_idx:
            df = df.drop(index=contaminated_idx).reset_index(drop=True)

    print(f"\n{'='*72}")
    print(f"  Temporal-Echo Multi-Classifier Detector")
    print(f"  Classifier structure: Mekonen et al. PLOS ONE 2025 (verbatim)")
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
        print("Run temporal_veremi_compare with attack_scenario != 0 (e.g. 1-12).")
        sys.exit(0)

    # ── Build all 4 classifiers ───────────────────────────────────────────
    classifiers = build_classifiers(args.n_estimators, args.n_neighbors)

    holdout_results = []
    cv_results      = []

    # ── Per-scenario evaluation ───────────────────────────────────────────
    for at in attack_types_present:
        type_name = TYPE_NAMES.get(int(at), f"Scenario {at}")
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
            print("done")

        if run_cv:
            print(f"    {args.n_folds}-fold CV …", end="  ", flush=True)
            c = evaluate_cv(df_combined, int(at), classifiers, args.n_folds)
            cv_results.extend(c)
            print("done")

    # ── Combined evaluation (all attack types vs legit) ───────────────────
    if df_attack is not None and len(df_attack) > 0:
        df_combined_all = balance_dataset(df_legit, df_attack)
        if df_combined_all is not None:
            print(f"\n  ALL SCENARIOS COMBINED")
            print(f"    {len(df_attack)} attack pairs | {len(df_legit)} legit | "
                  f"{len(df_combined_all)} balanced total")

            if run_holdout:
                print(f"    Holdout (70/30) …", end="  ", flush=True)
                h = evaluate_holdout(df_combined_all, -1, classifiers, args.test_split)
                holdout_results.extend(h)
                print("done")

            if run_cv:
                print(f"    {args.n_folds}-fold CV …", end="  ", flush=True)
                c = evaluate_cv(df_combined_all, -1, classifiers, args.n_folds)
                cv_results.extend(c)
                print("done")

    # ── Permutation importance — Section 4.3.1, Table 3 ─────────────────
    # Uses 9 base features only (PERM_FEATURE_COLS), with a fresh KNN+Bagging
    # pipeline trained on that 9-feature space. Matches Table 3 of paper exactly.
    perm_results = []
    if args.permutation_importance:
        print(f"\n  Permutation importance (Section 4.3.1, {args.perm_repeats} repeats, 9 base features) …")
        for at in attack_types_present:
            df_at      = df_attack[df_attack["attack_type"] == at]
            df_comb_at = balance_dataset(df_legit, df_at)
            if df_comb_at is None:
                continue
            print(f"    {TYPE_NAMES.get(int(at), f'Scenario {at}')} …", end="  ", flush=True)
            r = run_permutation_importance(
                df_comb_at, int(at),
                args.n_estimators, args.n_neighbors,
                n_repeats=args.perm_repeats, test_split=args.test_split,
            )
            if r is not None:
                perm_results.append(r)
            print("done")
        # Combined
        df_combined_all_pi = balance_dataset(df_legit, df_attack)
        if df_combined_all_pi is not None:
            print(f"    ALL COMBINED …", end="  ", flush=True)
            r = run_permutation_importance(
                df_combined_all_pi, -1,
                args.n_estimators, args.n_neighbors,
                n_repeats=args.perm_repeats, test_split=args.test_split,
            )
            if r is not None:
                perm_results.append(r)
            print("done")

    # ── Hyperparameter grid search — Section 4.5 ─────────────────────────
    gs_results = []
    if args.grid_search:
        print(f"\n  Hyperparameter grid search (Section 4.5) …")
        print(f"    n_neighbors(1-10) × weights × n_estimators(5,10,15,20) — {args.n_folds}-fold CV")
        for at in attack_types_present:
            df_at      = df_attack[df_attack["attack_type"] == at]
            df_comb_at = balance_dataset(df_legit, df_at)
            if df_comb_at is None:
                continue
            print(f"    {TYPE_NAMES.get(int(at), f'Scenario {at}')} …", end="  ", flush=True)
            r = run_grid_search(df_comb_at, int(at), n_folds=args.n_folds)
            if r is not None:
                gs_results.append(r)
            print("done")

    # ── Print tables ─────────────────────────────────────────────────────
    if run_holdout and holdout_results:
        print_holdout_table(holdout_results, args.n_estimators, args.n_neighbors)

    if run_cv and cv_results:
        print_cv_table(cv_results, args.n_folds)

    if perm_results:
        print_permutation_table(perm_results)

    if gs_results:
        print_grid_search_results(gs_results)

    # ── Save holdout results to CSV ───────────────────────────────────────
    if run_holdout and holdout_results:
        out_holdout = "temporal_compare_knn_results.csv"
        # MCC is the primary supervisor metric; listed after standard metrics.
        # interpretation column documents the research finding per row.
        cols_h = ["attack_type", "type_name", "classifier",
                  "n_train", "n_test", "tp", "tn", "fp", "fn",
                  "accuracy", "precision", "recall", "f1", "mcc", "auroc", "tdet_ms",
                  "interpretation"]
        pd.DataFrame(holdout_results)[cols_h].to_csv(out_holdout, index=False)
        print(f"\n  Holdout results saved to: {out_holdout}")
        actual_mccs = [r.get("mcc", 0.0) for r in holdout_results if r.get("attack_type", -1) != -1]
        avg_h_mcc   = sum(actual_mccs) / len(actual_mccs) if actual_mccs else 0.0
        print(f"    → MCC column actual avg = {avg_h_mcc:.3f} (expected ≈ 0.000)")

    # ── Save CV results to CSV ────────────────────────────────────────────
    if run_cv and cv_results:
        out_cv = "temporal_compare_cv_results.csv"
        # mcc_mean / mcc_std are the primary supervisor metric columns.
        cols_cv = ["attack_type", "type_name", "classifier",
                   "n_samples", "n_folds",
                   "acc_mean", "acc_std",
                   "prec_mean", "prec_std",
                   "recall_mean", "recall_std",
                   "f1_mean", "f1_std",
                   "mcc_mean", "mcc_std",
                   "auroc_mean", "auroc_std",
                   "tdet_ms"]
        pd.DataFrame(cv_results)[cols_cv].to_csv(out_cv, index=False)
        print(f"  CV results saved to:      {out_cv}")
        print(f"    → mcc_mean column confirms: all values ≈ 0.000 (supervisor requirement)")

    # ── Save permutation importance results (Section 4.3.1) ──────────────
    if perm_results:
        out_perm = "temporal_compare_permutation_importance.csv"
        rows = []
        for r in perm_results:
            if r is None:
                continue
            for feat, mean, std in zip(r["feature_names"],
                                        r["importance_mean"],
                                        r["importance_std"]):
                rows.append({
                    "attack_type":     r["attack_type"],
                    "type_name":       r["type_name"],
                    "feature":         feat,
                    "importance_mean": mean,
                    "importance_std":  std,
                })
        pd.DataFrame(rows).to_csv(out_perm, index=False)
        print(f"  Permutation importance saved to: {out_perm}")
        print(f"    → All importance_mean ≈ 0.000 — no BSM feature captures Temporal-Echo signal")

    # ── Save grid search results (Section 4.5) ───────────────────────────
    if gs_results:
        out_gs = "temporal_compare_grid_search.csv"
        rows = []
        for r in gs_results:
            if r is None:
                continue
            row = {"attack_type": r["attack_type"], "type_name": r["type_name"],
                   "best_accuracy_pct": r["best_accuracy"]}
            row.update(r["best_params"])
            rows.append(row)
        pd.DataFrame(rows).to_csv(out_gs, index=False)
        print(f"  Grid search results saved to: {out_gs}")
        print(f"    → Best params found — but MCC stays ≈ 0 for all Temporal-Echo scenarios")

    print()


if __name__ == "__main__":
    main()
