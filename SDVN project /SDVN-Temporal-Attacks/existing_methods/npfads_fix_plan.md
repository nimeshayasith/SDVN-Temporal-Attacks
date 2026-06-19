# NPFADS Implementation Fix Plan

**Reference paper:** Ilango, Ma & Su (2022), *Engineering Applications of AI* 116, 105380
**Your context:** Applying/adapting NPFADS (MDS + NADM) as a **baseline comparison method** against your TGNN solution, for TTW / BSHH / ME attacks in an SDN-enabled VANET (NS-3.35 + SUMO)
**Supervisor's requirement:** (1) verify the implemented state-of-the-art (NPFADS) is connected to the simulation variables properly, (2) verify the plots are correctly plotted

---

## 0. Glossary — "Simulation Variables" vs "Ground-Truth Labels"

This distinction is the whole point of your supervisor's first requirement, so it's worth pinning down before anything else.

- **Simulation variables** = real numbers the simulation actually measures while it runs. They change depending on what really happened. In your code: `xPos`, `yPos`, `xSpd`, `ySpd`, `xAcc`, `yAcc`, `sendTime`, and the 7 `eigs[]` values computed from them.
- **Ground-truth label** = a tag *you* attach beforehand for evaluation purposes, e.g. `attackType`. The simulation doesn't detect this — you told it this in advance. It exists only so you can later check whether the detector got the right answer.

**The rule a real detector must follow:** its decision (attack / not attack, which class, how confident) must be computed *only* from simulation variables. The label is allowed to appear *after* the decision, only to score it — never *inside* the decision logic itself.

Your current `SimulateSx()` breaks this rule — it reads `attackType` first and picks an output from it, like a student copying the answer key before "solving" the problem. That's the disconnect your supervisor is asking you to check for, and right now the check fails.

---

## 1. Current State of `npfads_solution.h`

| Component | Paper requires | Your code currently does | Status |
|---|---|---|---|
| Feature extraction | Mobility matrix → column centering → M^T·M → Jacobi eigenvalues | Implemented correctly, uses only simulation variables | ✅ Keep as-is |
| MDS (per-vehicle / per-fog classifier) | Trained Random Forest | Hardcoded `if/else` on a `posVar` ratio | ❌ Needs real training |
| NADM AutoEncoder | Trained on benign-only data, 7→4→3→2→3→4→7 | A ratio formula, never trained | ❌ Needs real training |
| NADM second RF | Trained on known attacks, outputs real C(X)/S(X) from simulation variables | `switch(attackType)` hardcodes S(X) from the **label**, not from any simulation variable | ❌ Needs real training — currently uses the label directly |
| H1/H2/H3 threshold sweep | CCR(τ)/MCR(τ) computed from a real trained model's outputs | τ₁/τ₂ copied as constants straight from the paper's Table 3 | ❌ Needs real computation |
| UC_known / UC_FN-BSMD / NASEA | Computed from real S(X) values | Formulas are coded correctly, but the inputs feeding them are fabricated | ⚠️ Formula OK, data isn't |

**Bottom line:** Feature extraction is solid and uses real simulation variables throughout. Everything from "Mode B" onward currently fails the "connected to simulation variables" test and needs to be rebuilt on real trained models.

---

## 2. Supervisor's Two Verification Requirements — How to Actually Check Them

### 2.1 "Is the detection mechanism connected to the simulation variables properly?"

Do this check on whatever code/model is producing the NPFADS numbers that go into your plots:

- [ ] Open the function that produces the final attack/no-attack decision (today: `SimulateSx()` / `RunModeB_RFSimulated()`). Check every line for any read of `attackType` (or any other ground-truth field). **If the decision-making code reads the label before producing its output, it fails this check.**
- [ ] Confirm the decision is a function of simulation variables only: `eigs[0..6]`, `posVar`, or — once trained — the actual fitted RF/AE model's `.predict()` call on those same features.
- [ ] Confirm `attackType` only appears *after* the decision is made, used solely to compute TP/FP/FN/TN for your metrics — never as an input to the decision itself.
- [ ] Sanity-check with a "scramble test": shuffle the `attackType` labels on a copy of your test set (keep the simulation variables untouched) and re-run detection. A properly connected detector's *decisions* won't change at all (since it never reads the label) — only your *scored accuracy* should collapse toward random. If the detector's decisions change when you scramble labels, it's reading the label somewhere — that's the bug.
- [ ] Once real training is done (Section 5), repeat this check against the trained-model version, not just the current heuristic version. This check needs to pass on whatever code generates your final reported numbers.

### 2.2 "Are the plots correctly plotted?"

I'll need two things from you to actually run this check:
- [ ] The plotting code (pgfplots/LaTeX, or Python/matplotlib — whichever you used)
- [ ] A sample of the underlying CSV/data file(s) each plot reads from

Once I have those, here's what gets checked against each other:
- [ ] Each plotted series maps to the correct column (e.g. an "F1 score" line is actually reading the F1 column, not precision or recall by accident)
- [ ] Axis values match the column's actual scale (0–1 for F1/precision/recall/AUROC; -1 to 1 for MCC; correct units/ms for detection latency)
- [ ] Grouping is correct — each S1–S4 scenario and each attack-percentage bucket (your 12 scenarios × 11 attack percentages = 132 runs) is pulling data from the matching rows, not an offset or duplicated set
- [ ] Each attack type (TTW/BSHH/ME, plus NPFADS's own Type 1/2/4/8/16 if shown separately) is labeled and colored consistently across all figures
- [ ] No silent aggregation bugs — e.g. averaging across runs that shouldn't be averaged together, or a column read as string instead of number, silently producing all-zero or all-NaN data that still "plots" something
- [ ] Legends, axis titles, and captions actually describe what's plotted (this sounds trivial but is the single most common reviewer comment on these kinds of figures)

---

## 3. A Bigger Question to Settle First: Does NPFADS's Feature Set Fit Your Attacks?

This matters more than the code fix itself, so resolve it before you train anything.

NPFADS was built to catch **position falsification** — a vehicle lying about its own physical location, speed, or acceleration in a BSM. Its 7 features (SendTime, XPos, YPos, XSpd, YSpd, XAcc, YAcc) are built entirely around that one assumption.

Your three attacks operate at a different layer:

| Your attack | What it actually tampers with | Does it touch a vehicle's position/speed/accel? |
|---|---|---|
| **TTW** (Timestamp Tampering by Wormhole) | Message timestamps / propagation delay | Partially — `SendTime` is already feature #1, so this *might* leave a signal |
| **BSHH** (Beacon State Heartbeat Hijack) | A compromised controller internally reinstates **stale, previously-received heartbeats** as if they were current — "zero-payload temporal state hijacking" | No — the vehicle's actual reported position/speed never changes. The falsification is purely about *when* a heartbeat is treated as valid, inside the controller |
| **ME** (Multipath Echo) | Vehicles, an RSU, or the controller **replay/echo legitimate HELLO messages**, making the controller infer extra non-existent logical paths | No — V1 and V2's real positions stay correct throughout. The falsification is in the *topology graph* the controller builds, not in any single vehicle's motion |

**Implication:** if you train NPFADS exactly as the paper specifies and point it at BSHH or ME, expect it to perform poorly — not because your implementation is broken, but because the signal these two attacks leave behind simply isn't present in 7 motion-based features. This is precisely the kind of attack your separate TGNN pipeline (with `seq_num`, timing-delay features, etc.) is built for.

**Recommended framing for your report:** treat NPFADS as a **baseline comparison method**, not your primary detector for BSHH/ME. Showing — honestly — that a position-falsification-style MDS underperforms on topology-layer attacks is a legitimate and common move in security papers, and it directly motivates why a TGNN-based approach is needed, and supports your goal of showing your solution is the better option.

If your project specification instead requires NPFADS itself to detect all three attacks well, see Section 8 for what extending the feature set would involve.

---

## 4. Decision to Make Before Training

- [ ] **Option A (recommended, faster):** Keep the original 7 features. Train NPFADS faithfully on your TTW data as the "known" attack class, and use BSHH/ME as deliberately held-out "novel" classes — this both tests NADM's novelty detection mechanism and honestly documents where a pure position-based MDS falls short, supporting your "our solution is better" comparison.
- [ ] **Option B (more work):** Extend the feature vector with topology/timing-aware signals so NPFADS has a fair chance at BSHH/ME too (Section 8).

Record your choice explicitly in your methodology section — don't let it be implicit.

---

## 5. Step-by-Step Fix Plan (Every Step, Start to Finish)

### Phase A — Data

- [ ] **A1.** Confirm your NS-3/SUMO runs label every BSM/event with the correct `attackType` (benign / TTW / BSHH / ME).
- [ ] **A2.** Confirm you have enough **benign** runs — this is the AE's only training signal, so it needs real volume.
- [ ] **A3.** Confirm you have enough **TTW** samples to split into train and test sets for the MDS and NADM RFs.
- [ ] **A4.** Set aside **all** BSHH and ME samples — these must not appear in any training set. They are only used later, in Phase D, to test novelty detection.
- [ ] **A5.** Run `BuildEigenvalueRecords()` and `WriteOutputCsvs()` unchanged — these are already correct. Confirm the output CSV has one row per vehicle per run with columns `eig1..eig7, posVar, attackType`.
- [ ] **A6.** Spot-check the CSV manually: open it, confirm benign rows have sensible eigenvalues, confirm attack rows look different from benign rows in at least some column. If everything looks identical, something upstream is wrong before you even get to modeling.

### Phase B — Python environment

- [ ] **B1.** Install dependencies:
  ```bash
  pip install scikit-learn pandas numpy --break-system-packages
  ```
- [ ] **B2.** (Optional, only if you want a true neural-net AE instead of an sklearn-MLP-based one):
  ```bash
  pip install tensorflow --break-system-packages
  ```
- [ ] **B3.** Load your CSV with pandas, split into `benign_df`, `ttw_df`, `bshh_df`, `me_df` based on `attackType`.

### Phase C — Train the real models

- [ ] **C1.** Split `benign_df` into train/validation/test.
- [ ] **C2.** Train the AE on the benign train split only. Architecture: 7 → 4 → 3 → 2 (bottleneck) → 3 → 4 → 7. Adam optimizer, 20 epochs, batch size 64, early-stop if validation loss is flat for 3 consecutive epochs (matches the paper exactly).
- [ ] **C3.** Compute MSE on the benign validation split and on a small TTW sample; pick τ_AE as the value that best separates the two (matches the paper's procedure for setting τ_AE).
- [ ] **C4.** Split `benign_df` + `ttw_df` into train/test for the MDS RF.
- [ ] **C5.** Train the MDS RF with `RandomizedSearchCV` for hyperparameter tuning (matches the paper's method).
- [ ] **C6.** Evaluate the MDS RF on its test split — accuracy/precision/recall/F1 (this gives you your Table-5-style numbers).
- [ ] **C7.** Train the NADM RF on the same benign+TTW split, but as a multi-class classifier (predict which class, plus return the model's own confidence — e.g. `predict_proba().max()` per row — this is your real S(X), not a hardcoded value).
- [ ] **C8.** On the NADM RF's own test split, sweep τ from 0 → 1 in steps of 0.001. For each τ and each known class, compute CCR(τ) and MCR(τ) (Eqs. 3–4 in the paper).
- [ ] **C9.** Apply Hypothesis H3: restrict to τ values where CCR(τ) > 0.90 for that class, then pick the τ that minimizes MCR(τ). This gives you τᵢ per known class.
- [ ] **C10.** Compute UC_known on this same NADM RF test split, using the τᵢ values from C9.
- [ ] **C11.** Run the "scramble test" from Section 2.1 on this trained pipeline to confirm it's genuinely label-free at decision time.

### Phase D — Evaluate novelty detection on BSHH/ME

- [ ] **D1.** Run the held-out `bshh_df` and `me_df` rows through the trained AE. Keep only rows with MSE ≥ τ_AE (flagged malicious).
- [ ] **D2.** Run the flagged rows through the trained NADM RF to get real C(X) and S(X).
- [ ] **D3.** Compute UC_FN-BSMD on this batch.
- [ ] **D4.** Compare UC_FN-BSMD to UC_known from C10. Report whether `UC_FN-BSMD > UC_known` holds.
- [ ] **D5.** Compute NASEA (Eq. 12) — the fraction of BSHH/ME samples correctly extracted as "novel."
- [ ] **D6.** Document the result honestly, whichever way it comes out. A clear result showing NPFADS struggles here (per Section 3) is still a legitimate, useful finding for your comparison narrative.

### Phase E — Reporting

- [ ] **E1.** Build per-attack-type tables: accuracy/precision/recall/F1 for TTW (known) and BSHH/ME (novel), mirroring the paper's Tables 5–6 format.
- [ ] **E2.** Build ROC and PR curves per attack type, mirroring Figs. 6–9.
- [ ] **E3.** Build a head-to-head comparison table: NPFADS vs. your TGNN solution, per attack type, mirroring the paper's Table 7 format — this is the centerpiece figure for "our solution is the best option."
- [ ] **E4.** Run the full plot-verification checklist from Section 2.2 against every figure before finalizing.
- [ ] **E5.** *(Optional)* Demonstrate the retraining loop: fold the extracted novel rows into the known set, retrain MDS + NADM RF, recompute τᵢ, and show improved detection on a second held-out batch of the same type — mirrors the paper's four-time-instant case study.

---

## 6. What Changes in Your C++ Code

- **Remove:** `RunModeB_RFSimulated()`, `SimulateSx()`, the hardcoded `TAU_1` / `TAU_2` constants, and the `posVar`-ratio heuristics across Modes A/B/C.
- **Keep unchanged:** `BuildEigenvalueRecords()`, `CenterColumns()`, `TransposeMultiply()`, `JacobiEigenvalues()`, and `WriteOutputCsvs()` (the eigenvalue CSV export) — these already use only simulation variables and pass the Section 2.1 check.
- **No C++ inference integration is required.** The paper itself never embeds the trained RF/AE back into a live simulator — its entire evaluation is an offline train/test exercise on exported data. Your NS-3 code's job ends at producing the labeled eigenvalue CSV; everything from Phase B onward happens in Python.

---

## 7. (Optional, Option B) Extending Features for BSHH/ME

If your project requires NPFADS itself to catch BSHH/ME, you'd need features that are actually sensitive to those attacks, e.g.:

- **For BSHH:** time-since-last-heartbeat-update, count of duplicate/stale heartbeats reinstated per controller cycle, timestamp delta vs. expected heartbeat interval
- **For ME:** number of distinct reporters claiming the same link, path-redundancy count per controller topology snapshot, link-reciprocity check (does the "echoed" intermediate also independently report seeing both endpoints?)

These likely require a different sampling unit altogether — per-link or per-controller-update, rather than per-vehicle — which is a bigger structural change than "fixing" NPFADS; it edges into redesigning it. Flag this with your supervisor before committing to it.

---

## 8. Full Deliverables Checklist

**Verification (supervisor's two requirements):**
- [ ] Decision logic checked line-by-line for any read of `attackType` before producing its output (Section 2.1)
- [ ] "Scramble test" run and passed — decisions don't change when labels are shuffled
- [ ] Plotting code and source CSVs reviewed against the checklist in Section 2.2

**Implementation:**
- [ ] Decision recorded: Option A or B (Section 4)
- [ ] Eigenvalue CSV exported from NS-3 with benign + TTW + held-out BSHH/ME rows
- [ ] AE trained benign-only, τ_AE set
- [ ] MDS RF trained and evaluated (precision/recall/F1/ROC/PR)
- [ ] NADM RF trained, H3 threshold sweep run, τᵢ + UC_known computed
- [ ] BSHH/ME run through the full NADM pipeline; UC_FN-BSMD/NASEA computed and compared to UC_known
- [ ] `npfads_solution.h` heuristic modes removed and replaced per Section 6

**Reporting:**
- [ ] Per-attack-type metrics tables produced (Tables 5–6 style)
- [ ] ROC/PR curves produced (Figs. 6–9 style)
- [ ] NPFADS-vs-TGNN comparison table produced (Table 7 style)
- [ ] All figures pass the plot-verification checklist (Section 2.2)
