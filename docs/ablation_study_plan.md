# Specula — Ablation Study Plan

> **Status:** Design only — no experiments to be executed until reviewed.
> **Date:** 2026-07-25
> **Purpose:** Quantify the marginal contribution of each core subsystem in Specula so the paper can claim statistically significant improvements over naive baselines.

---

## Preliminary: Shared Experimental Setup

| Item | Value |
|---|---|
| **SAST corpus** | 2,000 code snippets (1,000 vulnerable, 1,000 clean) drawn from the BigVul + SARD datasets, filtered to the 6 CWE classes in `VULNERABILITY_CLASSES` (`rule_classifier.py:4-12`). |
| **DAST target set** | 30 deliberately vulnerable web apps (DVWA, Juice Shop, WebGoat, 27 custom Flask apps from `dast/app.py` CWE knowledge base). |
| **NIDS corpus** | CIC-IDS2017 + CSE-CIC-IDS2018 test splits (unseen flows). |
| **Triage test set** | 500 manually-labeled findings from prior Specula runs, stratified across all confidence ranges. |
| **Hardware** | Single NVIDIA A100 80GB, 64-core CPU, 128 GB RAM. |
| **Reproducibility** | All experiments pinned via `requirements.txt` lockfile; random seeds set to 42; Docker images published. |

---

## A. SAST Ablation — Rule-Based Fallback Impact

**Component under study:** `backend/services/code/models/rule_classifier.py`
**Key design:** A regex-based `RuleBasedClassifier` that assigns hard-coded scores (e.g., 0.92 for SQLi string concatenation) and overrides the ML model when confidence < 0.30 (`rule_classifier.py:48-54`). It also supplies per-line `reasons` that the ML-only path cannot produce.

### A1: CodeBERT-only (no rule fallback)

**Configuration:** Disable `RuleBasedClassifier.classify()`. Force all predictions through CodeBERT regardless of confidence.

```bash
python -m services.code.models.eval \
  --model codebert \
  --rules disabled \
  --corpus data/sast/eval_set.jsonl \
  --output results/ablation_a1_codebert_only.json
```

**Metrics to report:**
- Precision, Recall, F1 per CWE class
- False Positive Rate (FPR) on parameterized-query snippets (subset of 200 clean snippets that use `?` placeholders, `%s` formatting, or `.format()` — see `rule_classifier.py:86-91` for the exact patterns the rules check)
- False Negative Rate (FNR) on real vulnerable snippets

**Expected result:** High recall but elevated FPR, especially for "clean but query-looking" code. The rule classifier's `has_parameterized` check (`rule_classifier.py:90-91`) specifically exempts parameterized queries; without it, CodeBERT will over-flag.

### A2: Rule-only (no CodeBERT)

**Configuration:** Use only `RuleBasedClassifier.classify()`. Do not load CodeBERT weights.

```bash
python -m services.code.models.eval \
  --model none \
  --rules only \
  --corpus data/sast/eval_set.jsonl \
  --output results/ablation_a2_rules_only.json
```

**Metrics to report:**
- Detection rate (recall) per CWE class
- FPR overall
- Number of findings with zero `reasons` (code that doesn't match any regex — `rule_classifier.py:43`)

**Expected result:** Near-zero FPR (rules are conservative), but significant recall gaps for complex or obfuscated vulnerabilities that don't trigger any regex pattern. Particularly poor on CWE classes like insecure deserialization where the rules only catch 4 API calls (`rule_classifier.py:292-299`).

### A3: CodeBERT + Rule Fallback (full system)

**Configuration:** Default — CodeBERT with `RuleBasedClassifier` fallback when confidence < 0.30 and rule score > 0.30.

```bash
python -m services.code.models.eval \
  --model codebert \
  --rules fallback \
  --threshold 0.30 \
  --corpus data/sast/eval_set.jsonl \
  --output results/ablation_a3_full.json
```

**Metrics to report:** Same as A1 + A2, plus:
- Number of samples where the rule fallback activated (count of `confidence < 0.30 && rule_score >= 0.30` decisions)
- Per-sample agreement/disagreement between CodeBERT and rules

**Expected delta (what the paper claims):**
| Metric | A1 (CodeBERT) | A2 (Rules) | A3 (Full) |
|---|---|---|---|
| FPR (parameterized queries) | ~0.25 | ~0.03 | **~0.05** |
| Recall (real vulns) | ~0.88 | ~0.52 | **~0.86** |
| F1 (macro) | ~0.78 | ~0.55 | **~0.84** |

The claim: A3 preserves >97% of CodeBERT's recall while reducing FPR by ~80% on parameterized-query code.

---

## B. DAST Ablation — Certainty Classification Impact

**Component under study:** `backend/services/dast/app.py` — the `certainty_type` field.
**Key design:** Passive findings (header checks, TLS inspection, exposed metadata) are labeled `confirmed` (`dast/app.py:229`). Active findings (SQLi probes, XSS markers, IDOR, auth bypass) are labeled `inferred` with a numeric confidence (`dast/app.py:237-248`).

### B1: All findings as "inferred"

**Configuration:** Override `_build_explanation()` to always set `certainty_type = 'inferred'` and include the confidence note template for every finding, including passive checks.

```python
# Patch: force all findings through the inferred branch
def _patched_build_explanation(check_name, target_url, detection_source, **kwargs):
    result = _build_explanation(check_name, target_url, detection_source, **kwargs)
    if result:
        result['certainty_type'] = 'inferred'
        conf = kwargs.get('confidence', 0.95)
        result['confidence_note'] = (
            f'medium confidence ({conf:.0%}): automated analysis — '
            f'behavior consistent with the issue but not confirmed'
        )
    return result
```

```bash
DAST_CERTAINTY_MODE=inferred python -m pytest tests/dast/ -k ablation_b1 --tb=short
```

**Metrics to report:**
- Triage accuracy: % of findings routed to correct triage tier (`auto_flagged`, `human_review`, `ignored`) per `backend/shared/triage/engine.js:12-21`
- Mean time-to-action (MTTA) proxy: number of findings in `human_review` status (proxy for manual burden)
- Under-trust rate: findings that should be `auto_flagged` but aren't

**Expected result:** Triage engine (`engine.js:9-24`) uses numeric confidence, so high-confidence passive findings (0.95) still route correctly. But the `certainty_type` metadata is gone, so downstream dashboards lose the ability to filter by "confirmed vs inferred" — increasing cognitive load on analysts.

### B2: All findings as "confirmed"

**Configuration:** Override to always set `certainty_type = 'confirmed'` and use the `passive_fact` template, even for active probes.

```python
def _patched_build_explanation(check_name, target_url, detection_source, **kwargs):
    result = _build_explanation(check_name, target_url, detection_source, **kwargs)
    if result:
        result['certainty_type'] = 'confirmed'
        result['confidence_note'] = 'Confirmed by direct inspection — automated probe result'
    return result
```

```bash
DAST_CERTAINTY_MODE=confirmed python -m pytest tests/dast/ -k ablation_b2 --tb=short
```

**Metrics to report:**
- Over-trust incidents: count of findings where `certainty_type == 'confirmed'` but the finding was a false positive (verified via manual audit of 50 random active findings)
- Analyst false-dismissal rate: how often analysts skip confirmed findings that turn out to be benign
- Triage accuracy vs. ground truth labels

**Expected result:** Analysts develop "confirmation bias" — they trust all findings equally and stop verifying. Over-trust rate spikes. The paper can cite established HCI/security research on automation bias.

### B3: Split certainty (our approach)

**Configuration:** Default — passive = `confirmed`, active = `inferred` with numeric confidence.

```bash
DAST_CERTAINTY_MODE=split python -m pytest tests/dast/ -k ablation_b3 --tb=short
```

**Metrics to report:** Same as B1 + B2, plus:
- Precision of certainty labels (is a "confirmed" finding actually confirmed? is an "inferred" finding actually uncertain?)
- Analyst verification rate per certainty type

**Expected delta (paper claim):**
| Metric | B1 (all inferred) | B2 (all confirmed) | B3 (split) |
|---|---|---|---|
| Triage accuracy | 82% | 78% | **91%** |
| Analyst burden (human_review count) | 340 | 180 | **220** |
| Over-trust FP rate | 5% | 32% | **8%** |

The claim: Split certainty achieves the best balance between automation confidence and human verification, reducing both over-trust and under-trust.

---

## C. NIDS Ablation — Ensemble Override Impact

**Component under study:** `backend/services/network/app.py` — the `calculate_confidence()` and override logic.
**Key design:** XGBoost provides supervised classification; Isolation Forest provides unsupervised anomaly detection. When the anomaly score > 0.7, the system overrides XGBoost's prediction to `novel_attack` (`app.py:43-44`). The `calculate_confidence` function returns the anomaly score if > 0.7, otherwise the supervised confidence (`app.py:69-72`).

### C1: XGBoost only (no Isolation Forest)

**Configuration:** Remove Isolation Forest from the pipeline. `confidence = supervised_conf` always. No novel-attack override.

```bash
python -m services.network.eval \
  --models xgboost \
  --corpus data/nids/test_nsl_kdd.csv \
  --output results/ablation_c1_xgboost_only.json
```

**Metrics to report:**
- Accuracy, Precision, Recall, F1 on known attack classes (DoS, Probe, R2L, U2R)
- Detection rate on zero-day/novel attack samples (synthetic unseen attack types injected into test set)
- False Positive Rate on benign traffic

**Expected result:** High accuracy on known attacks (>95%), but zero or near-zero detection of novel attacks that aren't in the XGBoost training distribution.

### C2: Isolation Forest only (no XGBoost)

**Configuration:** Remove XGBoost from the pipeline. Classification based solely on anomaly score (threshold at 0.7 for attack vs. benign).

```bash
python -m services.network.eval \
  --models isolation_forest \
  --corpus data/nids/test_nsl_kdd.csv \
  --output results/ablation_c2_iforest_only.json
```

**Metrics to report:**
- Anomaly detection accuracy (binary: attack vs. benign)
- False Positive Rate on benign traffic
- Novel attack detection rate

**Expected result:** Reasonable novel-attack detection, but high FPR on benign traffic because Isolation Forest doesn't distinguish between normal variance and true anomalies. Per-class accuracy will be poor (no supervised signal).

### C3: XGBoost + Isolation Forest ensemble (full system)

**Configuration:** Default — both models active, override logic enabled.

```bash
python -m services.network.eval \
  --models ensemble \
  --corpus data/nids/test_nsl_kdd.csv \
  --output results/ablation_c3_full.json
```

**Metrics to report:** Same as C1 + C2, plus:
- Novel attack detection rate (where override to `novel_attack` fired correctly)
- Override accuracy: % of `novel_attack` overrides that were true novel attacks (vs. false overrides of known attacks)
- Confidence calibration: reliability diagram of predicted vs. observed accuracy

**Expected delta (paper claim):**
| Metric | C1 (XGB) | C2 (IF) | C3 (Ensemble) |
|---|---|---|---|
| Known attack accuracy | 96.2% | 71.3% | **95.8%** |
| Novel attack detection | 2.1% | 68.4% | **72.6%** |
| FPR (benign traffic) | 1.8% | 14.2% | **2.9%** |

The claim: The ensemble preserves XGBoost's accuracy on known traffic while inheriting Isolation Forest's ability to detect novel attacks, with minimal FPR increase.

---

## D. Triage Ablation — Confidence Threshold Impact

**Component under study:** `backend/shared/triage/engine.js`
**Key design:** Two thresholds — `auto_flag` at 0.90 and `human_review` at 0.50 (`engine.js:4-5`). Findings ≥ 0.90 are auto-flagged (critical/high), 0.50–0.90 go to human review, < 0.50 are ignored. The `classifyConfirmed()` path (`engine.js:26-38`) bypasses numeric thresholds and maps severity strings directly.

### D1: Threshold = 0.50 (low threshold)

**Configuration:** Set `auto_flag = 0.50`, `human_review = 0.10`. Most findings get auto-flagged.

```javascript
const engine = new TriageEngine({ auto_flag: 0.50, human_review: 0.10 });
```

```bash
TRIAGE_AUTO_FLAG=0.50 TRIAGE_HUMAN_REVIEW=0.10 \
  node tests/triage/ablation_d1.js --corpus data/triage/test_set_500.json
```

**Metrics to report:**
- Auto-flagged count and % of total
- False auto-flag rate: findings that were auto-flagged but are false positives (validated against ground truth)
- Human review queue size
- Critical findings missed (should be auto-flagged but weren't)

**Expected result:** Flood of false auto-flags. Analysts overwhelmed. High noise drowns real findings.

### D2: Threshold = 0.95 (high threshold)

**Configuration:** Set `auto_flag = 0.95`, `human_review = 0.80`. Very few findings get auto-flagged.

```javascript
const engine = new TriageEngine({ auto_flag: 0.95, human_review: 0.80 });
```

```bash
TRIAGE_AUTO_FLAG=0.95 TRIAGE_HUMAN_REVIEW=0.80 \
  node tests/triage/ablation_d2.js --corpus data/triage/test_set_500.json
```

**Metrics to report:**
- Auto-flagged count
- Missed critical findings: real critical vulns with confidence 0.90–0.94 that now fall to `human_review`
- Mean time-to-remediation (proxy: queue depth × estimated review time)

**Expected result:** Almost nothing auto-flagged. Critical findings stuck in human review queue. Slower response to real threats.

### D3: Our dual threshold (default)

**Configuration:** Default — `auto_flag = 0.90`, `human_review = 0.50`.

```bash
TRIAGE_AUTO_FLAG=0.90 TRIAGE_HUMAN_REVIEW=0.50 \
  node tests/triage/ablation_d3.js --corpus data/triage/test_set_500.json
```

**Metrics to report:** Same as D1 + D2, plus:
- Calibration error: |predicted confidence - empirical detection rate| across bins
- Sweet-spot analysis: % of findings in each triage tier

**Expected delta (paper claim):**
| Metric | D1 (0.50) | D2 (0.95) | D3 (dual) |
|---|---|---|---|
| Auto-flagged findings | 387 (77%) | 12 (2%) | **94 (19%)** |
| False auto-flag rate | 41% | 0% | **3%** |
| Missed critical findings | 0 | 23 | **2** |
| Human review queue | 113 | 488 | **406** |

The claim: The dual threshold achieves <5% false auto-flag rate while missing <1% of critical findings — a Pareto-optimal operating point compared to either extreme.

---

## E. Result Presentation

### Tables for the Paper

**Table 1 — SAST Ablation (Section A)**
```
| Configuration         | FPR (param. queries) | Recall | F1 (macro) |
|-----------------------|----------------------|--------|------------|
| A1: CodeBERT only     | X.XX                 | X.XX   | X.XX       |
| A2: Rules only        | X.XX                 | X.XX   | X.XX       |
| A3: Full system       | X.XX                 | X.XX   | X.XX       |
```

**Table 2 — DAST Ablation (Section B)**
```
| Configuration            | Triage Accuracy | Over-trust FP | Analyst Burden |
|--------------------------|-----------------|---------------|----------------|
| B1: All inferred         | XX%             | XX%           | XXX            |
| B2: All confirmed        | XX%             | XX%           | XXX            |
| B3: Split certainty      | XX%             | XX%           | XXX            |
```

**Table 3 — NIDS Ablation (Section C)**
```
| Configuration       | Known Acc. | Novel Det. | FPR  |
|---------------------|------------|------------|------|
| C1: XGBoost only    | XX.X%      | X.X%       | X.X% |
| C2: IsoForest only  | XX.X%      | XX.X%      | XX.X%|
| C3: Ensemble        | XX.X%      | XX.X%      | X.X% |
```

**Table 4 — Triage Ablation (Section D)**
```
| Configuration        | Auto-flagged | FP Rate | Missed Critical |
|----------------------|--------------|---------|-----------------|
| D1: Threshold=0.50   | XXX (XX%)    | XX%     | X               |
| D2: Threshold=0.95   | XX (X%)      | X%      | XX              |
| D3: Dual threshold   | XX (XX%)     | X%      | X               |
```

### Figures

1. **Bar chart** per ablation: grouped bars showing the 3 configurations side-by-side for the primary metric (recall for A, triage accuracy for B, novel detection for C, false auto-flag rate for D).
2. **ROC curve** for C3 ensemble vs. C1 XGBoost-only, showing the AUC improvement.
3. **Calibration plot** for D3, with reliability diagrams for each threshold setting.
4. **Sankey diagram** showing finding flow through triage tiers under D1, D2, D3.

---

## F. Statistical Significance

For each ablation comparison:
- **McNemar's test** for paired classification outcomes (A1 vs A3, C1 vs C3)
- **95% bootstrap confidence intervals** (10,000 resamples) for all reported metrics
- **Effect size** via Cohen's h for proportion differences (FPR, recall)
- Report p-values in table footnotes; bold results where p < 0.01

---

## G. Execution Order

| Phase | Experiment | Prerequisite | Estimated Time |
|-------|-----------|--------------|----------------|
| 1 | A1, A2, A3 | SAST corpus prepared | 4 hours |
| 2 | C1, C2, C3 | NIDS corpus prepared | 6 hours |
| 3 | B1, B2, B3 | DAST target apps running | 8 hours |
| 4 | D1, D2, D3 | Triage test set labeled | 1 hour |
| 5 | Statistical analysis + figures | All above complete | 3 hours |

**Total estimated time:** ~22 hours of compute + analysis.

---

## H. Checklist Before Running

- [ ] Verify all test corpora exist and are checksummed
- [ ] Confirm Docker images build cleanly
- [ ] Run each ablation with `--dry-run` first to validate config
- [ ] Ensure results directory is clean (no stale data from prior runs)
- [ ] Log git commit hash for each experiment run
