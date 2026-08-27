# Evaluation Documentation

## Overview

This document contains evaluation metrics for both the Network Anomaly Detection and Code Vulnerability Detection modules.

---

## Module 1 — Network Anomaly Detection

### Dataset: NSL-KDD

### Model A: XGBoost Classifier

**Training Configuration:**
- Objective: multi:softprob (multi-class log-loss)
- max_depth: 5
- learning_rate: 0.1
- n_estimators: 200
- early_stopping_rounds: 20
- scale_pos_weight: Enabled for class imbalance

**Evaluation Metrics:**

| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|--------|----------|---------|
| normal | - | - | - | - |
| neptune | - | - | - | - |
| smurf | - | - | - | - |
| back | - | - | - | - |
| satan | - | - | - | - |
| ipsweep | - | - | - | - |
| portsweep | - | - | - | - |
| nmap | - | - | - | - |
| guess_passwd | - | - | - | - |
| buffer_overflow | - | - | - | - |
| **Macro Avg** | - | - | - | - |
| **Weighted Avg** | - | - | - | - |

**Log Loss:** - (lower is better)

**False Positive Rate on Normal Traffic:** -% (headline metric)

### Model B: Isolation Forest (Unsupervised)

**Training Configuration:**
- contamination: 0.1
- n_estimators: 100
- Trained only on normal-labeled traffic

**Evaluation Metrics:**
- Anomaly Detection Rate (on novel attacks): -%
- False Positive Rate: -%
- Average Anomaly Score for normal traffic: -
- Average Anomaly Score for attack traffic: -

### Comparison: Supervised vs. Unsupervised

| Metric | XGBoost | Isolation Forest |
|--------|---------|------------------|
| Recall on known attacks | - | - |
| Recall on novel attacks | - | - |
| False positive rate | - | - |
| Inference time (ms) | - | - |

**Key Findings:**
- [Document findings here]
- [Note where models struggle]
- [Identify edge cases]

---

## Module 2 — Code Vulnerability Detection

### Classifier: Fine-tuned CodeBERT

**Training Configuration:**
- Base model: microsoft/codebert-base
- Classes: 6 (not_vulnerable + 5 CWE types)
- Frozen layers: Lower layers frozen
- Fine-tuned layers: Top 2-4 layers + classification head
- Loss: Weighted Cross-Entropy
- Learning rate: 2e-5 to 5e-5
- Batch size: 16
- Epochs: 5

**Evaluation Metrics:**

| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|--------|----------|---------|
| not_vulnerable | - | - | - | - |
| sql_injection (CWE-89) | - | - | - | - |
| xss (CWE-79) | - | - | - | - |
| hardcoded_credentials (CWE-798) | - | - | - | - |
| command_injection (CWE-78) | - | - | - | - |
| path_traversal (CWE-22) | - | - | - | - |
| **Macro F1** | - | - | - | - |

**Top-2 CWE Accuracy:** -%

### Fix Generator: Fine-tuned CodeT5

**Training Configuration:**
- Base model: Salesforce/codet5-base
- Training data: Bugs2Fix, CVEfixes (before/after commit pairs)
- Learning rate: 3e-5
- Batch size: 8
- Epochs: 3
- Beam search width: 5

**Evaluation Metrics:**
- BLEU Score: -
- Exact Match Rate: -
- Average fix length: -
- Time to generate fix (ms): -

### Manual Quality Review (10-15 samples)

| Sample | Vulnerability | Fix Correct? | Quality Notes |
|--------|---------------|--------------|---------------|
| 1 | - | - | - |
| 2 | - | - | - |
| 3 | - | - | - |
| ... | ... | ... | ... |

**Key Findings:**
- [Document where classifier performs well]
- [Document where classifier struggles]
- [Note false positives/negatives]
- [Assess fix quality honestly]

---

## Honest Assessment

### Strengths
- [List what works well]
- [Note high-performing areas]

### Weaknesses
- [List where models struggle]
- [Note edge cases and failure modes]
- [Document limitations honestly]

### Future Improvements
- [List potential enhancements]
- [Note data quality issues]
- [Suggest architectural changes]

---

## Reproducibility

To reproduce these results:

```bash
# Network Module
cd backend/services/network
python -c "from models.xgboost_model import XGBoostClassifier; m = XGBoostClassifier(); m.train('data/nsl-kdd.csv')"

# Code Module
cd backend/services/code
python -c "from models.codebert_classifier import CodeBERTClassifier; m = CodeBERTClassifier(); m.train('data/cve_dataset.csv')"
```

**Environment:**
- Python: 3.x
- PyTorch: 2.x
- Transformers: 4.35.x
- XGBoost: 2.0.x
- scikit-learn: 1.3.x
