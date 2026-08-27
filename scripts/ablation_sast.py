#!/usr/bin/env python3
"""
SAST Ablation Study — Specula Code Vulnerability Classifier

Configurations:
  A1: Rule-based classifier ONLY (no ML model)
  A2: CodeBERT model ONLY (no rule fallback)
  A3: Full system (CodeBERT + rule fallback)

Also tests parameterized query false-positive rates.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'services', 'code'))

from collections import defaultdict, Counter
from models.rule_classifier import RuleBasedClassifier, VULNERABILITY_CLASSES, CWE_MAPPING

# ---------------------------------------------------------------------------
# Import test data from evaluate_code_classifier (reuse build_test_suite)
# ---------------------------------------------------------------------------
from evaluate_code_classifier import (
    build_test_suite,
    SQL_INJECTION_SAMPLES, SAFE_SQL_SAMPLES,
    XSS_SAMPLES, SAFE_XSS_SAMPLES,
    CMD_INJECTION_SAMPLES, SAFE_CMD_SAMPLES,
    PATH_TRAVERSAL_SAMPLES, SAFE_PATH_SAMPLES,
    HARDCODED_CRED_SAMPLES, SAFE_CRED_SAMPLES,
    INSECURE_DESERIALIZATION_SAMPLES, SAFE_DESERIALIZATION_SAMPLES,
    GENERIC_SAFE_SAMPLES,
)

# ---------------------------------------------------------------------------
# Try loading CodeBERT model
# ---------------------------------------------------------------------------
CODEBERT_AVAILABLE = False
codebert_model = None
codebert_tokenizer = None

def try_load_codebert():
    global CODEBERT_AVAILABLE, codebert_model, codebert_tokenizer
    try:
        import torch
        from transformers import RobertaTokenizer, RobertaForSequenceClassification

        # Try the current path first, then the old path
        base = os.path.join(os.path.dirname(__file__), '..', 'services', 'code', 'models', 'weights')
        candidates = [
            os.path.join(base, 'codebert_classifier'),
            os.path.join(base, 'codebert_classifier_old'),
        ]
        loaded_path = None
        for p in candidates:
            if os.path.exists(p) and os.path.isfile(os.path.join(p, 'model.safetensors' if not any(
                f.endswith('.bin') for f in os.listdir(p) if os.path.isfile(os.path.join(p, f))
            ) else 'pytorch_model.bin')):
                loaded_path = p
                break
            elif os.path.exists(p):
                # Check for any model file
                files = os.listdir(p)
                has_model = any(f.startswith('model.') for f in files)
                if has_model:
                    loaded_path = p
                    break

        if loaded_path is None:
            print("  [!] No CodeBERT weights found. Skipping A2.")
            return

        print(f"  [*] Loading CodeBERT from: {os.path.abspath(loaded_path)}")
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        codebert_tokenizer = RobertaTokenizer.from_pretrained(loaded_path)
        codebert_model = RobertaForSequenceClassification.from_pretrained(loaded_path).to(device)
        codebert_model.eval()
        CODEBERT_AVAILABLE = True
        print(f"  [+] CodeBERT loaded successfully on {device}")

    except Exception as e:
        print(f"  [!] Failed to load CodeBERT: {e}")
        CODEBERT_AVAILABLE = False


def codebert_classify_only(code):
    """CodeBERT inference ONLY — no rule fallback."""
    import torch
    device = next(codebert_model.parameters()).device

    encoding = codebert_tokenizer(
        code, add_special_tokens=True, max_length=512,
        padding='max_length', truncation=True,
        return_attention_mask=True, return_tensors='pt'
    )

    input_ids = encoding['input_ids'].to(device)
    attention_mask = encoding['attention_mask'].to(device)

    with torch.no_grad():
        outputs = codebert_model(input_ids=input_ids, attention_mask=attention_mask)

    probabilities = torch.softmax(outputs.logits, dim=1)[0]
    predicted_class = torch.argmax(probabilities).item()
    confidence = probabilities[predicted_class].item()

    top_predictions = []
    sorted_probs = torch.argsort(probabilities, descending=True)
    for idx in sorted_probs[:3]:
        cls_name = VULNERABILITY_CLASSES[idx.item()]
        top_predictions.append({
            'class': cls_name,
            'cwe': CWE_MAPPING[cls_name],
            'confidence': probabilities[idx].item()
        })

    return {
        'prediction': VULNERABILITY_CLASSES[predicted_class],
        'cwe': CWE_MAPPING[VULNERABILITY_CLASSES[predicted_class]],
        'confidence': confidence,
        'top_predictions': top_predictions,
    }


def full_system_classify(code):
    """Full system: CodeBERT with rule fallback (normal behavior)."""
    if CODEBERT_AVAILABLE and codebert_model is not None:
        return codebert_classify_only(code)
    else:
        return RuleBasedClassifier().classify(code)


# ---------------------------------------------------------------------------
# Metric computation
# ---------------------------------------------------------------------------

def compute_metrics(y_true, y_pred, classes):
    tp = defaultdict(int)
    fp = defaultdict(int)
    fn = defaultdict(int)

    for true, pred in zip(y_true, y_pred):
        if true == pred:
            tp[true] += 1
        else:
            fn[true] += 1
            fp[pred] += 1

    metrics = {}
    for cls in classes:
        p = tp[cls] / (tp[cls] + fp[cls]) if (tp[cls] + fp[cls]) > 0 else 0.0
        r = tp[cls] / (tp[cls] + fn[cls]) if (tp[cls] + fn[cls]) > 0 else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        support = tp[cls] + fn[cls]
        metrics[cls] = {'precision': p, 'recall': r, 'f1': f1, 'support': support}

    accuracy = sum(tp.values()) / len(y_true) if y_true else 0.0

    total_safe = sum(1 for t in y_true if t == 'not_vulnerable')
    fp_on_safe = sum(1 for t, p in zip(y_true, y_pred) if t == 'not_vulnerable' and p != 'not_vulnerable')
    fp_rate = fp_on_safe / total_safe if total_safe > 0 else 0.0

    return {
        'accuracy': accuracy,
        'per_class': metrics,
        'fp_on_safe': fp_on_safe,
        'total_safe': total_safe,
        'fp_rate': fp_rate,
    }


# ---------------------------------------------------------------------------
# Parameterized query false-positive test
# ---------------------------------------------------------------------------

PARAMETERIZED_QUERIES = [
    'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    'db.execute("SELECT * FROM users WHERE name = %s AND email = %s", (name, email))',
    'cursor.execute("INSERT INTO logs (msg) VALUES (%s)", (message,))',
    'db.execute("UPDATE users SET email = %s WHERE id = %s", (email, uid))',
    'cursor.execute("DELETE FROM sessions WHERE token = %s", (token,))',
    'db.execute("SELECT * FROM products WHERE category = %s ORDER BY name", (category,))',
    'cursor.execute("INSERT INTO audit (action, uid) VALUES (%s, %s)", (action, uid))',
    'db.execute("UPDATE orders SET status = %s WHERE id = %s", (status, oid))',
    'cursor.execute("SELECT * FROM payments WHERE amount > %s", (min_amt,))',
    'db.execute("DELETE FROM cache WHERE key = %s", (key,))',
    'ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setInt(1, id);',
    'stmt = conn.prepareStatement("SELECT * FROM t WHERE c = ? AND d = ?");',
    'String q = "SELECT * FROM orders WHERE name = ?"; ps.setString(1, name);',
    '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id"); $stmt->execute([":id" => $id]);',
    'db.query("SELECT * FROM users WHERE id = $1", [userId])',
    'pool.query("SELECT * FROM orders WHERE name = $1", [name])',
    'User.where(id: user_id).first',
    'db.Query("SELECT * FROM users WHERE id = $1", userId)',
    'session.query(User).filter(User.id == user_id).first()',
    'User.query.filter_by(username=username).first()',
]


def run_parameterized_query_test(classify_fn, label):
    """Test false positives on parameterized queries."""
    fp_count = 0
    results = []
    for i, code in enumerate(PARAMETERIZED_QUERIES):
        pred = classify_fn(code)
        is_fp = pred != 'not_vulnerable'
        fp_count += int(is_fp)
        results.append((i + 1, code[:70], pred, is_fp))

    return fp_count, results


# ---------------------------------------------------------------------------
# Paper-quality table printing
# ---------------------------------------------------------------------------

def print_section(title):
    w = 80
    print()
    print('=' * w)
    print(f'  {title}')
    print('=' * w)


def print_per_class_table(all_metrics, config_names):
    """Print a comparison table of per-class metrics across configs."""
    classes = VULNERABILITY_CLASSES
    abbrevs = {
        'not_vulnerable': 'SAFE',
        'sql_injection': 'SQLi',
        'xss': 'XSS',
        'hardcoded_credentials': 'CRDS',
        'command_injection': 'CMDi',
        'path_traversal': 'PTRV',
        'insecure_deserialization': 'DESER',
    }

    print()
    print(f"{'':>12s}", end='')
    for name in config_names:
        print(f"{'  ' + name:>24s}", end='')
    print()
    print('-' * (12 + 24 * len(config_names)))

    for metric in ['precision', 'recall', 'f1']:
        for cls in classes:
            abbr = abbrevs[cls]
            print(f"{abbr:>8s} {metric[:1]:>3s}", end='')
            for m in all_metrics:
                val = m['per_class'][cls][metric]
                print(f"{val:>24.3f}", end='')
            print()
        print('-' * (12 + 24 * len(config_names)))

    # Macro averages
    for metric in ['precision', 'recall', 'f1']:
        print(f"{'Macro':>8s} {metric[:1]:>3s}", end='')
        for m in all_metrics:
            vals = [m['per_class'][c][metric] for c in classes if m['per_class'][c]['support'] > 0]
            avg = sum(vals) / len(vals) if vals else 0.0
            print(f"{avg:>24.3f}", end='')
        print()

    # Accuracy & FP rate
    print('-' * (12 + 24 * len(config_names)))
    print(f"{'Accuracy':>12s}", end='')
    for m in all_metrics:
        print(f"{m['accuracy']:>24.3f}", end='')
    print()
    print(f"{'FP rate (safe)':>12s}", end='')
    for m in all_metrics:
        print(f"{m['fp_rate']:>23.1%}", end='')
    print()
    print(f"{'FP count':>12s}", end='')
    for m in all_metrics:
        print(f"{str(m['fp_on_safe']) + '/' + str(m['total_safe']):>24s}", end='')
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print_section("SPECULA SAST ABLATION STUDY")
    print()
    print("Loading components...")

    # Load CodeBERT
    try_load_codebert()

    # Build test suite
    suite = build_test_suite()
    print(f"  [*] Test suite: {len(suite)} samples")

    y_true = [s['expected'] for s in suite]
    codes = [s['code'] for s in suite]
    active_classes = sorted(set(y_true))

    # Define classify functions for each config
    rule_only = RuleBasedClassifier()
    configs = [
        ('A1: Rules', lambda code: rule_only.classify(code)['prediction']),
    ]

    if CODEBERT_AVAILABLE:
        configs.append(('A2: CodeBERT', lambda code: codebert_classify_only(code)['prediction']))
        configs.append(('A3: Full', lambda code: full_system_classify(code)['prediction']))
    else:
        print("  [!] A2 skipped — CodeBERT weights unavailable")
        configs.append(('A3: Rules', lambda code: rule_only.classify(code)['prediction']))
        print("  [i] A3 degraded to rule-only (no ML model loaded)")

    # ---- Run each config ----
    all_metrics = []
    all_preds = []

    for name, classify_fn in configs:
        preds = []
        for code in codes:
            preds.append(classify_fn(code))
        all_preds.append(preds)
        metrics = compute_metrics(y_true, preds, active_classes)
        all_metrics.append(metrics)

    # ---- Print per-class comparison table ----
    print_section("TABLE 1: Per-Class Classification Metrics")
    config_names = [c[0] for c in configs]
    print_per_class_table(all_metrics, config_names)

    # ---- Print detailed per-config breakdown ----
    for idx, (name, _) in enumerate(configs):
        print_section(f"DETAILED RESULTS — {name}")
        m = all_metrics[idx]
        preds = all_preds[idx]

        print(f"\n  Overall Accuracy: {m['accuracy']:.3f} ({int(m['accuracy'] * len(y_true))}/{len(y_true)})")
        print(f"  FP on safe code:  {m['fp_on_safe']}/{m['total_safe']} = {m['fp_rate']:.1%}")
        print()
        print(f"  {'Class':30s} {'Prec':>8s} {'Rec':>8s} {'F1':>8s} {'Support':>8s}")
        print(f"  {'-'*62}")
        for cls in active_classes:
            c = m['per_class'][cls]
            print(f"  {cls:30s} {c['precision']:8.3f} {c['recall']:8.3f} {c['f1']:8.3f} {c['support']:8d}")

        # Show misclassifications
        misses = [(t, p, codes[i][:80]) for i, (t, p) in enumerate(zip(y_true, preds)) if t != p]
        if misses:
            print(f"\n  Misclassifications ({len(misses)}):")
            for t, p, code_snip in misses:
                print(f"    {t:30s} -> {p:30s}  |  {code_snip}")

    # ---- Confusion matrices ----
    print_section("CONFUSION MATRICES")
    class_abbrevs = {
        'not_vulnerable': 'SAFE', 'sql_injection': 'SQLi', 'xss': 'XSS',
        'hardcoded_credentials': 'CRDS', 'command_injection': 'CMDi',
        'path_traversal': 'PTRV', 'insecure_deserialization': 'DESER',
    }

    for idx, (name, _) in enumerate(configs):
        print(f"\n  --- {name} ---")
        preds = all_preds[idx]

        conf = defaultdict(lambda: defaultdict(int))
        for t, p in zip(y_true, preds):
            conf[t][p] += 1

        abbrs = [class_abbrevs[c] for c in active_classes]
        true_pred_label = 'True\\Pred'
        hdr = f"  {true_pred_label:>8s}" + "".join(f"{a:>8s}" for a in abbrs)
        print(hdr)
        print("  " + "-" * (8 + 8 * len(abbrs)))
        for true_cls in active_classes:
            row = f"  {class_abbrevs[true_cls]:>8s}"
            for pred_cls in active_classes:
                row += f"{conf[true_cls][pred_cls]:>8d}"
            print(row)

    # ---- Parameterized query FP test ----
    print_section("TABLE 2: Parameterized Query False-Positive Test")
    print(f"\n  {len(PARAMETERIZED_QUERIES)} parameterized queries (should ALL be 'not_vulnerable')\n")

    param_table = []
    for idx, (name, classify_fn) in enumerate(configs):
        fp_count, details = run_parameterized_query_test(classify_fn, name)
        param_table.append((name, fp_count, details))

    print(f"  {'Config':20s} {'FP Rate':>10s} {'FP Count':>12s}")
    print(f"  {'-'*44}")
    for name, fp_count, _ in param_table:
        rate = fp_count / len(PARAMETERIZED_QUERIES)
        print(f"  {name:20s} {rate:>9.1%} {fp_count:>5d}/{len(PARAMETERIZED_QUERIES):<5d}")

    # Show which queries each config gets wrong
    for name, fp_count, details in param_table:
        if fp_count > 0:
            print(f"\n  {name} — {fp_count} false positives:")
            for idx_num, code_snip, pred, is_fp in details:
                if is_fp:
                    print(f"    #{idx_num:2d} predicted={pred:25s} | {code_snip}")

    # ---- Summary for paper ----
    print_section("TABLE 3: Summary for Paper")

    print(f"\n  {'Metric':30s}", end='')
    for name, _ in configs:
        print(f"{'  ' + name:>22s}", end='')
    print()
    print(f"  {'-' * (30 + 22 * len(configs))}")

    def macro_for(metric_key):
        def fn(m):
            vals = [m['per_class'][c][metric_key] for c in active_classes if m['per_class'][c]['support'] > 0]
            return f"{sum(vals) / max(1, len(vals)):.3f}"
        return fn

    rows = [
        ('Overall Accuracy', lambda m: f"{m['accuracy']:.1%}"),
        ('Macro Precision', macro_for('precision')),
        ('Macro Recall', macro_for('recall')),
        ('Macro F1', macro_for('f1')),
        ('FP Rate (safe code)', lambda m: f"{m['fp_rate']:.1%}"),
        ('FP Count / Total Safe', lambda m: f"{m['fp_on_safe']}/{m['total_safe']}"),
    ]

    for label, fn in rows:
        print(f"  {label:30s}", end='')
        for m in all_metrics:
            print(f"{fn(m):>22s}", end='')
        print()

    # Param query row
    print(f"  {'Param Query FP Rate':30s}", end='')
    for _, fp_count, _ in param_table:
        rate = fp_count / len(PARAMETERIZED_QUERIES)
        print(f"{rate:>21.1%}", end='')
    print()

    print(f"\n  Test samples: {len(y_true)}")
    print(f"  Vulnerability classes: {len(VULNERABILITY_CLASSES)}")
    print(f"  Class distribution: {dict(Counter(y_true))}")
    print()
    print_section("END OF ABLATION STUDY")


if __name__ == '__main__':
    main()
