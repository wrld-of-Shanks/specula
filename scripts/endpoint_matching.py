#!/usr/bin/env python3
"""Per-endpoint (target, endpoint, check_type) matching over saved DAST results.

Recomputes both check_type-level and endpoint-level metrics from the archived
{target}_results.json files produced by evaluate_dast.py, so the two
granularities can be reported side by side without re-running any scans.

Writes dast_eval_results/evaluation_summary_endpoint.json and prints a table.

Usage:  python3 scripts/endpoint_matching.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evaluate_dast as ed

RESULTS_DIR = os.path.join(ed.BASE_DIR, "scripts", "dast_eval_results")
TARGETS = ["dvwa", "juice_shop", "webgoat", "bwapp", "mutillidae"]


def agg_metrics(totals):
    p = totals["tp"] / (totals["tp"] + totals["fp"]) if (totals["tp"] + totals["fp"]) else 0.0
    r = totals["tp"] / (totals["tp"] + totals["fn"]) if (totals["tp"] + totals["fn"]) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return {"tp": totals["tp"], "fp": totals["fp"], "fn": totals["fn"],
            "precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4)}


def main():
    per_target = {}
    agg = {"check_type": {"horus": {"tp": 0, "fp": 0, "fn": 0}, "zap": {"tp": 0, "fp": 0, "fn": 0}},
           "endpoint": {"horus": {"tp": 0, "fp": 0, "fn": 0}, "zap": {"tp": 0, "fp": 0, "fn": 0}}}

    hdr = f"{'target':<11} {'match':<10} {'tool':<5} {'GT':>3} {'find':>5} {'TP':>3} {'FP':>3} {'FN':>3} {'P':>7} {'R':>7} {'F1':>7}"
    print(hdr)
    print("-" * len(hdr))
    for t in TARGETS:
        with open(os.path.join(RESULTS_DIR, f"{t}_results.json")) as f:
            d = json.load(f)
        gt = ed.GROUND_TRUTH[t]["vulnerabilities"]
        name = ed.GROUND_TRUTH[t]["name"]
        entry = {}
        for tool in ("horus", "zap"):
            ct = ed.compute_metrics(d[tool]["findings"], gt, name)
            ep = ed.compute_endpoint_metrics(d[tool]["findings"], gt, name)
            for k in agg["check_type"][tool]:
                agg["check_type"][tool][k] += ct[k]
            for k in agg["endpoint"][tool]:
                agg["endpoint"][tool][k] += ep[k]
            entry[tool] = {"check_type": {k: ct[k] for k in ("tp", "fp", "fn", "precision", "recall", "f1")},
                           "endpoint": {k: ep[k] for k in ("tp", "fp", "fn", "precision", "recall", "f1")},
                           "endpoint_units": {"tp": ep["tp_units"], "fp": ep["fp_units"], "fn": ep["fn_units"]}}
            for label, m in (("check_type", ct), ("endpoint", ep)):
                print(f"{t:<11} {label:<10} {tool:<5} {m.get('gt_count', m.get('gt_unit_count')):>3} "
                      f"{m.get('tool_finding_count', m.get('tool_unit_count')):>5} {m['tp']:>3} {m['fp']:>3} "
                      f"{m['fn']:>3} {m['precision']:>7.3f} {m['recall']:>7.3f} {m['f1']:>7.3f}")
        per_target[t] = entry

    for tool in ("horus", "zap"):
        for label in ("check_type", "endpoint"):
            a = agg_metrics(agg[label][tool])
            print(f"{'AGG':<11} {label:<10} {tool:<5} {'':>3} {'':>5} {a['tp']:>3} {a['fp']:>3} {a['fn']:>3} "
                  f"{a['precision']:>7.3f} {a['recall']:>7.3f} {a['f1']:>7.3f}")

    out = {
        "timestamp": None,
        "targets": TARGETS,
        "aggregate": {tool: {"check_type": agg_metrics(agg["check_type"][tool]),
                             "endpoint": agg_metrics(agg["endpoint"][tool])} for tool in ("horus", "zap")},
        "per_target": per_target,
    }
    import datetime
    out["timestamp"] = datetime.datetime.now().isoformat()
    path = os.path.join(RESULTS_DIR, "evaluation_summary_endpoint.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nsaved {path}")


if __name__ == "__main__":
    main()
