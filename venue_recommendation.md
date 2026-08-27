# Venue Guidance — arXiv DAST-only preprint vs. Workshop Submission

*Companion to `paper1.md`. Status: recommendation only, not part of the paper body.*

## Bottom line

Post a **DAST-only preprint to arXiv (cs.CR) now**. Do **not** submit the full multi-engine system paper to a workshop or conference until the SAST and NIDS claims carry real-world evidence.

## Evidence strength assessment (what the paper actually supports today)

| Chapter | Evidence | Submission-ready? |
|---------|----------|-------------------|
| DAST | 5 targets, 76 GT instances (68 endpoint units), ZAP 2.17.0 head-to-head under a standard unauthenticated baseline, per-endpoint + check_type-level metrics, reproducible harness, honest limitations (no auth crawling, SPA gap, endpoint-collapse caveat) | **Yes** — self-contained methods + reproducibility story |
| NIDS | XGBoost on NSL-KDD: 86.70% held-out accuracy | Partial — benchmark is dated; 13.5% train/test gap |
| SAST | CodeBERT 99.6% **validation** accuracy on a 4,239-sample **synthetic** corpus | **No** — no real-code (Juliet/SARD/CVE) evaluation yet |

The paper's strongest, most defensible empirical contribution is the comparative DAST evaluation. A workshop/full-paper submission that headlines the platform ("Specula/HORUS") will be critiqued on NIDS/SAST claims that are not yet supported; the DAST chapter alone is too thin for a full paper.

## Recommended sequence

1. **Now — arXiv (cs.CR), DAST-only preprint.** Title and scope the preprint as a comparative DAST evaluation methodology (not a full platform paper). Include:
   - All of Section 11 (check_type-level + per-endpoint tables)
   - The ZAP baseline framing (§11.6): standard unauthenticated configuration, no credential injection, no Ajax Spider
   - The reproducibility evidence: `evaluation_summary.json`, `evaluation_summary_endpoint.json`, the `dast-eval-reproducible-2026-07-31` tag, the 3× reproduction note
   - The honest-limitation framing from Section 12 items 6, 7, 8, 9, 10
2. **Follow-up — workshop submission of the full-system paper.** Target applied-AI-security workshops, which reward evaluation methodology and reproducibility:
   - **AISec @ CCS**
   - **DeepS&P @ IEEE S&P**
   - **WOSOC**
   Submit once **future work items 2 and 7** land:
   - CodeBERT evaluated on Juliet/SARD/real GitHub advisories (turns SAST into real evidence)
   - DAST harness with authenticated crawling + JS-rendered endpoint discovery (closes the injection-detection gap)
   With those, the multi-engine story (NIDS + SAST + DAST unified behind one pipeline) is publishable.

## Risks to avoid

- **Headlining the platform with unsupported claims** — reviewers will attack NIDS/SAST numbers (dated benchmark, synthetic-only accuracy). Keep the DAST preprint scoped to DAST.
- **Presenting 99.6% as a test result** — it is synthetic-validation accuracy; the caveat must stay attached (already done in paper1.md).
- **Comparisons framed as "HORUS beats ZAP"** — the paper correctly frames ZAP's run as the standard unauthenticated quick-external-scan baseline; any external description must preserve that scope to stay defensible.
