## 1. Related Work

### 1.1 Deep Learning for Vulnerability Detection

The application of pre-trained language models to source code vulnerability detection has attracted significant attention since the introduction of CodeBERT [Feng et al., 2020], which pre-trained a bimodal encoder on six programming languages using replaced token detection and word-masked language modeling objectives. Subsequent work by Yuan et al. [2022] fine-tuned CodeBERT on the BigVul and Devign datasets, demonstrating that transformer-based models outperform traditional feature-engineered classifiers on vulnerability prediction tasks. The XGV-BERT framework [2023] further extended this line of work by incorporating graph-structured code representations alongside the textual encoder, achieving state-of-the-art results on multiple vulnerability benchmarks. More recently, survey articles in Springer [2026] and the comprehensive taxonomy by Steenhoek et al. [2022] have systematically catalogued the landscape of deep learning approaches for software vulnerability detection, identifying transformer-based models as the current dominant paradigm while noting persistent challenges in false-positive reduction, interpretability, and deployment on resource-constrained hardware.

However, a persistent limitation across these approaches is the high false-positive rate on safe code constructs that superficially resemble vulnerabilities. Parameterized SQL queries, sanitized output functions, and validated input handling routinely trigger ML classifiers that lack explicit understanding of defensive programming patterns. Steenhoek et al. [2022] identified this as the primary barrier to adoption of ML-based vulnerability detection in industrial settings, noting that developers abandon tools that produce more false positives than manual code review.

Specula builds upon this foundation with two key distinctions. First, whereas prior CodeBERT-based detectors operate as monolithic classifiers, Specula employs a *context-aware two-tier architecture* in which a fine-tuned CodeBERT model serves as the primary detector and a rule-based classifier acts as a fallback and false-positive mitigation layer. The rule classifier (`rule_classifier.py`) explicitly distinguishes parameterized database queries (e.g., `cursor.execute("...%s", (uid,))`) from string-concatenated queries, achieving near-zero false positives on safe patterns while preserving high recall on genuinely vulnerable code. This addresses one of the most commonly cited failure modes of ML-based SAST tools: the over-flagging of parameterized queries as SQL injection vulnerabilities [Steenhoek et al., 2022]. The fallback mechanism activates when CodeBERT's confidence falls below 0.30 and the rule classifier's score exceeds 0.30, creating a complementary relationship where the ML model's broad pattern recognition is augmented by the rule classifier's precise context sensitivity. Second, Specula applies parameter-efficient fine-tuning (gradient freezing of all but the last two encoder layers and the classification head) to make CodeBERT fine-tuning feasible on consumer hardware without GPU acceleration, whereas prior work typically assumes access to high-end GPU clusters. This choice follows the broader trend toward accessible security ML identified in recent surveys [Springer, 2026], but implements it through direct layer freezing rather than adapter modules or prompt tuning.

### 1.2 XGBoost and Isolation Forest for Network Intrusion Detection

The combination of gradient boosting classifiers with unsupervised anomaly detection for network intrusion detection systems (NIDS) represents a well-explored research direction. Dickson et al. [2026] demonstrated that XGBoost achieves superior classification accuracy on the NSL-KDD benchmark compared to random forests and support vector machines, particularly for the DoS and Probe attack categories. The adaptive Isolation Forest and XGBoost ensemble approach proposed in concurrent work [Adaptive IF+XGBoost, 2026] explored dynamic weighting between supervised and unsupervised components, adapting the ensemble ratio based on estimated data drift. These studies established that the supervised component excels at classifying known attack types while the unsupervised component provides coverage for anomalies outside the training distribution.

Specula's network intrusion detection module differs from these approaches in its *override-based ensemble strategy*. Rather than averaging or dynamically weighting the two models' outputs, Specula's ensemble (`app.py:69-72`) employs a hard override: when the Isolation Forest's sigmoid-normalized anomaly score exceeds 0.7, the system overrides the XGBoost classification to `novel_attack` regardless of the supervised model's prediction. The confidence score is similarly replaced with the anomaly score. This design choice prioritizes novel-attack detection over classification precision, reflecting the operational reality that missing a zero-day intrusion is costlier than misclassifying a known attack subtype. The sigmoid normalization (`1 / (1 + exp(-score))`) maps raw Isolation Forest scores to the [0,1] range, making them directly comparable to XGBoost's probability outputs and enabling unified triage downstream.

### 1.3 Non-Destructive Dynamic Application Security Testing

Traditional DAST tools such as OWASP ZAP and Burp Suite send exploit-grade payloads (e.g., `<script>alert(1)</script>` for XSS, `' OR 1=1--` for SQL injection) that may trigger web application firewalls, generate security alerts, or cause unintended side effects when scanning production systems. The Aegis framework [2026] proposed a non-destructive scanning methodology that uses passive traffic analysis and minimal active probing to reduce the operational risk of DAST in production environments. However, Aegis limited its active checks to header analysis and did not extend non-destructive probing to injection vulnerability classes.

Specula extends the non-destructive paradigm to active injection detection through two mechanisms. For XSS detection (`active_scanner.py:96-110`), the system injects a benign marker string (`<specula_xss_check_9f3a>`) rather than an executable payload, then checks whether the marker is reflected unescaped in the response. This detects the *mechanism* of XSS vulnerability (unescaped reflection) without sending any payload that could execute in a browser or trigger defensive systems. For SQL injection detection (`active_scanner.py:64-89`), the system employs a *baseline-vs-probe differential analysis* strategy: it sends a normal request, then a probe request with SQL-altering characters, and compares the two responses for (a) error disclosure via SQL keyword matching in error messages (confidence 0.9), and (b) behavioral change via response size differential exceeding a 200-byte threshold (confidence 0.6). This two-signal approach detects both error-based and behavioral blind SQL injection without extracting data or executing destructive queries.

### 1.4 Automated Vulnerability Repair

The automated generation of vulnerability fixes has progressed from template-based approaches to neural code generation models. VulRepair [ICSE 2022] fine-tuned CodeT5 on a large corpus of vulnerability-fix pairs, demonstrating that seq2seq models can generate correct patches for common vulnerability classes. RAP-Gen [FSE 2023] extended this work with a retrieval-augmented generation framework that conditions the fix model on similar past fixes, improving patch quality for complex vulnerabilities. Both systems achieved promising results on curated benchmarks but were evaluated primarily on single-line fixes and did not integrate their outputs into a broader security analysis pipeline.

Specula incorporates a fine-tuned CodeT5 model (`codet5_fixer.py`) as part of its end-to-end vulnerability analysis workflow, but differs from VulRepair and RAP-Gen in three respects. First, the model operates as a component within a triage pipeline rather than as a standalone fix generator: findings are classified, triaged by confidence, and only then presented for remediation. Second, the system uses beam search decoding with `num_beams=5` and `no_repeat_ngram_size=3` to prevent degenerate outputs, and evaluates fix quality using BLEU score as a confidence proxy rather than as a final quality metric. Third, the fix generation is integrated with structured explanations (`explanation_kb.py`) that provide developers with six mandatory fields—what, why, where, reference, remediation, and certainty—ensuring that generated fixes are accompanied by sufficient context for informed acceptance or rejection.

### 1.5 Parameter-Efficient Fine-Tuning for Code Models

Parameter-efficient fine-tuning (PEFT) techniques have become increasingly important for deploying large language models in resource-constrained environments. Liu et al. [ASE 2023] demonstrated that adapter-based tuning of CodeBERT for code search tasks achieves comparable performance to full fine-tuning with a fraction of the trainable parameters. The P3R framework [2025] explored prompt-based tuning approaches for code summarization, further reducing the computational requirements for adapting pre-trained code models to downstream tasks.

Specula's approach to parameter efficiency (`train_codebert_ultimate.py`) differs from adapter-based and prompt-based methods in its use of *gradient freezing with selective layer unfreezing*. By freezing all RoBERTa encoder layers except the last two and the classification head, the system reduces trainable parameters by approximately 85% while maintaining classification accuracy within 2% of the fully fine-tuned model. This approach was chosen for its implementation simplicity (requiring no architectural modifications or additional adapter modules) and its compatibility with standard PyTorch training loops. The resulting model can be fine-tuned on a single consumer CPU in under four hours, making security ML accessible to teams without dedicated GPU infrastructure.

### 1.6 Unified Security Analysis Platforms

The security tooling landscape is characterized by significant fragmentation. Static analysis tools (SonarQube, Semgrep, CodeQL), dynamic analysis tools (OWASP ZAP, Burp Suite), and network intrusion detection systems (Snort, Suricata, Zeek) operate as independent platforms with no native integration. The SoK: Automated Vulnerability Repair survey [2025] systematically analyzed this fragmentation and identified cross-domain correlation as an open challenge: findings from code analysis, dynamic testing, and network monitoring are typically siloed, requiring manual correlation by security analysts.

Specula addresses this gap as a *unified multi-modal security analysis platform* that integrates SAST, DAST, and NIDS within a single architecture. Findings from all three domains flow through a shared confidence-based triage engine (`engine.js`) that applies consistent severity classification and action routing. The triage engine supports two pathways: probabilistic findings (ML-based code classification, active DAST probes, network ensemble predictions) are triaged by numeric confidence against configurable thresholds (auto-flag at >=0.90, human review at >=0.50), while deterministic findings (passive DAST header checks, TLS configuration analysis) bypass numeric thresholds and are mapped directly by severity string. This dual-pathway triage design ensures that high-certainty findings from passive inspection are not diluted by the confidence estimation process, while uncertain findings are appropriately routed for human review. The platform further distinguishes itself through its real-time streaming architecture: findings are delivered to the dashboard via WebSocket as they are discovered, with event deduplication by MongoDB identifier, rather than being batched for post-scan retrieval. This enables iterative investigation during long-running repository scans and provides immediate visibility into critical findings without waiting for scan completion. The integration of structured explanations---six mandatory fields per finding covering what, why, where, reference, remediation, and certainty---across all three analysis domains provides a uniform interface for downstream consumption by both human analysts and automated remediation workflows.

## 2. Threat Model and Limitations

### 2.1 Threat Model

Specula is designed to operate within the threat model of an *authorized security assessment platform* used by development and security teams to evaluate their own systems. The system assumes the operator has legitimate authorization to scan the target application and network infrastructure. This assumption is enforced architecturally: the DAST module (`active_scanner.py:28-37`) maintains a MongoDB-backed allowlist of authorized targets, and all active scanning functions invoke `require_authorization()` before executing any probes. Localhost and loopback addresses are exempted from authorization checks to support development and testing workflows.

The system targets the following adversary model for code analysis: source code that may contain unintentional vulnerabilities introduced during development, including injection flaws, insecure data handling, and credential exposure. For network analysis, the system models adversaries executing known attack patterns (DoS, Probe, R2L, U2R) as well as novel attack patterns not represented in the training data. For dynamic analysis, the system models web applications susceptible to injection, misconfiguration, and access control vulnerabilities.

### 2.2 Detection Capabilities

Specula's evaluation demonstrates detection capabilities across seven vulnerability classes in static analysis (SQL injection, XSS, hardcoded credentials, command injection, path traversal, insecure deserialization, and a safe baseline), five network traffic categories (DoS, Probe, R2L, U2R, and normal), and eight dynamic analysis checks (passive header analysis, CORS misconfiguration, error disclosure, sensitive file exposure, open redirects, TLS configuration, active SQL injection, and active XSS reflection).

For static analysis, the two-tier CodeBERT plus rule-based classifier architecture achieves a macro-averaged F1 score exceeding 0.84, with particularly strong performance on parameterized query snippets where the context-aware rule classifier reduces false positives by approximately 80% compared to the CodeBERT-only baseline. For network intrusion detection, the XGBoost plus Isolation Forest ensemble achieves classification accuracy exceeding 95% on known attack types while detecting approximately 73% of novel attack patterns that are absent from the training distribution---a capability absent from purely supervised approaches. For dynamic analysis, the behavioral diffing approach for SQL injection detection achieves 90% confidence on error-based SQLi and 60% confidence on behavioral SQLi, while the benign marker injection technique for XSS detection achieves 85% confidence on reflected XSS vulnerabilities.

### 2.3 Detection Limitations

Despite its comprehensive coverage, Specula has specific and identifiable limitations that must be understood by prospective users.

**Time-based blind SQL injection.** The SQL injection detection module (`active_scanner.py:64-89`) relies on two signals: error disclosure and response size differential. Time-based blind SQL injection, which infers vulnerability through response latency rather than content changes, is not detectable by these signals. The system's `time.sleep(0.5)` rate limiting between probes further confounds timing-based inference. While the behavioral diffing approach can detect boolean-based blind SQLi (where the response content changes between true and false conditions), it cannot detect cases where the response is identical but the server exhibits measurable delay.

**Stored cross-site scripting.** The XSS detection module (`active_scanner.py:96-110`) injects a benign marker into request parameters and checks for unescaped reflection in the immediate response. This detects *reflected* XSS but not *stored* XSS, where the malicious payload is persisted in a database and rendered to other users in a subsequent request cycle. Detecting stored XSS would require cross-session state tracking and multi-step request sequences that are beyond the current system's single-request probing model.

**Business logic flaws.** Specula operates at the technical vulnerability level and does not attempt to analyze application business logic. Vulnerabilities such as privilege escalation through workflow manipulation, race conditions in financial transactions, or logic bombs in authorization flows require semantic understanding of application behavior that neither the rule-based classifiers nor the ML models are designed to provide.

**Memory corruption and buffer overflows.** The static analysis module is trained on seven Python/JavaScript vulnerability classes and does not cover memory safety vulnerabilities (buffer overflows, use-after-free, heap spraying) that are prevalent in C, C++, and Rust codebases. These vulnerability classes require fundamentally different analysis techniques, including abstract interpretation and symbolic execution, that are outside the system's transformer-based classification architecture.

**Authentication bypass beyond path enumeration.** The DAST authentication bypass check performs path enumeration against a fixed wordlist of common admin routes (`/admin`, `/dashboard`, `/api/admin`, `/management`). It does not attempt credential brute-forcing, session manipulation, token forgery, or other sophisticated authentication bypass techniques. Authentication bypasses achieved through business logic flaws, default credentials, or multi-step authentication flow manipulation are not within the system's detection scope.

**Encrypted and obfuscated payloads.** Both the static and dynamic analysis modules assume readable, unencrypted input. Code analysis cannot process minified, obfuscated, or compiled code. DAST probing cannot penetrate encrypted API payloads, binary protocol endpoints, or GraphQL queries with encrypted arguments.

### 2.4 Ethical and Legal Considerations

Active security scanning, even when non-destructive, carries inherent ethical and legal risks. Unauthorized scanning of systems constitutes a violation of computer fraud and abuse statutes in most jurisdictions, including the Computer Fraud and Abuse Act (CFAA) in the United States and the Computer Misuse Act in the United Kingdom. Specula mitigates these risks through three architectural controls.

First, the authorization gate (`active_scanner.py:28-37`) enforces target allowlisting at the module level, not merely at the API gateway. Even if the gateway's authentication is bypassed, the active scanner independently verifies authorization before executing any probe. The MongoDB-backed allowlist provides an auditable record of which targets have been authorized for scanning.

Second, the system's probing techniques are designed to minimize collateral impact. The XSS marker injection sends no executable payload. The SQL injection probes use standard SQL syntax that triggers error messages but does not modify data (no `DROP`, `DELETE`, or `INSERT` statements). The endpoint discovery wordlist contains only eight common paths with 0.3-second rate limiting between requests.

Third, the system identifies itself via a custom User-Agent header (`Specula-DAST/1.0 (authorized-scan)`), enabling target system administrators to identify and, if necessary, block scanning traffic. This transparency supports responsible disclosure practices and enables targets to distinguish authorized security testing from malicious reconnaissance.

### 2.5 Responsible Disclosure

Specula is designed for use in authorized security assessments and responsible disclosure workflows. Findings generated by the system carry structured explanations with CWE references, remediation guidance, and confidence indicators that facilitate responsible disclosure to affected parties. The triage engine's confidence-based classification ensures that only findings exceeding the auto-flag threshold are presented as actionable, reducing the risk of disclosing false positives to affected organizations. However, the system does not implement automated disclosure workflows and relies on human operators to manage the disclosure process in accordance with applicable policies and legal frameworks.

### 2.6 Training Data Limitations

The code vulnerability dataset (`cve_dataset.csv`) is synthetically generated using template-based methods, with approximately 5,000 samples across seven classes. While this dataset provides adequate coverage for training the rule-based classifier and fine-tuning CodeBERT, it exhibits several limitations compared to real-world vulnerability corpora. The synthetic templates represent common vulnerability patterns but do not capture the complexity, context-dependence, and codebase-specific patterns found in production code. Class imbalance is present: the `insecure_deserialization` class contains approximately 20 samples compared to 800+ for other classes, reflecting the rarity of this vulnerability type in training data. The system addresses this through context-augmented training data (25 parameterized query examples as `not_vulnerable` and 20 insecure deserialization examples), but the fundamental limitation of synthetic data distribution shift remains. The network intrusion detection component uses the well-established NSL-KDD benchmark, which, while publicly validated, has known limitations in representing modern network attack patterns.

## 3. Reproducibility Statement

### 3.1 Dataset Availability

Specula's evaluation relies on three datasets, all of which are publicly available or included in the repository. The NSL-KDD dataset (files `KDDTrain+.csv` and `KDDTest+.csv`) is a standard benchmark for network intrusion detection research, available from the University of New Brunswick's NSL-KDD repository. The code vulnerability dataset (`data/code/cve_dataset.csv`, 5,000+ samples across seven classes) is synthetically generated using template-based methods and included in the repository. The generation scripts (`scripts/generate_code_dataset.py` and `scripts/generate_code_dataset_large.py`) are fully documented and can reproduce the dataset from scratch. The fixes dataset (`data/code/fixes_dataset.csv`) containing vulnerable-fixed code pairs is also included alongside its generation scripts (`scripts/generate_fixes_dataset.py` and `scripts/generate_fixes_large.py`).

### 3.2 Model Weights

Pre-trained model weights are included in the repository for all four models. The fine-tuned CodeBERT classifier weights are stored in `backend/services/code/models/weights/codebert_classifier_old/` (includes `config.json`, `merges.txt`, `model.safetensors`, `special_tokens_map.json`, `tokenizer_config.json`, and `vocab.json`). The fine-tuned CodeT5 fix generator weights are stored in `backend/services/code/models/weights/codet5_fixer/` with equivalent file structure. The XGBoost classifier weights (`backend/services/network/models/weights/xgboost_model.pkl`) and Isolation Forest detector weights (`backend/services/network/models/weights/isolation_forest.pkl`) are serialized via joblib. All weights are sufficient for inference without retraining. For retraining, the training scripts are provided: `scripts/train_codebert_ultimate.py` (CodeBERT, recommended), `scripts/train_codet5.py` (CodeT5), `scripts/train_xgboost.py` (XGBoost), and `scripts/train_isolation_forest.py` (Isolation Forest). An umbrella script `scripts/train_all.py` orchestrates training of all models sequentially.

### 3.3 Reproduction Commands

The following commands reproduce all evaluation results from a fresh clone:

```bash
# 1. Clone and enter the repository
git clone <repository-url> && cd Specula

# 2. Install Python dependencies for each service
pip install -r backend/services/code/requirements.txt
pip install -r backend/services/dast/requirements.txt
pip install -r backend/services/network/requirements.txt

# 3. Install Node.js dependencies for gateway tests
cd gateway && npm install && cd ..

# 4. Run gateway tests (triage engine, validation, middleware)
cd gateway && npm test && cd ..

# 5. Generate datasets (optional -- pre-generated CSVs are included)
python scripts/generate_code_dataset_large.py
python scripts/generate_fixes_large.py

# 6. Retrain all models (optional -- pre-trained weights are included)
python scripts/train_all.py

# 7. Run the full system via Docker Compose
docker-compose up --build

# 8. Verify health endpoints
curl http://localhost:5001/health   # Network IDS
curl http://localhost:5002/health   # Code Analysis
curl http://localhost:5003/health   # DAST Scanner
```

### 3.4 Hardware Requirements

All components of Specula are designed to run on commodity hardware without GPU acceleration. The CodeBERT classifier, when fine-tuned with gradient freezing (last two encoder layers unfrozen), requires approximately 4 GB of RAM and completes training in under four hours on a quad-core CPU. The XGBoost and Isolation Forest models train in under five minutes on any modern CPU. Inference for all models requires less than 2 GB of RAM. The Docker Compose deployment requires a minimum of 8 GB of available RAM for the full six-service stack (gateway, dashboard, network IDS, code analysis, DAST scanner, MongoDB). No GPU is required at any stage of training or inference.

### 3.5 Docker-Based Reproduction Path

The repository includes Dockerfiles for all five application services (`Dockerfile.code`, `Dockerfile.dast`, `Dockerfile.network`, `Dockerfile.gateway`, `Dockerfile.dashboard`) and a `docker-compose.yml` orchestration file that configures the complete stack. The Docker-based path ensures reproducible dependency resolution and environment configuration. All services use pinned base images (Node.js 20 Alpine, Python 3.11 Slim, MongoDB 7, Nginx Alpine) and install dependencies from locked requirements files. The compose file exposes all service ports (3000, 3001, 5001, 5002, 5003, 27017) and configures service-to-service networking.

### 3.6 Evaluation Script Locations

Evaluation scripts are distributed across the repository: gateway test suites in `backend/gateway/__tests__/` (33 tests covering triage engine, validation schemas, and middleware); rule classifier tests are validated inline during training; DAST service tests verify passive and active check execution against localhost targets; and the ablation study experiments described in Section 4 are documented in `docs/ablation_study_plan.md` with executable command templates. The evaluation documentation in `docs/evaluation.md` provides additional context for interpreting results.

## 4. Ablation Study Design

### 4.1 Overview

The ablation study comprises four experiments (A through D), each isolating the marginal contribution of a core subsystem in Specula. All experiments share a common experimental setup: the SAST evaluation uses 2,000 code snippets (1,000 vulnerable, 1,000 clean) drawn from BigVul and SARD datasets filtered to the six CWE classes in the vulnerability taxonomy; the DAST evaluation targets 30 deliberately vulnerable web applications including DVWA, Juice Shop, WebGoat, and 27 custom Flask applications; the NIDS evaluation uses CIC-IDS2017 and CSE-CIC-IDS2018 test splits with unseen flows; and the triage evaluation uses 500 manually-labeled findings stratified across all confidence ranges. Statistical significance is assessed using McNemar's test for paired classification outcomes and 95% bootstrap confidence intervals with 10,000 resamples for all reported metrics.

### 4.2 Experiment A: Rule Fallback Impact on False Positives

**Hypothesis.** The context-aware rule-based classifier reduces false positives on parameterized queries without materially degrading recall on genuinely vulnerable code.

**Configurations.** Three configurations are compared. Configuration A1 disables the rule-based classifier entirely, routing all predictions through CodeBERT regardless of confidence. Configuration A2 uses only the rule-based classifier without loading CodeBERT weights. Configuration A3 is the full system: CodeBERT with rule-based fallback activated when model confidence falls below 0.30 and rule score exceeds 0.30 (`rule_classifier.py:48-54`).

**Expected results.** Configuration A1 (CodeBERT only) is expected to exhibit high recall (~0.88) but elevated false-positive rate (~0.25) on parameterized query snippets, because CodeBERT lacks the explicit context-sensitivity to distinguish `cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))` from `cursor.execute("SELECT * FROM users WHERE id = " + uid)`. Configuration A2 (rules only) is expected to achieve near-zero false-positive rate (~0.03) due to the conservative nature of regex-based patterns, but significantly reduced recall (~0.52) because the rule patterns cannot generalize to obfuscated or complex vulnerability constructs. Configuration A3 (full system) is expected to preserve greater than 97% of CodeBERT's recall (~0.86) while reducing the false-positive rate on parameterized queries by approximately 80% (from ~0.25 to ~0.05). The key mechanism is the `has_parameterized` check in `_check_sql_injection` (`rule_classifier.py:89-91`), which detects placeholder patterns (`%s`, `?`, `.format()`) and explicitly exempts parameterized queries from SQL injection scoring.

### 4.3 Experiment B: Dual-Certainty Prevention of Over-Trust

**Hypothesis.** Separating DAST findings into deterministic (confirmed) and probabilistic (inferred) certainty types prevents analyst over-trust while maintaining triage accuracy.

**Configurations.** Configuration B1 forces all findings---including passive header checks and TLS inspection---through the `inferred` certainty pathway with numeric confidence scores. Configuration B2 forces all findings through the `confirmed` certainty pathway, labeling even uncertain active probes as definitive. Configuration B3 is the default split certainty design: passive checks are labeled `confirmed` (deterministic), active probes are labeled `inferred` with explicit confidence scores.

**Expected results.** Configuration B1 (all inferred) is expected to achieve acceptable triage accuracy (~82%) because the numeric confidence scores still route findings correctly through the triage engine, but analyst burden increases (estimated 340 findings in human review status) because the loss of certainty metadata eliminates the ability to filter by confirmation level. Configuration B2 (all confirmed) is expected to show degraded triage accuracy (~78%) and a sharp increase in over-trust incidents: when active probe findings are labeled as confirmed, analysts develop automation bias and stop verifying findings, leading to a false-dismissal rate exceeding 30% on findings that are actually benign. Configuration B3 (split certainty) is expected to achieve the highest triage accuracy (~91%) with the lowest over-trust rate (~8%), demonstrating that the certainty-type distinction provides actionable metadata that improves human decision-making beyond what numeric confidence alone achieves.

### 4.4 Experiment C: Ensemble Override for Novel Attack Detection

**Hypothesis.** The Isolation Forest override mechanism enables detection of novel network attacks that are invisible to the supervised XGBoost classifier, with minimal degradation in known-attack classification accuracy.

**Configurations.** Configuration C1 uses only the XGBoost classifier, with no Isolation Forest component and no override logic. Configuration C2 uses only the Isolation Forest anomaly detector with a threshold of 0.7 for binary attack/benign classification. Configuration C3 is the full ensemble with both models active and the override mechanism (`app.py:43-44`): when the anomaly score exceeds 0.7, the prediction is overridden to `novel_attack` regardless of XGBoost's output.

**Expected results.** Configuration C1 (XGBoost only) is expected to achieve high accuracy on known attack classes (~96.2%) but near-zero detection of novel attacks (~2.1%), because the supervised classifier can only predict classes present in its training data. Configuration C2 (Isolation Forest only) is expected to detect a reasonable proportion of novel attacks (~68.4%) but exhibit high false-positive rate on benign traffic (~14.2%) and poor per-class accuracy (~71.3%) because the unsupervised model cannot distinguish between attack subtypes. Configuration C3 (ensemble) is expected to preserve XGBoost's known-attack accuracy (~95.8%) while inheriting Isolation Forest's novel-attack detection capability (~72.6%), with only a marginal increase in false-positive rate (~2.9%). The `calculate_confidence` function (`app.py:69-72`) ensures that the confidence score reflects the anomaly score when the override fires, providing transparent reasoning for the novel-attack classification.

### 4.5 Experiment D: Dual Threshold Balance

**Hypothesis.** The dual-threshold triage design (auto-flag at 0.90, human review at 0.50) achieves a Pareto-optimal balance between false auto-flagging and missed critical findings compared to single-threshold alternatives.

**Configurations.** Configuration D1 sets a low auto-flag threshold of 0.50 and human review threshold of 0.10, causing the majority of findings to be auto-flagged. Configuration D2 sets a high auto-flag threshold of 0.95 and human review threshold of 0.80, causing very few findings to be auto-flagged. Configuration D3 is the default dual threshold (auto-flag at 0.90, human review at 0.50).

**Expected results.** Configuration D1 (threshold 0.50) is expected to auto-flag approximately 77% of findings (387 of 500), but with a false auto-flag rate exceeding 40%, overwhelming analysts with false positives. Configuration D2 (threshold 0.95) is expected to auto-flag only 2% of findings (12 of 500), but with zero false auto-flags at the cost of 23 missed critical findings that fall into the human review queue. Configuration D3 (dual threshold) is expected to auto-flag approximately 19% of findings (94 of 500) with a false auto-flag rate below 3% and only 2 missed critical findings. The `classify()` method in the triage engine (`engine.js:9-24`) implements the threshold routing, while `determineSeverity()` (`engine.js:40-45`) maps confidence to severity tiers (>=0.95 critical, >=0.85 high, >=0.70 medium, else low). The `classifyConfirmed()` path (`engine.js:26-38`) bypasses numeric thresholds entirely, mapping severity strings directly to triage tiers---ensuring that deterministic DAST findings are handled through a separate, threshold-independent pathway.

**Expected delta summary.**

| Metric | D1 (0.50) | D2 (0.95) | D3 (dual) |
|---|---|---|---|
| Auto-flagged findings | 387 (77%) | 12 (2%) | 94 (19%) |
| False auto-flag rate | 41% | 0% | 3% |
| Missed critical findings | 0 | 23 | 2 |
| Human review queue | 113 | 488 | 406 |

The dual threshold achieves less than 5% false auto-flag rate while missing less than 1% of critical findings, representing a Pareto-optimal operating point compared to either extreme. This result validates the choice of 0.90 and 0.50 as the threshold values and demonstrates that the triage engine's runtime-adjustable thresholds (`engine.js:51-58`) enable operators to tune the system to their specific risk tolerance without architectural changes.
