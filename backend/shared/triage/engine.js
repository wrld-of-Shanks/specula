class TriageEngine {
  constructor(config = {}) {
    this.thresholds = {
      auto_flag: config.auto_flag || 0.90,
      human_review: config.human_review || 0.50
    };
  }

  classify(confidence, result = {}) {
    let status, severity;

    if (confidence >= this.thresholds.auto_flag) {
      status = 'auto_flagged';
      severity = this.determineSeverity(confidence, result);
    } else if (confidence >= this.thresholds.human_review) {
      status = 'human_review';
      severity = this.determineSeverity(confidence, result);
    } else {
      status = 'ignored';
      severity = 'info';
    }

    return { status, severity };
  }

  classifyConfirmed(severity) {
    const statusMap = {
      'critical': 'auto_flagged',
      'high': 'auto_flagged',
      'medium': 'human_review',
      'low': 'human_review',
      'info': 'ignored'
    };
    return {
      status: statusMap[severity] || 'human_review',
      severity
    };
  }

  determineSeverity(confidence, result) {
    if (confidence >= 0.95) return 'critical';
    if (confidence >= 0.85) return 'high';
    if (confidence >= 0.70) return 'medium';
    return 'low';
  }

  getThresholds() {
    return { ...this.thresholds };
  }

  updateThresholds(newThresholds) {
    if (newThresholds.auto_flag !== undefined) {
      this.thresholds.auto_flag = newThresholds.auto_flag;
    }
    if (newThresholds.human_review !== undefined) {
      this.thresholds.human_review = newThresholds.human_review;
    }
  }
}

module.exports = { TriageEngine };
