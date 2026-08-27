const mongoose = require('mongoose');

const autoFixLogSchema = new mongoose.Schema({
  job_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ScanJob',
    default: null
  },
  finding_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Event',
    required: true,
    index: true
  },
  repo_url: {
    type: String,
    default: null
  },
  file_path: {
    type: String,
    default: null
  },
  fix_generated: {
    type: Boolean,
    default: false
  },
  fallback_issue: {
    type: Boolean,
    default: false
  },
  pr_url: {
    type: String,
    default: null
  },
  issue_url: {
    type: String,
    default: null
  },
  branch: {
    type: String,
    default: null
  },
  status: {
    type: String,
    enum: ['success', 'report_only', 'failed', 'blocked'],
    default: 'failed'
  },
  error: {
    type: String,
    default: null
  },
  user_ip: {
    type: String,
    default: null
  }
}, {
  timestamps: true
});

autoFixLogSchema.index({ created_at: 1 });
autoFixLogSchema.index({ user_ip: 1, created_at: 1 });

module.exports = mongoose.model('AutoFixLog', autoFixLogSchema);
