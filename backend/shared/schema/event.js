const mongoose = require('mongoose');

const eventSchema = new mongoose.Schema({
  event_type: {
    type: String,
    enum: ['network', 'code', 'dast', 'scan_repo'],
    required: true,
    index: true
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  },
  source: {
    type: String,
    required: true
  },
  prediction: {
    type: String,
    required: true
  },
  confidence: {
    type: Number,
    min: 0,
    max: 1,
    default: null
  },
  certainty_type: {
    type: String,
    enum: ['confirmed', 'inferred', null],
    default: null
  },
  severity: {
    type: String,
    enum: ['critical', 'high', 'medium', 'low', 'info'],
    required: true
  },
  status: {
    type: String,
    enum: ['auto_flagged', 'human_review', 'ignored'],
    required: true
  },
  explanation: {
    type: mongoose.Schema.Types.Mixed,
    default: null
  },
  suggested_fix: {
    type: String,
    default: null
  },
  raw_features: {
    type: mongoose.Schema.Types.Mixed,
    default: null
  },
  job_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ScanJob',
    default: null,
    index: true
  },
  file_path: {
    type: String,
    default: null
  },
  line_range: {
    start: { type: Number, default: null },
    end: { type: Number, default: null }
  },
  mode: {
    type: String,
    enum: ['passive', 'active', null],
    default: null
  },
  evidence: {
    type: mongoose.Schema.Types.Mixed,
    default: null
  }
}, {
  timestamps: true
});

eventSchema.index({ event_type: 1, timestamp: -1 });
eventSchema.index({ status: 1 });
eventSchema.index({ confidence: -1 });
eventSchema.index({ job_id: 1 });

module.exports = mongoose.model('Event', eventSchema);
