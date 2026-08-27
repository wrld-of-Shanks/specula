const mongoose = require('mongoose');

const scanJobSchema = new mongoose.Schema({
  repo_url: {
    type: String,
    required: true,
    index: true
  },
  status: {
    type: String,
    enum: ['pending', 'cloning', 'scanning', 'completed', 'failed'],
    default: 'pending',
    index: true
  },
  started_at: {
    type: Date,
    default: Date.now
  },
  completed_at: {
    type: Date,
    default: null
  },
  file_count: {
    type: Number,
    default: 0
  },
  finding_count: {
    type: Number,
    default: 0
  },
  error: {
    type: String,
    default: null
  }
}, {
  timestamps: true
});

scanJobSchema.index({ status: 1, started_at: -1 });

module.exports = mongoose.model('ScanJob', scanJobSchema);
