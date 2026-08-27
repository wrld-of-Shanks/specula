const mongoose = require('mongoose');

const reportLogSchema = new mongoose.Schema({
  job_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ScanJob',
    default: null,
    index: true
  },
  filename: {
    type: String,
    required: true,
    unique: true
  },
  generated_at: {
    type: Date,
    default: Date.now,
    index: true
  },
  expires_at: {
    type: Date,
    default: null
  },
  download_count: {
    type: Number,
    default: 0
  },
  size_bytes: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('ReportLog', reportLogSchema);
