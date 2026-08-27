const mongoose = require('mongoose');

const notificationLogSchema = new mongoose.Schema({
  job_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ScanJob',
    default: null,
    index: true
  },
  channel: {
    type: String,
    enum: ['slack', 'email'],
    required: true
  },
  recipient: {
    type: String,
    required: true
  },
  sent_at: {
    type: Date,
    default: Date.now,
    index: true
  },
  status: {
    type: String,
    enum: ['success', 'failed'],
    default: 'success'
  },
  error: {
    type: String,
    default: null
  }
}, {
  timestamps: true
});

notificationLogSchema.index({ job_id: 1, channel: 1 });

module.exports = mongoose.model('NotificationLog', notificationLogSchema);
