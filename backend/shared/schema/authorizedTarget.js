const mongoose = require('mongoose');

const authorizedTargetSchema = new mongoose.Schema({
  target: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  added_at: {
    type: Date,
    default: Date.now
  },
  note: {
    type: String,
    default: ''
  }
});

module.exports = mongoose.model('AuthorizedTarget', authorizedTargetSchema);
