const mongoose = require('mongoose');

const ForwarderSchema = new mongoose.Schema({
  deviceId: { type: String, required: true, unique: true },
  active: { type: Boolean, default: true },
  activeNumbers: { type: [String], default: [] }, // unique per device enforced via $addToSet
  updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Forwarder', ForwarderSchema);
