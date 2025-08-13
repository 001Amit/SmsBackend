const mongoose = require('mongoose');

const forwarderSchema = new mongoose.Schema({
  deviceId: { type: String, required: true, unique: true },
  numbers: [String],
  active: { type: Boolean, default: true },
  updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Forwarder', forwarderSchema);
