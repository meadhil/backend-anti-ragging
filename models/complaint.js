// complaint.js (Mongoose model)
const mongoose = require('mongoose');

const complaintSchema = new mongoose.Schema({
  subject: { type: String, required: true },
  description: { type: String, required: true },
  date: { type: String, required: false },
  location: { type: String, required: false },
  witnesses: { type: String, required: false },
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  filePath: { type: String, required: false },
}, { timestamps: true });

module.exports = mongoose.model('complaint', complaintSchema);
