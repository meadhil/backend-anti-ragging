const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },          // 🆕 Added name
  department: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
});

// 👉 Virtual field for isAdmin
userSchema.virtual('isAdmin').get(function () {
  return this.role === 'admin';
});

// 👉 Tell mongoose to include virtuals when converting to JSON and Objects
userSchema.set('toJSON', { virtuals: true });
userSchema.set('toObject', { virtuals: true });

module.exports = mongoose.model('User', userSchema);
