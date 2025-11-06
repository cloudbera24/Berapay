const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  phone: { type: String, unique: true, required: true },
  pinHash: { type: String, required: true },
  balance: { type: Number, default: 0 },
  profilePath: String,
  linked: { type: Boolean, default: false },
  walletId: { type: String, unique: true },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

userSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

userSchema.methods.verifyPin = function(pin) {
  return bcrypt.compare(pin, this.pinHash);
};

const sessionSchema = new mongoose.Schema({
  phone: { type: String, required: true },
  code: { type: String, required: true, unique: true },
  verified: { type: Boolean, default: false },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});

sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const transactionSchema = new mongoose.Schema({
  transactionId: { type: String, unique: true, required: true },
  sender: String,
  receiver: String,
  amount: { type: Number, required: true },
  type: { 
    type: String, 
    enum: ['deposit', 'withdrawal', 'transfer', 'payment'], 
    required: true 
  },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed', 'cancelled'], 
    default: 'pending' 
  },
  description: String,
  payheroReference: String,
  metadata: mongoose.Schema.Types.Mixed,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const walletSchema = new mongoose.Schema({
  walletId: { type: String, unique: true, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  balance: { type: Number, default: 0 },
  currency: { type: String, default: 'KES' },
  isActive: { type: Boolean, default: true },
  lastTransactionAt: Date,
  createdAt: { type: Date, default: Date.now }
});

module.exports = {
  User: mongoose.model('User', userSchema),
  Session: mongoose.model('Session', sessionSchema),
  Transaction: mongoose.model('Transaction', transactionSchema),
  Wallet: mongoose.model('Wallet', walletSchema)
};
