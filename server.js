require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const PayHero = require('payhero-wrapper');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Initialize PayHero with .env credentials
const payhero = new PayHero({
  authToken: process.env.AUTH_TOKEN,
  channelId: process.env.CHANNEL_ID,
  defaultProvider: process.env.DEFAULT_PROVIDER
});

console.log('✅ PayHero initialized with credentials from .env');

// Database Models
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  wallet_balance: { type: Number, default: 0 },
  role: { type: String, default: 'user' },
  is_active: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const transactionSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'transfer'], required: true },
  amount: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'successful', 'failed'], default: 'pending' },
  commission: { type: Number, default: 0 },
  external_reference: { type: String, required: true },
  recipient_phone: String,
  description: String,
  payhero_txn_id: String,
  createdAt: { type: Date, default: Date.now }
});

const adminSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'admin' },
  permissions: { type: [String], default: ['users', 'transactions', 'reports'] },
  is_active: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const developerSchema = new mongoose.Schema({
  developer_name: { type: String, required: true },
  api_key: { type: String, required: true },
  quota: { type: Number, default: 1000 },
  usage: { type: Number, default: 0 },
  is_active: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

// Pre-save middleware for hashing
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.updatedAt = Date.now();
  next();
});

adminSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

developerSchema.pre('save', async function(next) {
  if (this.isNew && !this.api_key) {
    const crypto = require('crypto');
    this.api_key = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 12);
  }
  next();
});

// Methods
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

adminSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

developerSchema.methods.compareApiKey = async function(candidateApiKey) {
  return await bcrypt.compare(candidateApiKey, this.api_key);
};

const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Admin = mongoose.model('Admin', adminSchema);
const DeveloperKey = mongoose.model('DeveloperKey', developerSchema);

// ==================== AUTHENTICATION MIDDLEWARE ====================

const authUser = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user || !user.is_active) {
      return res.status(401).json({ error: 'Invalid token or user deactivated.' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token.' });
  }
};

const authAdmin = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.adminId).select('-password');
    
    if (!admin || !admin.is_active) {
      return res.status(401).json({ error: 'Invalid admin token or admin deactivated.' });
    }

    req.admin = admin;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid admin token.' });
  }
};

const authDeveloper = async (req, res, next) => {
  try {
    const apiKey = req.header('X-API-Key');
    if (!apiKey) return res.status(401).json({ error: 'Access denied. No API key provided.' });

    const developerKey = await DeveloperKey.findOne({ is_active: true });
    if (!developerKey) return res.status(401).json({ error: 'Invalid API key.' });

    const isValid = await bcrypt.compare(apiKey, developerKey.api_key);
    if (!isValid) return res.status(401).json({ error: 'Invalid API key.' });

    if (developerKey.usage >= developerKey.quota) {
      return res.status(429).json({ error: 'API quota exceeded.' });
    }

    developerKey.usage += 1;
    await developerKey.save();

    req.developer = developerKey;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid API key.' });
  }
};

// ==================== UTILITY FUNCTIONS ====================

const formatPhoneNumber = (phone) => {
  let formatted = phone.replace(/\s+/g, '');
  if (formatted.startsWith('0')) {
    formatted = '254' + formatted.substring(1);
  } else if (formatted.startsWith('+254')) {
    formatted = formatted.substring(1);
  }
  return formatted;
};

const calculateCommission = (amount) => {
  return Number((amount * 0.02).toFixed(2));
};

const generateReference = (prefix, userId) => {
  return `${prefix}_${Date.now()}_${userId}`;
};

// ==================== USER ROUTES ====================

// User Registration
app.post('/api/users/register', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    // Validation
    if (!name || !email || !phone || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { phone }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email or phone' });
    }

    // Create user
    const user = new User({ name, email, phone, password });
    await user.save();

    // Generate token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        wallet_balance: user.wallet_balance,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User Login
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email, is_active: true });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        wallet_balance: user.wallet_balance,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get User Profile
app.get('/api/users/profile', authUser, async (req, res) => {
  res.json({
    user: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      phone: req.user.phone,
      wallet_balance: req.user.wallet_balance,
      role: req.user.role,
      createdAt: req.user.createdAt
    }
  });
});

// Deposit Funds
app.post('/api/users/deposit', authUser, async (req, res) => {
  try {
    const { amount, phone } = req.body;

    if (!amount || amount < 1) {
      return res.status(400).json({ error: 'Amount must be at least KES 1' });
    }

    const reference = generateReference('DEP', req.user._id);
    
    // Create transaction record
    const transaction = new Transaction({
      user_id: req.user._id,
      type: 'deposit',
      amount: amount,
      status: 'pending',
      external_reference: reference
    });
    await transaction.save();

    // Initiate STK push via PayHero
    const result = await payhero.stkPush({
      phone: formatPhoneNumber(phone || req.user.phone),
      amount: Math.round(amount),
      reference: reference
    });

    // Update transaction with PayHero transaction ID
    transaction.payhero_txn_id = result.transactionId;
    await transaction.save();

    res.json({
      message: 'Deposit initiated successfully',
      transactionId: transaction._id,
      reference: result.reference,
      payhero_txn_id: result.transactionId
    });
  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ error: error.message || 'Failed to initiate deposit' });
  }
});

// Withdraw Funds
app.post('/api/users/withdraw', authUser, async (req, res) => {
  try {
    const { amount, phone } = req.body;

    if (!amount || amount < 1) {
      return res.status(400).json({ error: 'Amount must be at least KES 1' });
    }

    if (req.user.wallet_balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const commission = calculateCommission(amount);
    const netAmount = amount - commission;

    const reference = generateReference('WD', req.user._id);
    
    // Create transaction record
    const transaction = new Transaction({
      user_id: req.user._id,
      type: 'withdrawal',
      amount: amount,
      status: 'pending',
      commission: commission,
      external_reference: reference
    });
    await transaction.save();

    // Deduct from user balance immediately
    await User.findByIdAndUpdate(req.user._id, {
      $inc: { wallet_balance: -amount }
    });

    // Initiate withdrawal via PayHero
    const result = await payhero.withdraw({
      phone: formatPhoneNumber(phone || req.user.phone),
      amount: Math.round(netAmount),
      reference: reference
    });

    // Update transaction with PayHero transaction ID
    transaction.payhero_txn_id = result.transactionId;
    await transaction.save();

    res.json({
      message: 'Withdrawal initiated successfully',
      transactionId: transaction._id,
      reference: result.reference,
      payhero_txn_id: result.transactionId,
      commission: commission,
      netAmount: netAmount
    });
  } catch (error) {
    console.error('Withdrawal error:', error);
    
    // Refund user balance if withdrawal failed
    await User.findByIdAndUpdate(req.user._id, {
      $inc: { wallet_balance: amount }
    });

    res.status(500).json({ error: error.message || 'Failed to initiate withdrawal' });
  }
});

// Get Balance
app.get('/api/users/balance', authUser, async (req, res) => {
  try {
    const balance = await payhero.balance();
    
    res.json({
      wallet_balance: req.user.wallet_balance,
      system_balance: balance.availableBalance || 0,
      currency: 'KES'
    });
  } catch (error) {
    console.error('Balance error:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch balance' });
  }
});

// Get User Transactions
app.get('/api/users/transactions', authUser, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    
    const transactions = await Transaction.find({ user_id: req.user._id })
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Transaction.countDocuments({ user_id: req.user._id });

    res.json({
      transactions,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      total
    });
  } catch (error) {
    console.error('Transactions error:', error);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// Internal Transfer
app.post('/api/users/transfer', authUser, async (req, res) => {
  try {
    const { recipient_phone, amount, description } = req.body;

    if (!amount || amount < 1) {
      return res.status(400).json({ error: 'Amount must be at least KES 1' });
    }

    if (req.user.wallet_balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const recipient = await User.findOne({ phone: recipient_phone, is_active: true });
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    if (recipient._id.toString() === req.user._id.toString()) {
      return res.status(400).json({ error: 'Cannot transfer to yourself' });
    }

    const commission = calculateCommission(amount);
    const netAmount = amount - commission;

    const reference = generateReference('TR', req.user._id);

    // Create transaction records
    const senderTransaction = new Transaction({
      user_id: req.user._id,
      type: 'transfer',
      amount: -amount,
      status: 'successful',
      commission: commission,
      external_reference: reference,
      recipient_phone: recipient_phone,
      description: description || `Transfer to ${recipient_phone}`
    });

    const recipientTransaction = new Transaction({
      user_id: recipient._id,
      type: 'transfer',
      amount: netAmount,
      status: 'successful',
      external_reference: reference,
      recipient_phone: req.user.phone,
      description: description || `Transfer from ${req.user.phone}`
    });

    // Update balances
    await User.findByIdAndUpdate(req.user._id, {
      $inc: { wallet_balance: -amount }
    });

    await User.findByIdAndUpdate(recipient._id, {
      $inc: { wallet_balance: netAmount }
    });

    await senderTransaction.save();
    await recipientTransaction.save();

    res.json({
      message: 'Transfer successful',
      transactionId: senderTransaction._id,
      commission: commission,
      netAmount: netAmount,
      recipient: {
        name: recipient.name,
        phone: recipient.phone
      }
    });
  } catch (error) {
    console.error('Transfer error:', error);
    res.status(500).json({ error: 'Transfer failed' });
  }
});

// ==================== ADMIN ROUTES ====================

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const admin = await Admin.findOne({ email, is_active: true });
    if (!admin || !(await admin.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }

    const token = jwt.sign({ adminId: admin._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Admin login successful',
      token,
      admin: {
        id: admin._id,
        name: admin.name,
        email: admin.email,
        role: admin.role,
        permissions: admin.permissions
      }
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get All Users (Admin Only)
app.get('/api/admin/users', authAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '' } = req.query;
    
    const query = search ? {
      $or: [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } }
      ]
    } : {};

    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await User.countDocuments(query);

    res.json({
      users,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      total
    });
  } catch (error) {
    console.error('Admin users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get All Transactions (Admin Only)
app.get('/api/admin/transactions', authAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, type, status } = req.query;
    
    const query = {};
    if (type) query.type = type;
    if (status) query.status = status;

    const transactions = await Transaction.find(query)
      .populate('user_id', 'name email phone')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Transaction.countDocuments(query);

    // Calculate totals
    const totalCommission = await Transaction.aggregate([
      { $match: { status: 'successful' } },
      { $group: { _id: null, total: { $sum: '$commission' } } }
    ]);

    const totalVolume = await Transaction.aggregate([
      { $match: { status: 'successful' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    res.json({
      transactions,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      total,
      totalCommission: totalCommission[0]?.total || 0,
      totalVolume: Math.abs(totalVolume[0]?.total || 0)
    });
  } catch (error) {
    console.error('Admin transactions error:', error);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// Admin Dashboard Stats
app.get('/api/admin/stats', authAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ is_active: true });
    const totalTransactions = await Transaction.countDocuments();
    
    const totalVolume = await Transaction.aggregate([
      { $match: { status: 'successful' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    const totalCommission = await Transaction.aggregate([
      { $match: { status: 'successful' } },
      { $group: { _id: null, total: { $sum: '$commission' } } }
    ]);

    const balance = await payhero.balance();

    // Recent transactions
    const recentTransactions = await Transaction.find()
      .populate('user_id', 'name')
      .sort({ createdAt: -1 })
      .limit(5);

    res.json({
      users: {
        total: totalUsers,
        active: activeUsers
      },
      transactions: {
        total: totalTransactions,
        volume: Math.abs(totalVolume[0]?.total || 0),
        commission: totalCommission[0]?.total || 0
      },
      system: {
        balance: balance.availableBalance || 0,
        currency: 'KES'
      },
      recentTransactions
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch stats' });
  }
});

// Admin Commission Analytics
app.get('/api/admin/commission', authAdmin, async (req, res) => {
  try {
    const { period = 'day' } = req.query;
    
    let groupFormat;
    switch (period) {
      case 'hour':
        groupFormat = { hour: { $hour: '$createdAt' } };
        break;
      case 'week':
        groupFormat = { week: { $week: '$createdAt' } };
        break;
      case 'month':
        groupFormat = { month: { $month: '$createdAt' } };
        break;
      default:
        groupFormat = { day: { $dayOfMonth: '$createdAt' } };
    }

    const commissionData = await Transaction.aggregate([
      {
        $match: {
          status: 'successful',
          commission: { $gt: 0 }
        }
      },
      {
        $group: {
          _id: {
            ...groupFormat,
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' }
          },
          totalCommission: { $sum: '$commission' },
          transactionCount: { $sum: 1 },
          totalAmount: { $sum: '$amount' }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1, ...groupFormat } }
    ]);

    res.json({
      commissionData,
      period
    });
  } catch (error) {
    console.error('Commission analytics error:', error);
    res.status(500).json({ error: 'Failed to fetch commission data' });
  }
});

// ==================== DEVELOPER API ROUTES ====================

// Developer Deposit
app.post('/api/v1/deposit', authDeveloper, async (req, res) => {
  try {
    const { phone, amount, reference } = req.body;

    if (!phone || !amount || amount < 1) {
      return res.status(400).json({ error: 'Phone and amount (min KES 1) are required' });
    }

    const user = await User.findOne({ phone, is_active: true });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const txReference = reference || generateReference('DEV_DEP', user._id);
    
    // Create transaction record
    const transaction = new Transaction({
      user_id: user._id,
      type: 'deposit',
      amount: amount,
      status: 'pending',
      external_reference: txReference
    });
    await transaction.save();

    // Initiate STK push via PayHero
    const result = await payhero.stkPush({
      phone: formatPhoneNumber(phone),
      amount: Math.round(amount),
      reference: txReference
    });

    transaction.payhero_txn_id = result.transactionId;
    await transaction.save();

    res.json({
      success: true,
      message: 'Deposit initiated successfully',
      transactionId: transaction._id,
      reference: result.reference,
      payhero_txn_id: result.transactionId,
      user: {
        id: user._id,
        name: user.name,
        phone: user.phone
      }
    });
  } catch (error) {
    console.error('Developer deposit error:', error);
    res.status(500).json({ error: error.message || 'Failed to initiate deposit' });
  }
});

// Developer Withdrawal
app.post('/api/v1/withdraw', authDeveloper, async (req, res) => {
  try {
    const { phone, amount, reference } = req.body;

    if (!phone || !amount || amount < 1) {
      return res.status(400).json({ error: 'Phone and amount (min KES 1) are required' });
    }

    const user = await User.findOne({ phone, is_active: true });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.wallet_balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const commission = calculateCommission(amount);
    const netAmount = amount - commission;

    const txReference = reference || generateReference('DEV_WD', user._id);
    
    // Create transaction record
    const transaction = new Transaction({
      user_id: user._id,
      type: 'withdrawal',
      amount: amount,
      status: 'pending',
      commission: commission,
      external_reference: txReference
    });
    await transaction.save();

    // Deduct from user balance
    await User.findByIdAndUpdate(user._id, {
      $inc: { wallet_balance: -amount }
    });

    // Initiate withdrawal via PayHero
    const result = await payhero.withdraw({
      phone: formatPhoneNumber(phone),
      amount: Math.round(netAmount),
      reference: txReference
    });

    transaction.payhero_txn_id = result.transactionId;
    await transaction.save();

    res.json({
      success: true,
      message: 'Withdrawal initiated successfully',
      transactionId: transaction._id,
      reference: result.reference,
      payhero_txn_id: result.transactionId,
      commission: commission,
      netAmount: netAmount
    });
  } catch (error) {
    console.error('Developer withdraw error:', error);
    
    // Refund user balance if withdrawal failed
    if (user) {
      await User.findByIdAndUpdate(user._id, {
        $inc: { wallet_balance: amount }
      });
    }

    res.status(500).json({ error: error.message || 'Failed to initiate withdrawal' });
  }
});

// Get User Balance (Developer API)
app.get('/api/v1/balance', authDeveloper, async (req, res) => {
  try {
    const { phone } = req.query;

    if (!phone) {
      return res.status(400).json({ error: 'Phone number is required' });
    }

    const user = await User.findOne({ phone, is_active: true }).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        phone: user.phone,
        wallet_balance: user.wallet_balance
      }
    });
  } catch (error) {
    console.error('Developer balance error:', error);
    res.status(500).json({ error: 'Failed to fetch balance' });
  }
});

// Get User Transactions (Developer API)
app.get('/api/v1/transactions', authDeveloper, async (req, res) => {
  try {
    const { phone, page = 1, limit = 10 } = req.query;

    if (!phone) {
      return res.status(400).json({ error: 'Phone number is required' });
    }

    const user = await User.findOne({ phone, is_active: true });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const transactions = await Transaction.find({ user_id: user._id })
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Transaction.countDocuments({ user_id: user._id });

    res.json({
      success: true,
      transactions,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      total
    });
  } catch (error) {
    console.error('Developer transactions error:', error);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// Get API Usage
app.get('/api/v1/usage', authDeveloper, async (req, res) => {
  try {
    res.json({
      success: true,
      usage: req.developer.usage,
      quota: req.developer.quota,
      remaining: req.developer.quota - req.developer.usage
    });
  } catch (error) {
    console.error('Usage error:', error);
    res.status(500).json({ error: 'Failed to fetch usage' });
  }
});

// ==================== WEBHOOKS & HEALTH CHECKS ====================

// PayHero Webhook for transaction callbacks
app.post('/webhooks/payhero', async (req, res) => {
  try {
    const { reference, status, transactionId, amount } = req.body;
    
    console.log('PayHero webhook received:', { reference, status, transactionId, amount });

    // Find transaction by reference
    const transaction = await Transaction.findOne({ external_reference: reference });
    if (!transaction) {
      console.error('Transaction not found for reference:', reference);
      return res.status(404).json({ error: 'Transaction not found' });
    }

    // Update transaction status
    transaction.status = status === 'success' ? 'successful' : 'failed';
    if (transactionId) {
      transaction.payhero_txn_id = transactionId;
    }

    await transaction.save();

    // If deposit was successful, update user balance
    if (status === 'success' && transaction.type === 'deposit') {
      await User.findByIdAndUpdate(transaction.user_id, {
        $inc: { wallet_balance: transaction.amount }
      });
      console.log(`Updated user balance for deposit: ${transaction.amount}`);
    }

    res.json({ success: true, message: 'Webhook processed' });
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Health check
app.get('/health', async (req, res) => {
  try {
    // Check database connection
    await mongoose.connection.db.admin().ping();
    
    // Check PayHero connection
    const balance = await payhero.balance();
    
    res.json({
      status: 'OK',
      database: 'connected',
      payhero: 'connected',
      timestamp: new Date().toISOString(),
      system_balance: balance.availableBalance || 0
    });
  } catch (error) {
    res.status(503).json({
      status: 'ERROR',
      database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      payhero: 'error',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// ==================== INITIALIZATION ====================

// Initialize default admin and developer
async function initializeDefaults() {
  try {
    // Create default admin
    const adminExists = await Admin.findOne({ email: 'admin@berapay.com' });
    if (!adminExists) {
      const admin = new Admin({
        name: 'System Administrator',
        email: 'admin@berapay.com',
        password: 'admin123'
      });
      await admin.save();
      console.log('✅ Default admin created: admin@berapay.com / admin123');
    }

    // Create default developer key
    const devExists = await DeveloperKey.findOne();
    if (!devExists) {
      const dev = new DeveloperKey({
        developer_name: 'BeraPay Developer'
      });
      await dev.save();
      console.log('✅ Default developer key created');
    }

    console.log('✅ System initialization completed');
  } catch (error) {
    console.error('Initialization error:', error);
  }
}

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('✅ MongoDB connected successfully');
    return initializeDefaults();
  })
  .then(() => {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`🚀 BeraPay server running on port ${PORT}`);
      console.log(`📍 Frontend: http://localhost:${PORT}`);
      console.log(`🔧 API: http://localhost:${PORT}/api`);
      console.log(`❤️  Health: http://localhost:${PORT}/health`);
      console.log(`🔑 Admin Login: admin@berapay.com / admin123`);
    });
  })
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });
