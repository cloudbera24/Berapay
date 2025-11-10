require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const { PayHeroClient } = require('payhero-devkit');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

// Initialize PayHero Client with YOUR credentials
const client = new PayHeroClient({
  authToken: process.env.AUTH_TOKEN
});

console.log('✅ PayHero Client initialized successfully');

// Database Models with Enhanced Admin System
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  wallet_balance: { type: Number, default: 0 },
  role: { type: String, default: 'user' },
  is_active: { type: Boolean, default: true },
  is_verified: { type: Boolean, default: false },
  is_blocked: { type: Boolean, default: false },
  blocked_reason: { type: String, default: '' },
  kyc_status: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
  created_by: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const transactionSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'transfer'], required: true },
  amount: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'successful', 'failed', 'cancelled'], default: 'pending' },
  commission: { type: Number, default: 0 },
  external_reference: { type: String, required: true },
  recipient_phone: String,
  description: String,
  payhero_txn_id: String,
  admin_notes: String,
  processed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  createdAt: { type: Date, default: Date.now }
});

const adminSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['super_admin', 'admin', 'support'], default: 'admin' },
  permissions: { 
    type: [String], 
    default: [
      'view_users', 'manage_users', 'view_transactions', 'manage_transactions',
      'process_withdrawals', 'view_reports', 'system_settings'
    ] 
  },
  is_active: { type: Boolean, default: true },
  last_login: { type: Date },
  created_by: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  createdAt: { type: Date, default: Date.now }
});

const adminLogSchema = new mongoose.Schema({
  admin_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
  action: { type: String, required: true },
  target_type: { type: String, enum: ['user', 'transaction', 'system'] },
  target_id: mongoose.Schema.Types.ObjectId,
  details: mongoose.Schema.Types.Mixed,
  ip_address: String,
  user_agent: String,
  createdAt: { type: Date, default: Date.now }
});

// Create indexes
transactionSchema.index({ external_reference: 1 }, { unique: true, sparse: true });
adminLogSchema.index({ admin_id: 1, createdAt: -1 });

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

// Methods
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

adminSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

adminSchema.methods.hasPermission = function(permission) {
  return this.permissions.includes(permission) || this.role === 'super_admin';
};

const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Admin = mongoose.model('Admin', adminSchema);
const AdminLog = mongoose.model('AdminLog', adminLogSchema);

// ==================== ADMIN LOGGING ====================

async function logAdminAction(adminId, action, targetType = null, targetId = null, details = null, req = null) {
  try {
    const log = new AdminLog({
      admin_id: adminId,
      action,
      target_type: targetType,
      target_id: targetId,
      details,
      ip_address: req?.ip || req?.connection?.remoteAddress,
      user_agent: req?.get('User-Agent')
    });
    await log.save();
  } catch (error) {
    console.error('Failed to log admin action:', error);
  }
}

// ==================== PERMISSION MIDDLEWARE ====================

const requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.admin.hasPermission(permission)) {
      return res.status(403).json({ 
        error: 'Access denied. Insufficient permissions.' 
      });
    }
    next();
  };
};

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

    if (user.is_blocked) {
      return res.status(403).json({ 
        error: `Account blocked. Reason: ${user.blocked_reason || 'Violation of terms'}` 
      });
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

    // Update last login
    admin.last_login = new Date();
    await admin.save();

    req.admin = admin;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid admin token.' });
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

    if (!name || !email || !phone || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const existingUser = await User.findOne({ 
      $or: [{ email }, { phone }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email or phone' });
    }

    const user = new User({ name, email, phone, password });
    await user.save();

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
        role: user.role,
        is_verified: user.is_verified
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    if (error.code === 11000) {
      return res.status(400).json({ error: 'User already exists with this email or phone' });
    }
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

    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.is_active) {
      return res.status(403).json({ error: 'Account deactivated. Please contact support.' });
    }

    if (user.is_blocked) {
      return res.status(403).json({ 
        error: `Account blocked. Reason: ${user.blocked_reason || 'Violation of terms'}` 
      });
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
        role: user.role,
        is_verified: user.is_verified,
        is_blocked: user.is_blocked
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
      is_verified: req.user.is_verified,
      is_blocked: req.user.is_blocked,
      kyc_status: req.user.kyc_status,
      createdAt: req.user.createdAt
    }
  });
});

// REAL STK Push Deposit
app.post('/api/users/deposit', authUser, async (req, res) => {
  try {
    const { amount, phone } = req.body;

    if (!amount || amount < 1) {
      return res.status(400).json({ error: 'Amount must be at least KES 1' });
    }

    let formattedPhone = phone || req.user.phone;
    formattedPhone = formatPhoneNumber(formattedPhone);

    if (!formattedPhone.startsWith('254')) {
      return res.status(400).json({ error: 'Phone number must be in format 2547XXXXXXXX' });
    }

    const reference = generateReference('DEP', req.user._id);
    
    const transaction = new Transaction({
      user_id: req.user._id,
      type: 'deposit',
      amount: amount,
      status: 'pending',
      external_reference: reference
    });
    await transaction.save();

    const stkPayload = {
      phone_number: formattedPhone,
      amount: parseFloat(amount),
      provider: process.env.DEFAULT_PROVIDER || 'm-pesa',
      channel_id: process.env.CHANNEL_ID,
      external_reference: reference,
      customer_name: req.user.name || 'Customer'
    };

    console.log('🔄 Initiating REAL STK Push for deposit:', stkPayload);
    
    const response = await client.stkPush(stkPayload);
    
    console.log('✅ STK Push Response:', response);

    transaction.payhero_txn_id = response.reference;
    await transaction.save();

    res.json({
      success: true,
      message: 'STK push initiated successfully',
      data: response,
      transactionId: transaction._id
    });

  } catch (error) {
    console.error('❌ STK Push Deposit Error:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to initiate STK push'
    });
  }
});

// REAL Withdrawal
app.post('/api/users/withdraw', authUser, async (req, res) => {
  try {
    const { amount, phone } = req.body;

    if (!amount || amount < 1) {
      return res.status(400).json({ error: 'Amount must be at least KES 1' });
    }

    if (req.user.wallet_balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    let formattedPhone = phone || req.user.phone;
    formattedPhone = formatPhoneNumber(formattedPhone);

    if (!formattedPhone.startsWith('254')) {
      return res.status(400).json({ error: 'Phone number must be in format 2547XXXXXXXX' });
    }

    const commission = calculateCommission(amount);
    const netAmount = amount - commission;

    const reference = generateReference('WD', req.user._id);
    
    const transaction = new Transaction({
      user_id: req.user._id,
      type: 'withdrawal',
      amount: amount,
      status: 'pending',
      commission: commission,
      external_reference: reference
    });
    await transaction.save();

    await User.findByIdAndUpdate(req.user._id, {
      $inc: { wallet_balance: -amount }
    });

    const withdrawPayload = {
      phone_number: formattedPhone,
      amount: parseFloat(netAmount),
      provider: process.env.DEFAULT_PROVIDER || 'm-pesa',
      channel_id: process.env.CHANNEL_ID,
      external_reference: reference
    };

    console.log('🔄 Initiating REAL Withdrawal:', withdrawPayload);
    
    const response = await client.withdraw(withdrawPayload);
    
    console.log('✅ Withdrawal Response:', response);

    transaction.payhero_txn_id = response.reference;
    await transaction.save();

    res.json({
      success: true,
      message: 'Withdrawal initiated successfully',
      data: response,
      transactionId: transaction._id,
      commission: commission,
      netAmount: netAmount
    });

  } catch (error) {
    console.error('❌ Withdrawal Error:', error);
    
    await User.findByIdAndUpdate(req.user._id, {
      $inc: { wallet_balance: amount }
    });

    res.status(500).json({
      success: false,
      error: error.message || 'Failed to initiate withdrawal'
    });
  }
});

// Get Balance
app.get('/api/users/balance', authUser, async (req, res) => {
  try {
    const balance = await client.serviceWalletBalance();
    
    res.json({
      wallet_balance: req.user.wallet_balance,
      system_balance: balance.balance || 0,
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

    const recipient = await User.findOne({ phone: recipient_phone, is_active: true, is_blocked: false });
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found or account inactive' });
    }

    if (recipient._id.toString() === req.user._id.toString()) {
      return res.status(400).json({ error: 'Cannot transfer to yourself' });
    }

    const commission = calculateCommission(amount);
    const netAmount = amount - commission;

    const reference = generateReference('TR', req.user._id);

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
    if (error.code === 11000) {
      return res.status(400).json({ error: 'Duplicate transaction detected' });
    }
    res.status(500).json({ error: 'Transfer failed' });
  }
});

// ==================== ENHANCED ADMIN ROUTES ====================

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

    const token = jwt.sign({ adminId: admin._id }, process.env.JWT_SECRET, { expiresIn: '24h' });

    await logAdminAction(admin._id, 'login', 'system', null, { email }, req);

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

// Get Admin Profile
app.get('/api/admin/profile', authAdmin, async (req, res) => {
  res.json({
    admin: {
      id: req.admin._id,
      name: req.admin.name,
      email: req.admin.email,
      role: req.admin.role,
      permissions: req.admin.permissions,
      last_login: req.admin.last_login,
      createdAt: req.admin.createdAt
    }
  });
});

// Get All Users (Admin Only)
app.get('/api/admin/users', authAdmin, requirePermission('view_users'), async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '', status = '' } = req.query;
    
    const query = {};
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } }
      ];
    }
    if (status === 'active') query.is_active = true;
    if (status === 'inactive') query.is_active = false;
    if (status === 'blocked') query.is_blocked = true;
    if (status === 'verified') query.is_verified = true;

    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await User.countDocuments(query);

    await logAdminAction(req.admin._id, 'view_users', 'system', null, { search, status }, req);

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

// Block/Unblock User
app.patch('/api/admin/users/:userId/block', authAdmin, requirePermission('manage_users'), async (req, res) => {
  try {
    const { userId } = req.params;
    const { blocked, reason } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.is_blocked = blocked;
    user.blocked_reason = reason || '';
    await user.save();

    await logAdminAction(req.admin._id, blocked ? 'block_user' : 'unblock_user', 'user', userId, { reason }, req);

    res.json({
      message: `User ${blocked ? 'blocked' : 'unblocked'} successfully`,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        is_blocked: user.is_blocked,
        blocked_reason: user.blocked_reason
      }
    });
  } catch (error) {
    console.error('Block user error:', error);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

// Verify User
app.patch('/api/admin/users/:userId/verify', authAdmin, requirePermission('manage_users'), async (req, res) => {
  try {
    const { userId } = req.params;
    const { verified } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.is_verified = verified;
    await user.save();

    await logAdminAction(req.admin._id, verified ? 'verify_user' : 'unverify_user', 'user', userId, null, req);

    res.json({
      message: `User ${verified ? 'verified' : 'unverified'} successfully`,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        is_verified: user.is_verified
      }
    });
  } catch (error) {
    console.error('Verify user error:', error);
    res.status(500).json({ error: 'Failed to update user verification' });
  }
});

// Update User KYC Status
app.patch('/api/admin/users/:userId/kyc', authAdmin, requirePermission('manage_users'), async (req, res) => {
  try {
    const { userId } = req.params;
    const { status, notes } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.kyc_status = status;
    await user.save();

    await logAdminAction(req.admin._id, 'update_kyc_status', 'user', userId, { status, notes }, req);

    res.json({
      message: `User KYC status updated to ${status}`,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        kyc_status: user.kyc_status
      }
    });
  } catch (error) {
    console.error('KYC update error:', error);
    res.status(500).json({ error: 'Failed to update KYC status' });
  }
});

// Get All Transactions (Admin Only)
app.get('/api/admin/transactions', authAdmin, requirePermission('view_transactions'), async (req, res) => {
  try {
    const { page = 1, limit = 10, type, status, userId } = req.query;
    
    const query = {};
    if (type) query.type = type;
    if (status) query.status = status;
    if (userId) query.user_id = userId;

    const transactions = await Transaction.find(query)
      .populate('user_id', 'name email phone')
      .populate('processed_by', 'name email')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Transaction.countDocuments(query);

    const totalCommission = await Transaction.aggregate([
      { $match: { status: 'successful' } },
      { $group: { _id: null, total: { $sum: '$commission' } } }
    ]);

    const totalVolume = await Transaction.aggregate([
      { $match: { status: 'successful' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    await logAdminAction(req.admin._id, 'view_transactions', 'system', null, { type, status, userId }, req);

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

// Process Withdrawal on Behalf of User (Manual Processing)
app.post('/api/admin/transactions/:transactionId/process', authAdmin, requirePermission('process_withdrawals'), async (req, res) => {
  try {
    const { transactionId } = req.params;
    const { action, notes } = req.body; // action: 'approve', 'reject', 'cancel'

    const transaction = await Transaction.findById(transactionId).populate('user_id');
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    if (transaction.type !== 'withdrawal') {
      return res.status(400).json({ error: 'Only withdrawal transactions can be processed manually' });
    }

    let updateData = { admin_notes: notes, processed_by: req.admin._id };

    if (action === 'approve') {
      // Process withdrawal via PayHero
      const withdrawPayload = {
        phone_number: transaction.user_id.phone,
        amount: parseFloat(transaction.amount - transaction.commission),
        provider: process.env.DEFAULT_PROVIDER || 'm-pesa',
        channel_id: process.env.CHANNEL_ID,
        external_reference: transaction.external_reference
      };

      const response = await client.withdraw(withdrawPayload);
      updateData.status = 'successful';
      updateData.payhero_txn_id = response.reference;

    } else if (action === 'reject') {
      // Refund user balance
      await User.findByIdAndUpdate(transaction.user_id, {
        $inc: { wallet_balance: transaction.amount }
      });
      updateData.status = 'failed';

    } else if (action === 'cancel') {
      // Refund user balance
      await User.findByIdAndUpdate(transaction.user_id, {
        $inc: { wallet_balance: transaction.amount }
      });
      updateData.status = 'cancelled';
    }

    await Transaction.findByIdAndUpdate(transactionId, updateData);

    await logAdminAction(req.admin._id, `manual_${action}_withdrawal`, 'transaction', transactionId, { notes }, req);

    res.json({
      message: `Withdrawal ${action}d successfully`,
      transaction: {
        id: transaction._id,
        status: updateData.status,
        admin_notes: notes
      }
    });
  } catch (error) {
    console.error('Manual withdrawal processing error:', error);
    res.status(500).json({ error: error.message || 'Failed to process withdrawal' });
  }
});

// Admin Dashboard Stats
app.get('/api/admin/stats', authAdmin, requirePermission('view_reports'), async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ is_active: true });
    const blockedUsers = await User.countDocuments({ is_blocked: true });
    const verifiedUsers = await User.countDocuments({ is_verified: true });
    const totalTransactions = await Transaction.countDocuments();
    
    const totalVolume = await Transaction.aggregate([
      { $match: { status: 'successful' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    const totalCommission = await Transaction.aggregate([
      { $match: { status: 'successful' } },
      { $group: { _id: null, total: { $sum: '$commission' } } }
    ]);

    const pendingWithdrawals = await Transaction.countDocuments({ 
      type: 'withdrawal', 
      status: 'pending' 
    });

    const balance = await client.serviceWalletBalance();

    const recentTransactions = await Transaction.find()
      .populate('user_id', 'name')
      .sort({ createdAt: -1 })
      .limit(5);

    await logAdminAction(req.admin._id, 'view_dashboard_stats', 'system', null, null, req);

    res.json({
      users: {
        total: totalUsers,
        active: activeUsers,
        blocked: blockedUsers,
        verified: verifiedUsers
      },
      transactions: {
        total: totalTransactions,
        volume: Math.abs(totalVolume[0]?.total || 0),
        commission: totalCommission[0]?.total || 0,
        pending_withdrawals: pendingWithdrawals
      },
      system: {
        balance: balance.balance || 0,
        currency: 'KES'
      },
      recentTransactions
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch stats' });
  }
});

// Get Admin Activity Logs
app.get('/api/admin/logs', authAdmin, requirePermission('view_reports'), async (req, res) => {
  try {
    const { page = 1, limit = 20, adminId } = req.query;
    
    const query = {};
    if (adminId) query.admin_id = adminId;

    const logs = await AdminLog.find(query)
      .populate('admin_id', 'name email')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await AdminLog.countDocuments(query);

    res.json({
      logs,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      total
    });
  } catch (error) {
    console.error('Admin logs error:', error);
    res.status(500).json({ error: 'Failed to fetch admin logs' });
  }
});

// ==================== TRANSACTION STATUS ====================

app.get('/api/transaction-status/:reference', async (req, res) => {
  try {
    const { reference } = req.params;
    
    if (!reference) {
      return res.status(400).json({
        success: false,
        error: 'Transaction reference is required'
      });
    }

    console.log('🔄 Checking REAL transaction status:', reference);
    const response = await client.transactionStatus(reference);
    console.log('✅ Status Response:', response);
    
    res.json({
      success: true,
      data: response
    });

  } catch (error) {
    console.error('❌ Transaction Status Error:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to get transaction status'
    });
  }
});

// ==================== WEBHOOKS & HEALTH CHECKS ====================

app.post('/webhooks/payhero', async (req, res) => {
  try {
    const { reference, status, transactionId, amount } = req.body;
    
    console.log('PayHero webhook received:', { reference, status, transactionId, amount });

    const transaction = await Transaction.findOne({ external_reference: reference });
    if (!transaction) {
      console.error('Transaction not found for reference:', reference);
      return res.status(404).json({ error: 'Transaction not found' });
    }

    transaction.status = status === 'success' ? 'successful' : 'failed';
    if (transactionId) {
      transaction.payhero_txn_id = transactionId;
    }

    await transaction.save();

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

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    const balance = await client.serviceWalletBalance();
    
    res.json({
      success: true,
      message: 'BeraPay is running and connected to PayHero',
      account_id: process.env.CHANNEL_ID,
      timestamp: new Date().toISOString(),
      balance: balance
    });
  } catch (error) {
    res.json({
      success: false,
      message: 'BeraPay running but PayHero connection failed',
      error: error.message
    });
  }
});

// ==================== INITIALIZATION ====================

async function initializeDefaults() {
  try {
    // Drop problematic indexes first
    try {
      await Transaction.collection.dropIndex('ref_1');
      console.log('✅ Dropped problematic ref_1 index');
    } catch (e) {
      console.log('ℹ️  No problematic index to drop');
    }

    // Create super admin from environment variables
    const superAdminExists = await Admin.findOne({ email: process.env.ADMIN_EMAIL });
    if (!superAdminExists) {
      const superAdmin = new Admin({
        name: process.env.ADMIN_NAME || 'System Administrator',
        email: process.env.ADMIN_EMAIL,
        password: process.env.ADMIN_PASSWORD,
        role: 'super_admin',
        permissions: [
          'view_users', 'manage_users', 'view_transactions', 'manage_transactions',
          'process_withdrawals', 'view_reports', 'system_settings', 'manage_admins'
        ]
      });
      await superAdmin.save();
      console.log('✅ Super Admin created from environment variables');
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
    app.listen(port, () => {
      console.log('🚀 BeraPay - Enhanced Admin System');
      console.log('📍 Server running on port:', port);
      console.log('🔑 Account ID:', process.env.CHANNEL_ID);
      console.log('👑 Super Admin:', process.env.ADMIN_EMAIL);
      console.log('🌐 Access: http://localhost:' + port);
      console.log('❤️  Health: http://localhost:' + port + '/api/health');
    });
  })
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });
