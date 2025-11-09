const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const morgan = require('morgan');
const dotenv = require('dotenv');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(morgan('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// MongoDB connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/berapay', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('MongoDB connected successfully');
    
    // Create admin user if not exists
    await createAdminUser();
  } catch (err) {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  }
};

const createAdminUser = async () => {
  try {
    const adminExists = await User.findOne({ email: 'admin@berapay.com' });
    if (!adminExists) {
      const adminUser = new User({
        name: 'Admin User',
        phone: '+254700000000',
        email: 'admin@berapay.com',
        password: 'admin123',
        role: 'admin'
      });
      await adminUser.save();
      console.log('Admin user created: admin@berapay.com / admin123');
    }
  } catch (error) {
    console.error('Error creating admin user:', error);
  }
};

connectDB();

// ==================== MODELS ====================

// User Model
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  phone: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true, minlength: 6 },
  balance: { type: Number, default: 0, min: 0 },
  apiKey: { type: String, unique: true, sparse: true },
  isActive: { type: Boolean, default: true },
  lastLogin: { type: Date },
  role: { type: String, enum: ['user', 'admin'], default: 'user' }
}, { timestamps: true });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    if (!this.apiKey) {
      this.apiKey = crypto.randomBytes(32).toString('hex');
    }
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.toJSON = function() {
  const user = this.toObject();
  delete user.password;
  return user;
};

const User = mongoose.model('User', userSchema);

// Merchant Model
const merchantSchema = new mongoose.Schema({
  companyName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  apiKey: { type: String, required: true, unique: true },
  secretKey: { type: String, required: true, unique: true },
  webhookUrl: { type: String },
  balance: { type: Number, default: 0 },
  totalEarnings: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  commissionRate: { type: Number, default: 0.005 },
}, { timestamps: true });

const Merchant = mongoose.model('Merchant', merchantSchema);

// Transaction Model
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  merchantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant' },
  amount: { type: Number, required: true, min: 1 },
  type: { type: String, enum: ['deposit', 'withdrawal', 'payment', 'payout'], required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  commission: { type: Number, default: 0, min: 0 },
  platformCommission: { type: Number, default: 0 },
  netAmount: { type: Number, required: true },
  phone: { type: String },
  reference: { type: String, unique: true, sparse: true },
  swiftReference: { type: String },
  description: { type: String },
  paymentMethod: { type: String, enum: ['stk_push', 'paybill', 'till', 'bank', 'mobile'] },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { timestamps: true });

const Transaction = mongoose.model('Transaction', transactionSchema);

// Commission Model
const commissionSchema = new mongoose.Schema({
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  merchantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant' },
  amount: { type: Number, required: true, min: 0 },
  transactionAmount: { type: Number, required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'payment', 'payout'], required: true },
  rate: { type: Number, default: 0.02 }
}, { timestamps: true });

const Commission = mongoose.model('Commission', commissionSchema);

// Admin Wallet Model
const adminWalletSchema = new mongoose.Schema({
  totalCommission: { type: Number, default: 0, min: 0 },
  totalTransactions: { type: Number, default: 0 },
  totalDeposits: { type: Number, default: 0 },
  totalWithdrawals: { type: Number, default: 0 },
  totalPlatformEarnings: { type: Number, default: 0 }
}, { timestamps: true });

adminWalletSchema.statics.getWallet = async function() {
  let wallet = await this.findOne();
  if (!wallet) {
    wallet = await this.create({});
  }
  return wallet;
};

const AdminWallet = mongoose.model('AdminWallet', adminWalletSchema);

// Payment Channel Model
const paymentChannelSchema = new mongoose.Schema({
  merchantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant', required: true },
  channelType: { type: String, enum: ['paybill', 'till', 'bank', 'mobile'], required: true },
  paybillNumber: { type: String },
  paybillAccount: { type: String },
  tillNumber: { type: String },
  bankName: { type: String },
  bankAccount: { type: String },
  bankCode: { type: String },
  isActive: { type: Boolean, default: true },
  isDefault: { type: Boolean, default: false }
}, { timestamps: true });

const PaymentChannel = mongoose.model('PaymentChannel', paymentChannelSchema);

// ==================== SWIFT WALLET SERVICE ====================

class SwiftWalletService {
  constructor() {
    this.config = {
      baseURL: process.env.SWIFT_API_URL || 'https://api.swiftwallet.co.ke/v1',
      apiKey: process.env.SWIFT_API_KEY,
      headers: {
        'Authorization': `Bearer ${process.env.SWIFT_API_KEY}`,
        'Content-Type': 'application/json'
      }
    };
    this.client = axios.create(this.config);
  }

  async initiateSTKPush(phone, amount, reference, description) {
    try {
      const response = await this.client.post('/stk/push', {
        phone: this.formatPhone(phone),
        amount: amount,
        reference: reference,
        description: description,
        callback_url: `${process.env.RENDER_URL || 'http://localhost:10000'}/api/webhook/swift-callback`
      });

      return {
        success: true,
        checkoutRequestId: response.data.checkout_request_id,
        customerMessage: response.data.customer_message,
        swiftResponse: response.data
      };
    } catch (error) {
      console.error('Swift STK Push Error:', error.response?.data || error.message);
      return {
        success: false,
        error: error.response?.data?.message || 'Failed to initiate STK Push'
      };
    }
  }

  async sendMoney(phone, amount, reference, description) {
    try {
      const response = await this.client.post('/b2c/payment', {
        phone: this.formatPhone(phone),
        amount: amount,
        reference: reference,
        description: description,
        callback_url: `${process.env.RENDER_URL || 'http://localhost:10000'}/api/webhook/swift-callback`
      });

      return {
        success: true,
        transactionId: response.data.transaction_id,
        swiftResponse: response.data
      };
    } catch (error) {
      console.error('Swift Send Money Error:', error.response?.data || error.message);
      return {
        success: false,
        error: error.response?.data?.message || 'Failed to send money'
      };
    }
  }

  async checkPaybillAvailability(paybillNumber) {
    try {
      // Simulate PayBill check - in production, use actual Swift API
      return { available: true, registeredTo: 'BeraPay Merchant' };
    } catch (error) {
      return { available: false, error: error.message };
    }
  }

  async validateTillNumber(tillNumber) {
    try {
      // Simulate Till validation
      return { valid: true, businessName: 'BeraPay Merchant' };
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }

  async validateBankAccount(bankCode, accountNumber) {
    try {
      // Simulate bank validation
      return { valid: true, accountName: 'BeraPay Merchant' };
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }

  async bankTransfer(transferDetails) {
    try {
      // Simulate bank transfer
      return {
        success: true,
        transactionId: `BT${Date.now()}`,
        reference: transferDetails.reference
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  formatPhone(phone) {
    let cleaned = phone.replace(/\s+/g, '').replace('+', '');
    if (cleaned.startsWith('0') && cleaned.length === 10) {
      return '+254' + cleaned.substring(1);
    } else if (cleaned.startsWith('7') && cleaned.length === 9) {
      return '+254' + cleaned;
    } else if (cleaned.startsWith('254') && cleaned.length === 12) {
      return '+' + cleaned;
    }
    return '+' + cleaned;
  }
}

const swiftService = new SwiftWalletService();

// ==================== UTILS ====================

const calculateCommission = (amount, type) => {
  const commissionRate = 0.02;
  const commission = Math.round(amount * commissionRate * 100) / 100;
  const netAmount = Math.round((amount - commission) * 100) / 100;
  return { commission, netAmount, rate: commissionRate, type };
};

const validateAmount = (amount) => {
  return amount > 0 && amount <= 1000000;
};

const generateReference = (prefix) => {
  return `${prefix}${Date.now()}${Math.random().toString(36).substr(2, 6)}`;
};

// ==================== MIDDLEWARES ====================

const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || !user.isActive) {
      return res.status(401).json({ success: false, message: 'Token is invalid or user is inactive.' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: 'Token is invalid.' });
  }
};

const adminMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || !user.isActive || user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Admin access required.' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: 'Token is invalid.' });
  }
};

const merchantAuth = async (req, res, next) => {
  try {
    const apiKey = req.header('X-API-Key');
    const signature = req.header('X-Signature');
    
    if (!apiKey || !signature) {
      return res.status(401).json({ success: false, message: 'API Key and Signature required' });
    }

    const merchant = await Merchant.findOne({ apiKey, isActive: true });
    if (!merchant) {
      return res.status(401).json({ success: false, message: 'Invalid API Key' });
    }

    // Simple signature verification (enhance in production)
    const expectedSignature = crypto
      .createHmac('sha256', merchant.secretKey)
      .update(JSON.stringify(req.body))
      .digest('hex');

    if (signature !== expectedSignature) {
      return res.status(401).json({ success: false, message: 'Invalid signature' });
    }

    req.merchant = merchant;
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: 'Authentication failed' });
  }
};

// ==================== USER CONTROLLERS ====================

const registerUser = async (req, res) => {
  try {
    const { name, phone, email, password } = req.body;

    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'User already exists' });
    }

    // Create admin user if specific email
    const role = email === 'admin@berapay.com' ? 'admin' : 'user';
    
    const user = new User({ name, phone, email, password, role });
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });

    res.status(201).json({ success: true, message: 'User registered successfully', token, user });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, isActive: true });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });

    res.json({ success: true, message: 'Login successful', token, user });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

const getProfile = async (req, res) => {
  res.json({ success: true, user: req.user });
};

// ==================== PAYMENT CONTROLLERS ====================

const initiateSTKPush = async (req, res) => {
  try {
    const { amount, phone, description = 'BeraPay Deposit' } = req.body;
    const userId = req.user._id;

    if (!validateAmount(amount)) {
      return res.status(400).json({ success: false, message: 'Invalid amount' });
    }

    const commissionDetails = calculateCommission(amount, 'deposit');
    const reference = generateReference('DP');

    const transaction = new Transaction({
      userId,
      amount,
      type: 'deposit',
      status: 'pending',
      commission: commissionDetails.commission,
      netAmount: commissionDetails.netAmount,
      phone,
      description,
      reference,
      paymentMethod: 'stk_push'
    });

    await transaction.save();

    const swiftResponse = await swiftService.initiateSTKPush(phone, amount, reference, description);

    if (!swiftResponse.success) {
      transaction.status = 'failed';
      transaction.metadata = { error: swiftResponse.error };
      await transaction.save();
      return res.status(400).json({ success: false, message: `Payment failed: ${swiftResponse.error}` });
    }

    transaction.swiftReference = swiftResponse.checkoutRequestId;
    await transaction.save();

    res.json({
      success: true,
      message: 'Payment prompt sent! Check your phone.',
      transaction: {
        id: transaction._id,
        amount: transaction.amount,
        commission: transaction.commission,
        netAmount: transaction.netAmount,
        reference: transaction.reference,
        status: transaction.status,
      },
      swiftResponse: {
        checkoutRequestId: swiftResponse.checkoutRequestId,
        customerMessage: swiftResponse.customerMessage
      },
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

const initiateWithdrawal = async (req, res) => {
  try {
    const { amount, phone, description = 'BeraPay Withdrawal' } = req.body;
    const userId = req.user._id;

    if (!validateAmount(amount)) {
      return res.status(400).json({ success: false, message: 'Invalid amount' });
    }

    const user = await User.findById(userId);
    if (user.balance < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }

    const commissionDetails = calculateCommission(amount, 'withdrawal');
    const reference = generateReference('WD');

    const transaction = new Transaction({
      userId,
      amount,
      type: 'withdrawal',
      status: 'pending',
      commission: commissionDetails.commission,
      netAmount: commissionDetails.netAmount,
      phone,
      description,
      reference,
      paymentMethod: 'mobile'
    });

    await transaction.save();

    user.balance -= amount;
    await user.save();

    const swiftResponse = await swiftService.sendMoney(phone, commissionDetails.netAmount, reference, description);

    if (!swiftResponse.success) {
      user.balance += amount;
      await user.save();
      transaction.status = 'failed';
      transaction.metadata = { error: swiftResponse.error };
      await transaction.save();
      return res.status(400).json({ success: false, message: `Withdrawal failed: ${swiftResponse.error}` });
    }

    transaction.swiftReference = swiftResponse.transactionId;
    await transaction.save();

    res.json({
      success: true,
      message: 'Withdrawal initiated successfully',
      transaction: {
        id: transaction._id,
        amount: transaction.amount,
        commission: transaction.commission,
        netAmount: transaction.netAmount,
        reference: transaction.reference,
        status: transaction.status,
      }
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

const getTransactions = async (req, res) => {
  try {
    const userId = req.user._id;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const type = req.query.type;
    const skip = (page - 1) * limit;

    const query = { userId };
    if (type) query.type = type;

    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Transaction.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    res.json({ success: true, transactions, pagination: { page, limit, total, totalPages } });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

const getBalance = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('balance name email phone');
    res.json({ success: true, balance: user.balance, user });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

// ==================== MERCHANT CONTROLLERS ====================

const registerMerchant = async (req, res) => {
  try {
    const { companyName, email, webhookUrl } = req.body;

    const existingMerchant = await Merchant.findOne({ email });
    if (existingMerchant) {
      return res.status(400).json({ success: false, message: 'Merchant already exists' });
    }

    const apiKey = crypto.randomBytes(32).toString('hex');
    const secretKey = crypto.randomBytes(64).toString('hex');

    const merchant = new Merchant({
      companyName,
      email,
      apiKey,
      secretKey,
      webhookUrl
    });

    await merchant.save();

    res.json({
      success: true,
      message: 'Merchant registered successfully',
      apiKey,
      secretKey,
      merchant: { id: merchant._id, companyName, email }
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

const merchantRequestPayment = async (req, res) => {
  try {
    const { customerPhone, amount, reference, description, metadata } = req.body;
    const merchant = req.merchant;

    if (!validateAmount(amount)) {
      return res.status(400).json({ success: false, message: 'Invalid amount' });
    }

    const swiftCommission = amount * 0.02;
    const platformCommission = amount * merchant.commissionRate;
    const merchantReceives = amount - swiftCommission - platformCommission;

    const transaction = new Transaction({
      merchantId: merchant._id,
      customerPhone,
      amount,
      reference: reference || generateReference('MR'),
      description,
      type: 'payment',
      status: 'pending',
      swiftCommission,
      platformCommission,
      netAmount: merchantReceives,
      paymentMethod: 'stk_push',
      metadata
    });

    await transaction.save();

    const swiftResponse = await swiftService.initiateSTKPush(
      customerPhone,
      amount,
      transaction.reference,
      `${merchant.companyName}: ${description}`
    );

    if (!swiftResponse.success) {
      transaction.status = 'failed';
      await transaction.save();
      return res.status(400).json({ success: false, message: `Payment request failed: ${swiftResponse.error}` });
    }

    transaction.swiftReference = swiftResponse.checkoutRequestId;
    await transaction.save();

    res.json({
      success: true,
      message: 'Payment request sent to customer',
      transactionId: transaction._id,
      reference: transaction.reference,
      swiftResponse: {
        checkoutRequestId: swiftResponse.checkoutRequestId,
        customerMessage: swiftResponse.customerMessage
      }
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

const setupPaybill = async (req, res) => {
  try {
    const { paybillNumber, accountNumber } = req.body;
    const merchant = req.merchant;

    const swiftResponse = await swiftService.checkPaybillAvailability(paybillNumber);
    if (!swiftResponse.available) {
      return res.status(400).json({ success: false, message: 'PayBill not available' });
    }

    const paybillChannel = new PaymentChannel({
      merchantId: merchant._id,
      channelType: 'paybill',
      paybillNumber,
      paybillAccount: accountNumber,
      isDefault: true
    });

    await paybillChannel.save();

    res.json({
      success: true,
      message: 'PayBill configured successfully',
      paybill: { number: paybillNumber, account: accountNumber }
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

const merchantGetBalance = async (req, res) => {
  try {
    const merchant = req.merchant;
    
    const stats = await Transaction.aggregate([
      { $match: { merchantId: merchant._id } },
      {
        $group: {
          _id: null,
          totalVolume: { $sum: '$amount' },
          totalTransactions: { $sum: 1 },
          totalFees: { $sum: '$platformCommission' },
          successfulTransactions: { $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] } }
        }
      }
    ]);

    res.json({
      success: true,
      dashboard: {
        balance: merchant.balance,
        totalEarnings: merchant.totalEarnings,
        totalVolume: stats[0]?.totalVolume || 0,
        totalTransactions: stats[0]?.totalTransactions || 0,
        successRate: stats[0] ? (stats[0].successfulTransactions / stats[0].totalTransactions) * 100 : 0
      }
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

// ==================== ADMIN CONTROLLERS ====================

const getAdminSummary = async (req, res) => {
  try {
    const adminWallet = await AdminWallet.getWallet();
    const totalUsers = await User.countDocuments({ isActive: true });
    const totalMerchants = await Merchant.countDocuments({ isActive: true });

    const depositStats = await Transaction.aggregate([
      { $match: { type: 'deposit', status: 'completed' } },
      { $group: { _id: null, totalAmount: { $sum: '$amount' }, count: { $sum: 1 } } }
    ]);

    const paymentStats = await Transaction.aggregate([
      { $match: { type: 'payment', status: 'completed' } },
      { $group: { _id: null, totalAmount: { $sum: '$amount' }, count: { $sum: 1 } } }
    ]);

    const commissionStats = await Commission.aggregate([
      { $group: { _id: null, totalCommission: { $sum: '$amount' }, count: { $sum: 1 } } }
    ]);

    const platformEarnings = await Transaction.aggregate([
      { $match: { status: 'completed', platformCommission: { $gt: 0 } } },
      { $group: { _id: null, totalPlatform: { $sum: '$platformCommission' } } }
    ]);

    const recentTransactions = await Transaction.find()
      .populate('userId', 'name email')
      .populate('merchantId', 'companyName')
      .sort({ createdAt: -1 })
      .limit(10)
      .lean();

    const userGrowth = await User.aggregate([
      { $match: { createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } } },
      { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, count: { $sum: 1 } } },
      { $sort: { _id: 1 } }
    ]);

    res.json({
      success: true,
      summary: {
        totalUsers,
        totalMerchants,
        totalDeposits: depositStats[0]?.totalAmount || 0,
        totalPayments: paymentStats[0]?.totalAmount || 0,
        totalTransactions: adminWallet.totalTransactions,
        totalCommission: commissionStats[0]?.totalCommission || 0,
        platformEarnings: platformEarnings[0]?.totalPlatform || 0,
        adminWallet: adminWallet.totalCommission
      },
      recentTransactions,
      userGrowth,
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

const getUsers = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const search = req.query.search;
    const skip = (page - 1) * limit;

    const query = { isActive: true };
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } },
      ];
    }

    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await User.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    for (let user of users) {
      const transactionCount = await Transaction.countDocuments({ userId: user._id });
      user.transactionCount = transactionCount;
    }

    res.json({ success: true, users, pagination: { page, limit, total, totalPages } });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

const getMerchants = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const search = req.query.search;
    const skip = (page - 1) * limit;

    const query = { isActive: true };
    if (search) {
      query.companyName = { $regex: search, $options: 'i' };
    }

    const merchants = await Merchant.find(query)
      .select('-secretKey')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Merchant.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    for (let merchant of merchants) {
      const transactionStats = await Transaction.aggregate([
        { $match: { merchantId: merchant._id, status: 'completed' } },
        { $group: { _id: null, totalVolume: { $sum: '$amount' }, count: { $sum: 1 } } }
      ]);
      merchant.totalVolume = transactionStats[0]?.totalVolume || 0;
      merchant.transactionCount = transactionStats[0]?.count || 0;
    }

    res.json({ success: true, merchants, pagination: { page, limit, total, totalPages } });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

// ==================== WEBHOOK CONTROLLERS ====================

const handleSwiftWebhook = async (req, res) => {
  try {
    const { body } = req;
    console.log('Swift Webhook Received:', JSON.stringify(body, null, 2));

    const { checkout_request_id, merchant_request_id, result_code, result_desc, callback_metadata, transaction_id, amount, phone, reference } = body;

    const transaction = await Transaction.findOne({
      $or: [
        { swiftReference: checkout_request_id },
        { swiftReference: merchant_request_id },
        { swiftReference: transaction_id },
        { reference: reference }
      ]
    }).populate('userId merchantId');

    if (!transaction) {
      return res.status(404).json({ success: false, message: 'Transaction not found' });
    }

    if (result_code === 0) {
      transaction.status = 'completed';
      
      if (transaction.type === 'deposit' && transaction.userId) {
        const user = await User.findById(transaction.userId);
        user.balance += transaction.netAmount;
        await user.save();

        const commission = new Commission({
          transactionId: transaction._id,
          userId: transaction.userId,
          amount: transaction.commission,
          transactionAmount: transaction.amount,
          type: transaction.type,
        });
        await commission.save();

        const adminWallet = await AdminWallet.getWallet();
        adminWallet.totalCommission += transaction.commission;
        adminWallet.totalTransactions += 1;
        adminWallet.totalDeposits += transaction.amount;
        await adminWallet.save();
      }

      if (transaction.type === 'payment' && transaction.merchantId) {
        const merchant = await Merchant.findById(transaction.merchantId);
        merchant.balance += transaction.netAmount;
        merchant.totalEarnings += transaction.platformCommission;
        await merchant.save();

        const commission = new Commission({
          transactionId: transaction._id,
          merchantId: transaction.merchantId,
          amount: transaction.swiftCommission,
          transactionAmount: transaction.amount,
          type: transaction.type,
        });
        await commission.save();

        const adminWallet = await AdminWallet.getWallet();
        adminWallet.totalCommission += transaction.swiftCommission;
        adminWallet.totalPlatformEarnings += transaction.platformCommission;
        adminWallet.totalTransactions += 1;
        await adminWallet.save();

        if (merchant.webhookUrl) {
          await axios.post(merchant.webhookUrl, {
            event: 'payment.received',
            transactionId: transaction._id,
            amount: transaction.amount,
            netAmount: transaction.netAmount,
            customerPhone: transaction.customerPhone,
            reference: transaction.reference
          }).catch(err => console.error('Webhook failed:', err));
        }
      }

      await transaction.save();
      console.log(`✅ Transaction ${transaction._id} completed`);

    } else {
      transaction.status = 'failed';
      transaction.metadata = { failureReason: result_desc, swiftWebhook: body };

      if (transaction.type === 'withdrawal' && transaction.userId) {
        const user = await User.findById(transaction.userId);
        user.balance += transaction.amount;
        await user.save();
      }

      await transaction.save();
      console.log(`❌ Transaction ${transaction._id} failed: ${result_desc}`);
    }

    res.json({ success: true, message: 'Webhook processed' });
  } catch (error) {
    console.error('Swift webhook error:', error);
    res.status(500).json({ success: false, message: 'Webhook processing failed' });
  }
};

// ==================== ROUTES ====================

// User Routes
app.post('/api/users/register', registerUser);
app.post('/api/users/login', loginUser);
app.get('/api/users/profile', authMiddleware, getProfile);

// Payment Routes
app.post('/api/payments/stkpush', authMiddleware, initiateSTKPush);
app.post('/api/payments/withdraw', authMiddleware, initiateWithdrawal);
app.get('/api/payments/transactions', authMiddleware, getTransactions);
app.get('/api/payments/balance', authMiddleware, getBalance);

// Merchant Routes
app.post('/api/merchants/register', registerMerchant);
app.post('/api/v1/merchant/request-payment', merchantAuth, merchantRequestPayment);
app.post('/api/v1/merchant/paybill/setup', merchantAuth, setupPaybill);
app.get('/api/v1/merchant/dashboard', merchantAuth, merchantGetBalance);

// Admin Routes
app.get('/api/admin/summary', adminMiddleware, getAdminSummary);
app.get('/api/admin/users', adminMiddleware, getUsers);
app.get('/api/admin/merchants', adminMiddleware, getMerchants);

// Webhook Routes
app.post('/api/webhook/swift-callback', handleSwiftWebhook);

// ==================== FIXED FRONTEND ROUTES ====================

// Serve login page as default
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve specific pages with proper routing
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (user.role === 'admin') {
      res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
    } else {
      res.sendFile(path.join(__dirname, 'public', 'user-dashboard.html'));
    }
  } catch (error) {
    res.redirect('/login');
  }
});

app.get('/user-dashboard', authMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'user-dashboard.html'));
});

app.get('/admin-dashboard', adminMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

app.get('/merchant-dashboard', authMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'merchant-dashboard.html'));
});

// API Info
app.get('/api', (req, res) => {
  res.json({ 
    message: 'BeraPay API is running!',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK',
    database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    timestamp: new Date().toISOString()
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    success: false, 
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'production' ? {} : err.message 
  });
});

app.use('/api/*', (req, res) => {
  res.status(404).json({ success: false, message: 'API endpoint not found' });
});

// 404 handler - redirect to login
app.get('*', (req, res) => {
  res.redirect('/login');
});

// Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🚀 BeraPay server running on port ${PORT}`);
  console.log(`📍 Login: http://localhost:${PORT}`);
  console.log(`🔐 Admin: admin@berapay.com / admin123`);
});
