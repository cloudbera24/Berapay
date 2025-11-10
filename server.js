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

// PayHero Service
const payhero = new PayHero({
  authToken: process.env.AUTH_TOKEN,
  channelId: process.env.CHANNEL_ID,
  defaultProvider: process.env.DEFAULT_PROVIDER
});

// MongoDB Models
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  phone: { type: String, unique: true },
  password: String,
  wallet_balance: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const transactionSchema = new mongoose.Schema({
  user_id: mongoose.Schema.Types.ObjectId,
  type: String,
  amount: Number,
  status: { type: String, default: 'pending' },
  commission: { type: Number, default: 0 },
  external_reference: String,
  recipient_phone: String,
  description: String,
  createdAt: { type: Date, default: Date.now }
});

const adminSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: 'admin' },
  createdAt: { type: Date, default: Date.now }
});

const developerSchema = new mongoose.Schema({
  developer_name: String,
  api_key: String,
  quota: { type: Number, default: 1000 },
  usage: { type: Number, default: 0 },
  is_active: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

// Pre-save middleware for hashing
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

adminSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

developerSchema.pre('save', async function(next) {
  if (this.isNew && !this.api_key) {
    this.api_key = await bcrypt.hash(Math.random().toString(36), 12);
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

// Auth Middleware
const authUser = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token' });
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) return res.status(401).json({ error: 'Invalid token' });
    
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const authAdmin = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token' });
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.adminId).select('-password');
    if (!admin) return res.status(401).json({ error: 'Invalid admin token' });
    
    req.admin = admin;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid admin token' });
  }
};

const authDeveloper = async (req, res, next) => {
  try {
    const apiKey = req.header('X-API-Key');
    if (!apiKey) return res.status(401).json({ error: 'No API key' });
    
    const developer = await DeveloperKey.findOne({ is_active: true });
    if (!developer) return res.status(401).json({ error: 'Invalid API key' });
    
    const isValid = await bcrypt.compare(apiKey, developer.api_key);
    if (!isValid) return res.status(401).json({ error: 'Invalid API key' });
    
    if (developer.usage >= developer.quota) {
      return res.status(429).json({ error: 'Quota exceeded' });
    }
    
    developer.usage += 1;
    await developer.save();
    req.developer = developer;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid API key' });
  }
};

// PayHero Service Functions
const formatPhone = (phone) => {
  let formatted = phone.replace(/\s+/g, '');
  if (formatted.startsWith('0')) formatted = '254' + formatted.substring(1);
  if (formatted.startsWith('+254')) formatted = formatted.substring(1);
  return formatted;
};

const calculateCommission = (amount) => Number((amount * 0.02).toFixed(2));

// User Routes
app.post('/api/users/register', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;
    
    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) return res.status(400).json({ error: 'User exists' });
    
    const user = new User({ name, email, phone, password });
    await user.save();
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.status(201).json({
      message: 'Registered successfully',
      token,
      user: { id: user._id, name, email, phone, wallet_balance: user.wallet_balance }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      message: 'Login successful',
      token,
      user: { id: user._id, name: user.name, email: user.email, phone: user.phone, wallet_balance: user.wallet_balance }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/users/profile', authUser, (req, res) => {
  res.json({ user: req.user });
});

app.post('/api/users/deposit', authUser, async (req, res) => {
  try {
    const { amount, phone } = req.body;
    if (!amount || amount < 1) return res.status(400).json({ error: 'Amount min KES 1' });
    
    const reference = `DEP_${Date.now()}_${req.user._id}`;
    const transaction = new Transaction({
      user_id: req.user._id,
      type: 'deposit',
      amount,
      status: 'pending',
      external_reference: reference
    });
    await transaction.save();
    
    const result = await payhero.stkPush({
      phone: formatPhone(phone || req.user.phone),
      amount: Math.round(amount),
      reference
    });
    
    res.json({
      message: 'Deposit initiated',
      transactionId: transaction._id,
      reference: result.reference
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/users/withdraw', authUser, async (req, res) => {
  try {
    const { amount, phone } = req.body;
    if (!amount || amount < 1) return res.status(400).json({ error: 'Amount min KES 1' });
    if (req.user.wallet_balance < amount) return res.status(400).json({ error: 'Insufficient balance' });
    
    const commission = calculateCommission(amount);
    const netAmount = amount - commission;
    const reference = `WD_${Date.now()}_${req.user._id}`;
    
    const transaction = new Transaction({
      user_id: req.user._id,
      type: 'withdrawal',
      amount,
      status: 'pending',
      commission,
      external_reference: reference
    });
    await transaction.save();
    
    await User.findByIdAndUpdate(req.user._id, { $inc: { wallet_balance: -amount } });
    
    const result = await payhero.withdraw({
      phone: formatPhone(phone || req.user.phone),
      amount: Math.round(netAmount),
      reference
    });
    
    res.json({
      message: 'Withdrawal initiated',
      transactionId: transaction._id,
      reference: result.reference,
      commission,
      netAmount
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/users/balance', authUser, async (req, res) => {
  try {
    const balance = await payhero.balance();
    res.json({
      wallet_balance: req.user.wallet_balance,
      system_balance: balance.availableBalance || 0
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/users/transactions', authUser, async (req, res) => {
  try {
    const transactions = await Transaction.find({ user_id: req.user._id })
      .sort({ createdAt: -1 })
      .limit(20);
    
    res.json({ transactions });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/users/transfer', authUser, async (req, res) => {
  try {
    const { recipient_phone, amount, description } = req.body;
    if (!amount || amount < 1) return res.status(400).json({ error: 'Amount min KES 1' });
    if (req.user.wallet_balance < amount) return res.status(400).json({ error: 'Insufficient balance' });
    
    const recipient = await User.findOne({ phone: recipient_phone });
    if (!recipient) return res.status(404).json({ error: 'Recipient not found' });
    if (recipient._id.toString() === req.user._id.toString()) return res.status(400).json({ error: 'Cannot transfer to self' });
    
    const commission = calculateCommission(amount);
    const netAmount = amount - commission;
    
    const senderTransaction = new Transaction({
      user_id: req.user._id,
      type: 'transfer',
      amount: -amount,
      status: 'successful',
      commission,
      external_reference: `TR_${Date.now()}_${req.user._id}`,
      recipient_phone,
      description: description || `Transfer to ${recipient_phone}`
    });
    
    const recipientTransaction = new Transaction({
      user_id: recipient._id,
      type: 'transfer',
      amount: netAmount,
      status: 'successful',
      external_reference: `TR_${Date.now()}_${req.user._id}`,
      recipient_phone: req.user.phone,
      description: description || `Transfer from ${req.user.phone}`
    });
    
    await User.findByIdAndUpdate(req.user._id, { $inc: { wallet_balance: -amount } });
    await User.findByIdAndUpdate(recipient._id, { $inc: { wallet_balance: netAmount } });
    await senderTransaction.save();
    await recipientTransaction.save();
    
    res.json({
      message: 'Transfer successful',
      transactionId: senderTransaction._id,
      commission,
      netAmount,
      recipient: { name: recipient.name, phone: recipient.phone }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin Routes
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = await Admin.findOne({ email });
    
    if (!admin || !(await admin.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }
    
    const token = jwt.sign({ adminId: admin._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      message: 'Admin login successful',
      token,
      admin: { id: admin._id, name: admin.name, email: admin.email, role: admin.role }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/users', authAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 }).limit(50);
    res.json({ users });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/transactions', authAdmin, async (req, res) => {
  try {
    const transactions = await Transaction.find()
      .populate('user_id', 'name email phone')
      .sort({ createdAt: -1 })
      .limit(50);
    
    const totalCommission = await Transaction.aggregate([
      { $match: { status: 'successful' } },
      { $group: { _id: null, total: { $sum: '$commission' } } }
    ]);
    
    res.json({
      transactions,
      totalCommission: totalCommission[0]?.total || 0
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/stats', authAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
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
    
    res.json({
      totalUsers,
      totalTransactions,
      totalVolume: totalVolume[0]?.total || 0,
      totalCommission: totalCommission[0]?.total || 0,
      systemBalance: balance.availableBalance || 0
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Developer API Routes
app.post('/api/v1/deposit', authDeveloper, async (req, res) => {
  try {
    const { phone, amount, reference } = req.body;
    if (!phone || !amount || amount < 1) return res.status(400).json({ error: 'Phone and amount required' });
    
    const user = await User.findOne({ phone });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    const txReference = reference || `DEV_DEP_${Date.now()}_${user._id}`;
    const transaction = new Transaction({
      user_id: user._id,
      type: 'deposit',
      amount,
      status: 'pending',
      external_reference: txReference
    });
    await transaction.save();
    
    const result = await payhero.stkPush({
      phone: formatPhone(phone),
      amount: Math.round(amount),
      reference: txReference
    });
    
    res.json({
      success: true,
      message: 'Deposit initiated',
      transactionId: transaction._id,
      reference: result.reference
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/v1/withdraw', authDeveloper, async (req, res) => {
  try {
    const { phone, amount, reference } = req.body;
    if (!phone || !amount || amount < 1) return res.status(400).json({ error: 'Phone and amount required' });
    
    const user = await User.findOne({ phone });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.wallet_balance < amount) return res.status(400).json({ error: 'Insufficient balance' });
    
    const commission = calculateCommission(amount);
    const netAmount = amount - commission;
    const txReference = reference || `DEV_WD_${Date.now()}_${user._id}`;
    
    const transaction = new Transaction({
      user_id: user._id,
      type: 'withdrawal',
      amount,
      status: 'pending',
      commission,
      external_reference: txReference
    });
    await transaction.save();
    
    await User.findByIdAndUpdate(user._id, { $inc: { wallet_balance: -amount } });
    
    const result = await payhero.withdraw({
      phone: formatPhone(phone),
      amount: Math.round(netAmount),
      reference: txReference
    });
    
    res.json({
      success: true,
      message: 'Withdrawal initiated',
      transactionId: transaction._id,
      reference: result.reference,
      commission,
      netAmount
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/v1/balance', authDeveloper, async (req, res) => {
  try {
    const { phone } = req.query;
    if (!phone) return res.status(400).json({ error: 'Phone required' });
    
    const user = await User.findOne({ phone }).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    
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
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/v1/transactions', authDeveloper, async (req, res) => {
  try {
    const { phone } = req.query;
    if (!phone) return res.status(400).json({ error: 'Phone required' });
    
    const user = await User.findOne({ phone });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    const transactions = await Transaction.find({ user_id: user._id })
      .sort({ createdAt: -1 })
      .limit(20);
    
    res.json({ success: true, transactions });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Initialize default admin and developer
async function initializeDefaults() {
  try {
    const adminExists = await Admin.findOne({ email: 'admin@berapay.com' });
    if (!adminExists) {
      const admin = new Admin({
        name: 'System Admin',
        email: 'admin@berapay.com',
        password: 'admin123'
      });
      await admin.save();
      console.log('Default admin created: admin@berapay.com / admin123');
    }
    
    const devExists = await DeveloperKey.findOne();
    if (!devExists) {
      const dev = new DeveloperKey({
        developer_name: 'BeraPay Developer',
        quota: 10000
      });
      await dev.save();
      console.log('Default developer key created');
    }
  } catch (error) {
    console.log('Initialization note:', error.message);
  }
}

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('MongoDB connected');
    initializeDefaults();
    
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`BeraPay running on port ${PORT}`);
      console.log(`Frontend: http://localhost:${PORT}`);
      console.log(`API: http://localhost:${PORT}/api`);
    });
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });
