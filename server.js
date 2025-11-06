require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const path = require('path');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const { User, Transaction, Session } = require('./models');

const app = express();
const PORT = process.env.PORT || 3000;

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/errors.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Security middleware
app.use(helmet());
app.use(compression());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => logger.info('✅ MongoDB connected successfully'))
.catch(err => logger.error('❌ MongoDB connection error:', err));

// Utility functions
function generateRef() {
  return 'TX' + Date.now() + Math.random().toString(36).substr(2, 9).toUpperCase();
}

function generateCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function formatPhone(phone) {
  let cleaned = phone.replace(/\D/g, '');
  if (cleaned.startsWith('0')) {
    cleaned = '254' + cleaned.substring(1);
  } else if (!cleaned.startsWith('254')) {
    cleaned = '254' + cleaned;
  }
  return cleaned;
}

// PayHero API functions
async function initiateSTKPush(phone, amount, reference) {
  try {
    const response = await axios.post('https://api.payhero.co.ke/v2/stkpush', {
      amount: amount,
      phone: formatPhone(phone),
      callback_url: process.env.PAYHERO_CALLBACK_URL,
      reference: reference
    }, {
      headers: {
        'Authorization': process.env.AUTH_TOKEN,
        'Content-Type': 'application/json'
      }
    });

    return { success: true, data: response.data };
  } catch (error) {
    logger.error('STK Push Error:', error.response?.data || error.message);
    return { success: false, error: error.response?.data || error.message };
  }
}

async function disburseFunds(phone, amount, reference) {
  try {
    const response = await axios.post('https://api.payhero.co.ke/v2/disburse', {
      amount: amount,
      phone: formatPhone(phone),
      channel_id: process.env.CHANNEL_ID,
      provider: process.env.DEFAULT_PROVIDER,
      reference: reference
    }, {
      headers: {
        'Authorization': process.env.AUTH_TOKEN,
        'Content-Type': 'application/json'
      }
    });

    return { success: true, data: response.data };
  } catch (error) {
    logger.error('Disbursement Error:', error.response?.data || error.message);
    return { success: false, error: error.response?.data || error.message };
  }
}

// API Routes

// Send verification code
app.get('/api/send-code', async (req, res) => {
  try {
    const { phone } = req.query;
    if (!phone) {
      return res.status(400).json({ error: 'Phone number is required' });
    }

    const formattedPhone = formatPhone(phone);
    const code = generateCode();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    // Delete any existing sessions for this phone
    await Session.deleteMany({ phone: formattedPhone });

    // Create new session
    const session = new Session({
      phone: formattedPhone,
      code: code,
      expiresAt: expiresAt
    });
    await session.save();

    // In production, integrate with your WhatsApp bot here
    logger.info(`Verification code for ${formattedPhone}: ${code}`);

    res.json({ 
      success: true, 
      message: 'Verification code sent via WhatsApp',
      code: process.env.NODE_ENV === 'development' ? code : undefined 
    });
  } catch (error) {
    logger.error('Send code error:', error);
    res.status(500).json({ error: 'Failed to send verification code' });
  }
});

// Verify code and login
app.post('/api/verify-code', async (req, res) => {
  try {
    const { phone, code } = req.body;
    if (!phone || !code) {
      return res.status(400).json({ error: 'Phone and code are required' });
    }

    const formattedPhone = formatPhone(phone);
    const session = await Session.findOne({ 
      phone: formattedPhone, 
      code: code,
      expiresAt: { $gt: new Date() }
    });

    if (!session) {
      return res.status(400).json({ error: 'Invalid or expired code' });
    }

    session.verified = true;
    await session.save();

    // Check if user exists
    let user = await User.findOne({ phone: formattedPhone });
    const isNewUser = !user;

    // Generate JWT token
    const token = jwt.sign(
      { phone: formattedPhone, userId: user?._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '24h' }
    );

    res.json({ 
      success: true, 
      token, 
      isNewUser,
      message: isNewUser ? 'Please complete registration' : 'Login successful'
    });
  } catch (error) {
    logger.error('Verify code error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Register user
app.post('/api/register', async (req, res) => {
  try {
    const { phone, name, pin } = req.body;
    if (!phone || !name || !pin) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const formattedPhone = formatPhone(phone);
    
    // Verify session
    const session = await Session.findOne({ 
      phone: formattedPhone, 
      verified: true,
      expiresAt: { $gt: new Date() }
    });

    if (!session) {
      return res.status(400).json({ error: 'Session expired or not verified' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ phone: formattedPhone });
    if (existingUser) {
      return res.status(400).json({ error: 'User already registered' });
    }

    // Hash PIN
    const pinHash = await bcrypt.hash(pin, 12);

    // Create user
    const user = new User({
      name: name.trim(),
      phone: formattedPhone,
      pinHash: pinHash,
      balance: 0
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { phone: formattedPhone, userId: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '24h' }
    );

    res.json({ 
      success: true, 
      token, 
      message: 'Registration successful',
      user: { name: user.name, phone: user.phone, balance: user.balance }
    });
  } catch (error) {
    logger.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Get balance
app.get('/api/balance', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ phone: decoded.phone });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ 
      success: true, 
      balance: user.balance,
      name: user.name 
    });
  } catch (error) {
    logger.error('Balance error:', error);
    res.status(500).json({ error: 'Failed to fetch balance' });
  }
});

// Deposit via STK Push
app.post('/api/deposit', async (req, res) => {
  try {
    const { amount, pin } = req.body;
    const token = req.headers.authorization?.replace('Bearer ', '');

    if (!token || !amount || !pin) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ phone: decoded.phone });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify PIN
    const isPinValid = await user.verifyPin(pin);
    if (!isPinValid) {
      return res.status(400).json({ error: 'Invalid PIN' });
    }

    const reference = generateRef();
    
    // Create transaction record
    const transaction = new Transaction({
      ref: reference,
      sender: user.phone,
      receiver: user.phone,
      amount: parseFloat(amount),
      type: 'deposit',
      status: 'pending',
      description: `Deposit to BeraPay wallet`
    });
    await transaction.save();

    // Initiate STK Push
    const stkResult = await initiateSTKPush(user.phone, amount, reference);
    
    if (!stkResult.success) {
      transaction.status = 'failed';
      await transaction.save();
      return res.status(400).json({ error: 'STK Push failed: ' + stkResult.error });
    }

    res.json({ 
      success: true, 
      message: 'STK Push initiated. Check your phone to complete payment.',
      reference: reference
    });
  } catch (error) {
    logger.error('Deposit error:', error);
    res.status(500).json({ error: 'Deposit failed' });
  }
});

// Send money
app.post('/api/send', async (req, res) => {
  try {
    const { recipient, amount, pin } = req.body;
    const token = req.headers.authorization?.replace('Bearer ', '');

    if (!token || !recipient || !amount || !pin) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const sender = await User.findOne({ phone: decoded.phone });
    
    if (!sender) {
      return res.status(404).json({ error: 'Sender not found' });
    }

    // Verify PIN
    const isPinValid = await sender.verifyPin(pin);
    if (!isPinValid) {
      return res.status(400).json({ error: 'Invalid PIN' });
    }

    // Check balance
    if (sender.balance < parseFloat(amount)) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const formattedRecipient = formatPhone(recipient);
    const reference = generateRef();

    // Check if recipient exists
    let recipientUser = await User.findOne({ phone: formattedRecipient });
    
    if (!recipientUser) {
      // Send via PayHero disbursement to any M-Pesa number
      const disbursement = await disburseFunds(formattedRecipient, amount, reference);
      
      if (!disbursement.success) {
        return res.status(400).json({ error: 'Disbursement failed: ' + disbursement.error });
      }

      // Deduct from sender
      sender.balance -= parseFloat(amount);
      await sender.save();

      // Create transaction record
      const transaction = new Transaction({
        ref: reference,
        sender: sender.phone,
        receiver: formattedRecipient,
        amount: parseFloat(amount),
        type: 'send',
        status: 'completed',
        providerRef: disbursement.data?.transaction_id,
        description: `Send money to ${formattedRecipient}`
      });
      await transaction.save();

      res.json({ 
        success: true, 
        message: `KSh ${amount} sent to ${formattedRecipient} successfully`,
        reference: reference,
        newBalance: sender.balance
      });
    } else {
      // Internal transfer
      sender.balance -= parseFloat(amount);
      recipientUser.balance += parseFloat(amount);
      
      await sender.save();
      await recipientUser.save();

      // Create transaction record
      const transaction = new Transaction({
        ref: reference,
        sender: sender.phone,
        receiver: recipientUser.phone,
        amount: parseFloat(amount),
        type: 'send',
        status: 'completed',
        description: `Send money to ${recipientUser.name}`
      });
      await transaction.save();

      res.json({ 
        success: true, 
        message: `KSh ${amount} sent to ${recipientUser.name} successfully`,
        reference: reference,
        newBalance: sender.balance
      });
    }
  } catch (error) {
    logger.error('Send money error:', error);
    res.status(500).json({ error: 'Send money failed' });
  }
});

// Get transactions
app.get('/api/transactions', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const transactions = await Transaction.find({
      $or: [{ sender: decoded.phone }, { receiver: decoded.phone }]
    })
    .sort({ createdAt: -1 })
    .limit(10);

    res.json({ 
      success: true, 
      transactions: transactions.map(tx => ({
        ref: tx.ref,
        type: tx.type,
        amount: tx.amount,
        status: tx.status,
        description: tx.description,
        date: tx.createdAt,
        isOutgoing: tx.sender === decoded.phone
      }))
    });
  } catch (error) {
    logger.error('Transactions error:', error);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// PayHero callback
app.post('/api/payhero/callback', async (req, res) => {
  try {
    const { reference, status, transaction_id, amount } = req.body;
    
    logger.info('PayHero callback received:', { reference, status, transaction_id, amount });

    const transaction = await Transaction.findOne({ ref: reference });
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    if (status === 'success' && transaction.status === 'pending') {
      transaction.status = 'completed';
      transaction.providerRef = transaction_id;

      // Update user balance for deposits
      if (transaction.type === 'deposit' && transaction.sender === transaction.receiver) {
        const user = await User.findOne({ phone: transaction.sender });
        if (user) {
          user.balance += parseFloat(amount);
          await user.save();
        }
      }

      await transaction.save();
      logger.info(`Transaction ${reference} completed successfully`);
    } else if (status === 'failed') {
      transaction.status = 'failed';
      await transaction.save();
      logger.error(`Transaction ${reference} failed`);
    }

    res.json({ success: true });
  } catch (error) {
    logger.error('Callback error:', error);
    res.status(500).json({ error: 'Callback processing failed' });
  }
});

// Admin routes
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.post('/api/admin/login', async (req, res) => {
  try {
    const { pin } = req.body;
    if (pin === process.env.ADMIN_PIN) {
      const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ success: true, token });
    } else {
      res.status(401).json({ error: 'Invalid admin PIN' });
    }
  } catch (error) {
    logger.error('Admin login error:', error);
    res.status(500).json({ error: 'Admin login failed' });
  }
});

app.get('/api/admin/users', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const users = await User.find().sort({ createdAt: -1 });
    res.json({ success: true, users });
  } catch (error) {
    logger.error('Admin users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/api/admin/transactions', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const transactions = await Transaction.find().sort({ createdAt: -1 }).limit(50);
    res.json({ success: true, transactions });
  } catch (error) {
    logger.error('Admin transactions error:', error);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.listen(PORT, () => {
  logger.info(`🚀 BeraPay server running on port ${PORT}`);
  logger.info(`📱 Web portal: http://localhost:${PORT}`);
  logger.info(`🔧 Admin panel: http://localhost:${PORT}/admin`);
});
