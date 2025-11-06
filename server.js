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
const { User, Transaction, Session } = require('./models');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
}));
app.use(compression());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// MongoDB connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('✅ MongoDB connected successfully');
    
    // Drop the problematic index if it exists
    try {
      await mongoose.connection.collection('sessions').dropIndex('sessionId_1');
      console.log('✅ Removed problematic sessionId index');
    } catch (e) {
      console.log('ℹ️ No problematic index to remove');
    }
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    setTimeout(connectDB, 5000);
  }
};
connectDB();

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
      },
      timeout: 30000
    });

    return { success: true, data: response.data };
  } catch (error) {
    console.error('STK Push Error:', error.response?.data || error.message);
    return { 
      success: false, 
      error: error.response?.data?.message || error.message 
    };
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
      },
      timeout: 30000
    });

    return { success: true, data: response.data };
  } catch (error) {
    console.error('Disbursement Error:', error.response?.data || error.message);
    return { 
      success: false, 
      error: error.response?.data?.message || error.message 
    };
  }
}

// API Routes

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'BeraPay API'
  });
});

// Generate pairing code (display directly on webpage)
app.get('/api/pair-code', async (req, res) => {
  try {
    const { phone } = req.query;
    if (!phone) {
      return res.status(400).json({ error: 'Phone number is required' });
    }

    const formattedPhone = formatPhone(phone);
    const code = generateCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Delete any existing sessions for this phone first
    await Session.deleteMany({ 
      phone: formattedPhone,
      verified: false 
    });

    // Create new session
    const session = new Session({
      phone: formattedPhone,
      code: code,
      expiresAt: expiresAt
    });
    
    await session.save();

    console.log(`Pairing code for ${formattedPhone}: ${code}`);

    res.json({ 
      success: true, 
      code: code,
      message: 'Pairing code generated successfully'
    });
  } catch (error) {
    console.error('Pair code error:', error);
    
    // Handle specific MongoDB errors
    if (error.code === 11000) {
      // Duplicate key error - try again with a new code
      return res.status(500).json({ error: 'Please try again' });
    }
    
    res.status(500).json({ error: 'Failed to generate pairing code' });
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
    
    // Find valid session
    const session = await Session.findOne({ 
      phone: formattedPhone, 
      code: code,
      expiresAt: { $gt: new Date() }
    });

    if (!session) {
      return res.status(400).json({ error: 'Invalid or expired code' });
    }

    // Mark as verified
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
    console.error('Verify code error:', error);
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
    
    // Verify session exists and is valid
    const session = await Session.findOne({ 
      phone: formattedPhone, 
      verified: true,
      expiresAt: { $gt: new Date() }
    });

    if (!session) {
      return res.status(400).json({ error: 'Session expired or not verified. Please start over.' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ phone: formattedPhone });
    if (existingUser) {
      return res.status(400).json({ error: 'User already registered' });
    }

    // Validate PIN
    if (pin.length !== 4 || !/^\d+$/.test(pin)) {
      return res.status(400).json({ error: 'PIN must be 4 digits only' });
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

    // Clean up session after successful registration
    await Session.deleteOne({ _id: session._id });

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
    console.error('Registration error:', error);
    
    // Handle duplicate user error
    if (error.code === 11000) {
      return res.status(400).json({ error: 'User already registered with this phone number' });
    }
    
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
    console.error('Balance error:', error);
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

    const isPinValid = await user.verifyPin(pin);
    if (!isPinValid) {
      return res.status(400).json({ error: 'Invalid PIN' });
    }

    const reference = generateRef();
    
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
    console.error('Deposit error:', error);
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

    const isPinValid = await sender.verifyPin(pin);
    if (!isPinValid) {
      return res.status(400).json({ error: 'Invalid PIN' });
    }

    if (sender.balance < parseFloat(amount)) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const formattedRecipient = formatPhone(recipient);
    const reference = generateRef();

    let recipientUser = await User.findOne({ phone: formattedRecipient });
    
    if (!recipientUser) {
      const disbursement = await disburseFunds(formattedRecipient, amount, reference);
      
      if (!disbursement.success) {
        return res.status(400).json({ error: 'Disbursement failed: ' + disbursement.error });
      }

      sender.balance -= parseFloat(amount);
      await sender.save();

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
      sender.balance -= parseFloat(amount);
      recipientUser.balance += parseFloat(amount);
      
      await sender.save();
      await recipientUser.save();

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
    console.error('Send money error:', error);
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
    console.error('Transactions error:', error);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// PayHero callback
app.post('/api/payhero/callback', async (req, res) => {
  try {
    const { reference, status, transaction_id, amount } = req.body;
    
    console.log('PayHero callback received:', { reference, status, transaction_id, amount });

    const transaction = await Transaction.findOne({ ref: reference });
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    if (status === 'success' && transaction.status === 'pending') {
      transaction.status = 'completed';
      transaction.providerRef = transaction_id;

      if (transaction.type === 'deposit' && transaction.sender === transaction.receiver) {
        const user = await User.findOne({ phone: transaction.sender });
        if (user) {
          user.balance += parseFloat(amount);
          await user.save();
        }
      }

      await transaction.save();
      console.log(`Transaction ${reference} completed successfully`);
    } else if (status === 'failed') {
      transaction.status = 'failed';
      await transaction.save();
      console.error(`Transaction ${reference} failed`);
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Callback error:', error);
    res.status(500).json({ error: 'Callback processing failed' });
  }
});

// Clean up expired sessions (optional cleanup endpoint)
app.delete('/api/cleanup-sessions', async (req, res) => {
  try {
    const result = await Session.deleteMany({ 
      expiresAt: { $lt: new Date() } 
    });
    res.json({ 
      success: true, 
      deletedCount: result.deletedCount,
      message: 'Cleaned up expired sessions'
    });
  } catch (error) {
    console.error('Cleanup error:', error);
    res.status(500).json({ error: 'Cleanup failed' });
  }
});

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Error handler
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`🚀 BeraPay server running on port ${PORT}`);
  console.log(`📱 Web portal: http://localhost:${PORT}`);
});
