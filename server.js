require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs-extra');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/berapay', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// MongoDB Models
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  phone: {
    type: String,
    required: true,
    unique: true,
    match: [/^254[0-9]{9}$/, 'Please enter a valid Kenyan phone number (2547...)']
  },
  pinHash: {
    type: String,
    required: true
  },
  balance: {
    type: Number,
    default: 0
  },
  profilePath: {
    type: String,
    default: ''
  },
  linked: {
    type: Boolean,
    default: false
  },
  walletActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Hash PIN before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('pinHash')) return next();
  this.pinHash = await bcrypt.hash(this.pinHash, 12);
  next();
});

// Compare PIN method
userSchema.methods.comparePin = async function(candidatePin) {
  return await bcrypt.compare(candidatePin, this.pinHash);
};

const transactionSchema = new mongoose.Schema({
  ref: {
    type: String,
    required: true,
    unique: true
  },
  sender: {
    type: String,
    required: true
  },
  receiver: {
    type: String,
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
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
  payheroRef: String,
  description: String,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const sessionSchema = new mongoose.Schema({
  phone: {
    type: String,
    required: true
  },
  code: {
    type: String,
    required: true
  },
  verified: {
    type: Boolean,
    default: false
  },
  expiresAt: {
    type: Date,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Index for automatic expiry
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Session = mongoose.model('Session', sessionSchema);

// Serve main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve dashboard
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Generate link code endpoint
app.post('/generate-code', async (req, res) => {
  try {
    const { phone } = req.body;
    
    console.log('📱 Generating code for:', phone);
    
    if (!phone || !phone.match(/^254[0-9]{9}$/)) {
      return res.status(400).json({ 
        success: false,
        error: 'Valid Kenyan phone number required (2547...)' 
      });
    }

    // Generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Create session (expires in 5 minutes)
    const session = new Session({
      phone,
      code,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });

    await session.save();

    console.log('✅ Code generated:', code, 'for', phone);

    res.json({ 
      success: true, 
      code,
      message: 'Code generated successfully'
    });
  } catch (error) {
    console.error('❌ Generate code error:', error);
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// Get wallet data for dashboard
app.get('/api/wallet/:phone', async (req, res) => {
  try {
    const { phone } = req.params;
    
    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const transactions = await Transaction.find({
      $or: [{ sender: phone }, { receiver: phone }]
    })
    .sort({ createdAt: -1 })
    .limit(10);

    res.json({
      user: {
        name: user.name,
        phone: user.phone,
        balance: user.balance,
        linked: user.linked
      },
      transactions
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Send money to another user
app.post('/api/wallet/send', async (req, res) => {
  try {
    const { fromPhone, toPhone, amount, pin } = req.body;

    // Validate input
    if (!fromPhone || !toPhone || !amount || !pin) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const amountNum = parseFloat(amount);
    if (isNaN(amountNum) || amountNum < 1) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    // Find sender
    const sender = await User.findOne({ phone: fromPhone });
    if (!sender) {
      return res.status(404).json({ error: 'Sender not found' });
    }

    // Verify PIN
    const isPinValid = await sender.comparePin(pin);
    if (!isPinValid) {
      return res.status(401).json({ error: 'Invalid PIN' });
    }

    // Check balance
    if (sender.balance < amountNum) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Find recipient
    const recipient = await User.findOne({ phone: toPhone });
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    // Start transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Update sender balance
      await User.findOneAndUpdate(
        { phone: fromPhone },
        { $inc: { balance: -amountNum } },
        { session }
      );

      // Update recipient balance
      await User.findOneAndUpdate(
        { phone: toPhone },
        { $inc: { balance: amountNum } },
        { session }
      );

      // Create transaction record
      const transaction = new Transaction({
        ref: `TRF${Date.now()}`,
        sender: fromPhone,
        receiver: toPhone,
        amount: amountNum,
        type: 'transfer',
        status: 'completed',
        description: `Transfer to ${recipient.name}`
      });

      await transaction.save({ session });

      // Commit transaction
      await session.commitTransaction();
      session.endSession();

      res.json({
        success: true,
        message: 'Transfer successful',
        newBalance: sender.balance - amountNum,
        transactionRef: transaction.ref
      });

    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get transaction history
app.get('/api/wallet/transactions/:phone', async (req, res) => {
  try {
    const { phone } = req.params;
    const { limit = 20, page = 1 } = req.query;

    const transactions = await Transaction.find({
      $or: [{ sender: phone }, { receiver: phone }]
    })
    .sort({ createdAt: -1 })
    .limit(parseInt(limit))
    .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Transaction.countDocuments({
      $or: [{ sender: phone }, { receiver: phone }]
    });

    res.json({
      success: true,
      transactions,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PayHero callback endpoint (Mock for now)
app.post('/api/payhero/callback', async (req, res) => {
  try {
    console.log('📞 PayHero callback received:', JSON.stringify(req.body, null, 2));
    
    // Mock successful payment processing
    // In production, this would integrate with real PayHero API
    res.json({ ResultCode: 0, ResultDesc: 'Success' });
  } catch (error) {
    console.error('Callback error:', error);
    res.status(500).json({ ResultCode: 1, ResultDesc: 'Failed' });
  }
});

// Mock deposit endpoint (Replace with real PayHero integration)
app.post('/api/payhero/deposit', async (req, res) => {
  try {
    const { phone, amount, description } = req.body;

    if (!phone || !amount) {
      return res.status(400).json({ error: 'Phone and amount are required' });
    }

    const amountNum = parseFloat(amount);
    if (isNaN(amountNum) || amountNum < 10 || amountNum > 70000) {
      return res.status(400).json({ error: 'Amount must be between KSh 10 and KSh 70,000' });
    }

    // Check if user exists
    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(404).json({ error: 'User not found. Please register first.' });
    }

    // Mock STK Push response
    const mockResponse = {
      MerchantRequestID: `MER${Date.now()}`,
      CheckoutRequestID: `CHK${Date.now()}`,
      ResponseCode: '0',
      ResponseDescription: 'Success',
      CustomerMessage: 'Success. Request accepted for processing'
    };

    // Create pending transaction
    const transaction = new Transaction({
      ref: `DEP${Date.now()}`,
      sender: phone,
      receiver: 'BERAPAY',
      amount: amountNum,
      type: 'deposit',
      status: 'pending',
      payheroRef: mockResponse.CheckoutRequestID,
      description: description || 'BeraPay Deposit'
    });

    await transaction.save();

    // Simulate payment processing (in real system, this would wait for PayHero callback)
    setTimeout(async () => {
      try {
        // Update transaction status
        transaction.status = 'completed';
        await transaction.save();

        // Update user balance
        await User.findOneAndUpdate(
          { phone },
          { $inc: { balance: amountNum } }
        );

        console.log(`✅ Mock deposit completed: KSh ${amountNum} for ${phone}`);
      } catch (error) {
        console.error('❌ Mock deposit processing error:', error);
      }
    }, 5000); // Simulate 5 second processing time

    res.json({
      success: true,
      message: 'Payment initiated. Check your phone to complete.',
      checkoutRequestID: mockResponse.CheckoutRequestID,
      response: mockResponse
    });

  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Mock withdraw endpoint
app.post('/api/payhero/withdraw', async (req, res) => {
  try {
    const { phone, amount, pin } = req.body;

    if (!phone || !amount || !pin) {
      return res.status(400).json({ error: 'Phone, amount, and PIN are required' });
    }

    const amountNum = parseFloat(amount);
    if (isNaN(amountNum) || amountNum < 10) {
      return res.status(500).json({ error: 'Invalid amount' });
    }

    // Find user and verify PIN
    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isPinValid = await user.comparePin(pin);
    if (!isPinValid) {
      return res.status(401).json({ error: 'Invalid PIN' });
    }

    // Check balance
    if (user.balance < amountNum) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Create withdrawal transaction
    const transaction = new Transaction({
      ref: `WDL${Date.now()}`,
      sender: 'BERAPAY',
      receiver: phone,
      amount: amountNum,
      type: 'withdrawal',
      status: 'pending',
      description: 'Withdrawal from BeraPay'
    });

    await transaction.save();

    // Deduct from balance immediately
    user.balance -= amountNum;
    await user.save();

    // Simulate M-Pesa processing
    setTimeout(async () => {
      try {
        transaction.status = 'completed';
        await transaction.save();
        console.log(`✅ Mock withdrawal completed: KSh ${amountNum} to ${phone}`);
      } catch (error) {
        console.error('❌ Mock withdrawal processing error:', error);
      }
    }, 3000);

    res.json({
      success: true,
      message: 'Withdrawal initiated successfully',
      newBalance: user.balance,
      transactionRef: transaction.ref
    });

  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({ error: error.message });
  }
});

// User registration endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { phone, name, pin } = req.body;

    if (!phone || !name || !pin) {
      return res.status(400).json({ error: 'Phone, name, and PIN are required' });
    }

    if (!phone.match(/^254[0-9]{9}$/)) {
      return res.status(400).json({ error: 'Valid Kenyan phone number required (2547...)' });
    }

    if (!/^\d{4}$/.test(pin)) {
      return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ phone });
    if (existingUser) {
      return res.status(400).json({ error: 'User already registered' });
    }

    const newUser = new User({
      name,
      phone,
      pinHash: pin,
      linked: true
    });

    await newUser.save();

    res.json({
      success: true,
      message: 'Registration successful',
      user: {
        name: newUser.name,
        phone: newUser.phone,
        balance: newUser.balance
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    environment: process.env.NODE_ENV || 'development'
  });
});

// WhatsApp bot pairing endpoint (for the pair.js integration)
app.get('/pair', async (req, res) => {
  const { number } = req.query;
  
  if (!number) {
    return res.status(400).json({ error: 'Number parameter is required' });
  }

  // This would integrate with your pair.js system
  // For now, return a mock response
  res.json({
    code: Math.floor(100000 + Math.random() * 900000).toString(),
    status: 'success'
  });
});

// Start WhatsApp bot (you can integrate your existing pair.js here)
const startBot = require('./bot');
startBot();

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('🚨 Server Error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : error.message
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`
💰 BeraPay Wallet System Running
📍 Port: ${PORT}
🌐 Environment: ${process.env.NODE_ENV || 'development'}
📱 API: http://localhost:${PORT}
🏠 Main Page: http://localhost:${PORT}/
📊 Dashboard: http://localhost:${PORT}/dashboard
❤️  Health: http://localhost:${PORT}/health

🔧 Features:
✅ Glass morphism design
✅ WhatsApp code generation
✅ User registration
✅ Money transfers
✅ Deposit/withdrawal (Mock)
✅ Transaction history
✅ MongoDB integration
  `);
});

module.exports = app;
