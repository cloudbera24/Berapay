require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs'); // Using native fs instead of fs-extra

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Create public directory if it doesn't exist
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir, { recursive: true });
}

// Serve static files from public directory
app.use(express.static(publicDir));

// MongoDB Connection with fallback
const MONGODB_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/berapay';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => {
  console.error('❌ MongoDB Connection Error:', err);
  console.log('⚠️  Continuing without MongoDB - using in-memory storage');
});

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

// In-memory storage fallback
const memoryStorage = {
  sessions: new Map(),
  users: new Map(),
  transactions: []
};

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
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
    
    try {
      // Try MongoDB first
      const session = new Session({
        phone,
        code,
        expiresAt
      });
      await session.save();
    } catch (mongoError) {
      console.log('⚠️  MongoDB not available, using memory storage');
      // Fallback to memory storage
      memoryStorage.sessions.set(code, {
        phone,
        code,
        expiresAt,
        verified: false
      });
    }

    console.log('✅ Code generated:', code, 'for', phone);

    res.json({ 
      success: true, 
      code,
      message: 'Code generated successfully. It expires in 5 minutes.'
    });
  } catch (error) {
    console.error('❌ Generate code error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to generate code. Please try again.' 
    });
  }
});

// Get wallet data for dashboard
app.get('/api/wallet/:phone', async (req, res) => {
  try {
    const { phone } = req.params;
    
    let user, transactions;

    try {
      // Try MongoDB first
      user = await User.findOne({ phone });
      transactions = await Transaction.find({
        $or: [{ sender: phone }, { receiver: phone }]
      })
      .sort({ createdAt: -1 })
      .limit(10);
    } catch (mongoError) {
      console.log('⚠️  MongoDB not available, using memory storage');
      // Fallback to memory storage
      user = memoryStorage.users.get(phone);
      transactions = memoryStorage.transactions
        .filter(t => t.sender === phone || t.receiver === phone)
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        .slice(0, 10);
    }

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      user: {
        name: user.name,
        phone: user.phone,
        balance: user.balance || 0,
        linked: user.linked || false
      },
      transactions: transactions || []
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

    let sender, recipient;

    try {
      // Try MongoDB first
      sender = await User.findOne({ phone: fromPhone });
      recipient = await User.findOne({ phone: toPhone });
    } catch (mongoError) {
      console.log('⚠️  MongoDB not available, using memory storage');
      // Fallback to memory storage
      sender = memoryStorage.users.get(fromPhone);
      recipient = memoryStorage.users.get(toPhone);
    }

    if (!sender) {
      return res.status(404).json({ error: 'Sender not found' });
    }

    // Verify PIN
    const isPinValid = await sender.comparePin ? 
      await sender.comparePin(pin) : 
      (sender.pinHash === pin); // Simple fallback for memory storage

    if (!isPinValid) {
      return res.status(401).json({ error: 'Invalid PIN' });
    }

    // Check balance
    if (sender.balance < amountNum) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    try {
      // Update balances
      sender.balance -= amountNum;
      recipient.balance += amountNum;

      // Create transaction record
      const transaction = {
        ref: `TRF${Date.now()}`,
        sender: fromPhone,
        receiver: toPhone,
        amount: amountNum,
        type: 'transfer',
        status: 'completed',
        description: `Transfer to ${recipient.name}`,
        createdAt: new Date()
      };

      if (mongoose.connection.readyState === 1) {
        // Use MongoDB
        await User.findOneAndUpdate({ phone: fromPhone }, { $inc: { balance: -amountNum } });
        await User.findOneAndUpdate({ phone: toPhone }, { $inc: { balance: amountNum } });
        
        const mongoTransaction = new Transaction(transaction);
        await mongoTransaction.save();
      } else {
        // Use memory storage
        memoryStorage.users.set(fromPhone, sender);
        memoryStorage.users.set(toPhone, recipient);
        memoryStorage.transactions.push(transaction);
      }

      res.json({
        success: true,
        message: 'Transfer successful',
        newBalance: sender.balance,
        transactionRef: transaction.ref
      });

    } catch (error) {
      throw error;
    }

  } catch (error) {
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

    let existingUser;
    try {
      existingUser = await User.findOne({ phone });
    } catch (mongoError) {
      existingUser = memoryStorage.users.get(phone);
    }

    if (existingUser) {
      return res.status(400).json({ error: 'User already registered' });
    }

    const newUser = {
      name,
      phone,
      pinHash: pin, // In production, this should be hashed
      balance: 0,
      linked: true,
      createdAt: new Date()
    };

    if (mongoose.connection.readyState === 1) {
      // Use MongoDB
      const user = new User(newUser);
      await user.save();
    } else {
      // Use memory storage
      memoryStorage.users.set(phone, newUser);
    }

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

// Mock deposit endpoint
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

    let user;
    try {
      user = await User.findOne({ phone });
    } catch (mongoError) {
      user = memoryStorage.users.get(phone);
    }

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

    const transaction = {
      ref: `DEP${Date.now()}`,
      sender: phone,
      receiver: 'BERAPAY',
      amount: amountNum,
      type: 'deposit',
      status: 'pending',
      payheroRef: mockResponse.CheckoutRequestID,
      description: description || 'BeraPay Deposit',
      createdAt: new Date()
    };

    if (mongoose.connection.readyState === 1) {
      const mongoTransaction = new Transaction(transaction);
      await mongoTransaction.save();
    } else {
      memoryStorage.transactions.push(transaction);
    }

    // Simulate payment processing
    setTimeout(async () => {
      try {
        // Update transaction status
        transaction.status = 'completed';
        
        // Update user balance
        user.balance += amountNum;

        if (mongoose.connection.readyState === 1) {
          await User.findOneAndUpdate({ phone }, { $inc: { balance: amountNum } });
          await Transaction.findOneAndUpdate({ ref: transaction.ref }, { status: 'completed' });
        } else {
          memoryStorage.users.set(phone, user);
          // Update transaction in memory
          const txIndex = memoryStorage.transactions.findIndex(t => t.ref === transaction.ref);
          if (txIndex !== -1) {
            memoryStorage.transactions[txIndex].status = 'completed';
          }
        }

        console.log(`✅ Mock deposit completed: KSh ${amountNum} for ${phone}`);
      } catch (error) {
        console.error('❌ Mock deposit processing error:', error);
      }
    }, 5000);

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
      return res.status(400).json({ error: 'Invalid amount' });
    }

    let user;
    try {
      user = await User.findOne({ phone });
    } catch (mongoError) {
      user = memoryStorage.users.get(phone);
    }

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify PIN
    const isPinValid = await user.comparePin ? 
      await user.comparePin(pin) : 
      (user.pinHash === pin);

    if (!isPinValid) {
      return res.status(401).json({ error: 'Invalid PIN' });
    }

    // Check balance
    if (user.balance < amountNum) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Create withdrawal transaction
    const transaction = {
      ref: `WDL${Date.now()}`,
      sender: 'BERAPAY',
      receiver: phone,
      amount: amountNum,
      type: 'withdrawal',
      status: 'pending',
      description: 'Withdrawal from BeraPay',
      createdAt: new Date()
    };

    if (mongoose.connection.readyState === 1) {
      const mongoTransaction = new Transaction(transaction);
      await mongoTransaction.save();
    } else {
      memoryStorage.transactions.push(transaction);
    }

    // Deduct from balance immediately
    user.balance -= amountNum;

    if (mongoose.connection.readyState === 1) {
      await User.findOneAndUpdate({ phone }, { balance: user.balance });
    } else {
      memoryStorage.users.set(phone, user);
    }

    // Simulate M-Pesa processing
    setTimeout(async () => {
      try {
        transaction.status = 'completed';
        
        if (mongoose.connection.readyState === 1) {
          await Transaction.findOneAndUpdate({ ref: transaction.ref }, { status: 'completed' });
        } else {
          const txIndex = memoryStorage.transactions.findIndex(t => t.ref === transaction.ref);
          if (txIndex !== -1) {
            memoryStorage.transactions[txIndex].status = 'completed';
          }
        }

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

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    environment: process.env.NODE_ENV || 'development',
    memoryUsers: memoryStorage.users.size,
    memorySessions: memoryStorage.sessions.size,
    memoryTransactions: memoryStorage.transactions.length
  });
});

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
✅ MongoDB with memory fallback
✅ Transaction history
  `);
});

module.exports = app;
