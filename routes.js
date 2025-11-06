const express = require('express');
const bcrypt = require('bcryptjs');
const { User, Session, Transaction, Wallet } = require('./models');
const { processDeposit, processWithdrawal } = require('./payhero');
const router = express.Router();

// Generate link code
router.get('/get-link-code', async (req, res) => {
  try {
    const { phone } = req.query;
    
    if (!phone || phone.length < 10) {
      return res.json({ 
        success: false, 
        message: 'Valid phone number required' 
      });
    }

    // Clean phone number
    const cleanPhone = phone.replace(/\D/g, '');
    if (!cleanPhone.startsWith('254')) {
      return res.json({ 
        success: false, 
        message: 'Kenyan phone number required (254...)'
      });
    }

    // Generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Create session (expires in 10 minutes)
    const session = new Session({
      phone: cleanPhone,
      code,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    });

    await session.save();

    res.json({
      success: true,
      code,
      message: 'Link code generated successfully',
      expiresIn: '10 minutes'
    });

  } catch (error) {
    console.error('Link code error:', error);
    res.json({ 
      success: false, 
      message: 'Failed to generate link code' 
    });
  }
});

// User registration
router.post('/register', async (req, res) => {
  try {
    const { name, phone, pin } = req.body;

    if (!name || !phone || !pin) {
      return res.json({ 
        success: false, 
        message: 'Name, phone, and PIN are required' 
      });
    }

    if (pin.length !== 4 || !/^\d+$/.test(pin)) {
      return res.json({ 
        success: false, 
        message: 'PIN must be 4 digits' 
      });
    }

    const cleanPhone = phone.replace(/\D/g, '');
    
    // Check if user exists
    const existingUser = await User.findOne({ phone: cleanPhone });
    if (existingUser) {
      return res.json({ 
        success: false, 
        message: 'User already exists' 
      });
    }

    // Hash PIN
    const pinHash = await bcrypt.hash(pin, 10);
    
    // Generate wallet ID
    const walletId = 'BP' + Date.now().toString().slice(-8);

    // Create user
    const user = new User({
      name,
      phone: cleanPhone,
      pinHash,
      walletId
    });

    await user.save();

    // Create wallet
    const wallet = new Wallet({
      walletId,
      userId: user._id
    });

    await wallet.save();

    res.json({
      success: true,
      message: 'Registration successful',
      walletId,
      user: {
        name: user.name,
        phone: user.phone,
        linked: user.linked
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.json({ 
      success: false, 
      message: 'Registration failed' 
    });
  }
});

// User login
router.post('/login', async (req, res) => {
  try {
    const { phone, pin } = req.body;

    if (!phone || !pin) {
      return res.json({ 
        success: false, 
        message: 'Phone and PIN required' 
      });
    }

    const cleanPhone = phone.replace(/\D/g, '');
    const user = await User.findOne({ phone: cleanPhone });
    
    if (!user) {
      return res.json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    const isValidPin = await user.verifyPin(pin);
    if (!isValidPin) {
      return res.json({ 
        success: false, 
        message: 'Invalid PIN' 
      });
    }

    res.json({
      success: true,
      user: {
        name: user.name,
        phone: user.phone,
        balance: user.balance,
        linked: user.linked,
        walletId: user.walletId
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.json({ 
      success: false, 
      message: 'Login failed' 
    });
  }
});

// Get user profile
router.get('/user/:phone', async (req, res) => {
  try {
    const { phone } = req.params;
    const user = await User.findOne({ phone });
    
    if (!user) {
      return res.json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    res.json({
      success: true,
      user: {
        name: user.name,
        phone: user.phone,
        balance: user.balance,
        linked: user.linked,
        walletId: user.walletId,
        createdAt: user.createdAt
      }
    });

  } catch (error) {
    console.error('User profile error:', error);
    res.json({ 
      success: false, 
      message: 'Failed to fetch user profile' 
    });
  }
});

// Get transactions
router.get('/transactions/:phone', async (req, res) => {
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
    console.error('Transactions error:', error);
    res.json({ 
      success: false, 
      message: 'Failed to fetch transactions' 
    });
  }
});

// Check link status
router.get('/link-status/:phone', async (req, res) => {
  try {
    const { phone } = req.params;
    const session = await Session.findOne({ 
      phone, 
      verified: true 
    }).sort({ createdAt: -1 });

    const user = await User.findOne({ phone });

    res.json({
      success: true,
      linked: !!session,
      user: user ? {
        name: user.name,
        balance: user.balance,
        walletId: user.walletId
      } : null
    });

  } catch (error) {
    console.error('Link status error:', error);
    res.json({ 
      success: false, 
      message: 'Failed to check link status' 
    });
  }
});

// PayHero callback handler
router.post('/payhero/callback', async (req, res) => {
  try {
    const callbackData = req.body;
    console.log('PayHero callback received:', callbackData);

    // Handle STK Push callback
    if (callbackData.StkCallback) {
      const { MerchantRequestID, CheckoutRequestID, ResultCode, ResultDesc, CallbackMetadata } = callbackData.StkCallback;
      
      if (ResultCode === 0) {
        // Successful payment
        const metadata = CallbackMetadata?.Item || [];
        const amountItem = metadata.find(item => item.Name === 'Amount');
        const phoneItem = metadata.find(item => item.Name === 'PhoneNumber');
        const mpesaReceipt = metadata.find(item => item.Name === 'MpesaReceiptNumber');

        if (amountItem && phoneItem) {
          const amount = amountItem.Value;
          const phone = phoneItem.Value.toString();
          
          // Update user balance and transaction status
          const user = await User.findOne({ phone });
          if (user) {
            user.balance += amount;
            await user.save();

            // Update transaction status
            await Transaction.findOneAndUpdate(
              { 'metadata.reference': MerchantRequestID },
              { 
                status: 'completed',
                payheroReference: mpesaReceipt?.Value 
              }
            );

            console.log(`✅ Deposit completed: ${phone} - KES ${amount}`);
          }
        }
      }
    }

    // Handle B2C callback
    if (callbackData.Result) {
      const { ResultType, ResultCode, ResultDesc, ResultParameters } = callbackData.Result;
      
      if (ResultCode === 0 && ResultType === 0) {
        // Successful B2C payment
        console.log('✅ B2C payment completed');
      }
    }

    res.status(200).send('OK');
  } catch (error) {
    console.error('Callback error:', error);
    res.status(500).send('Error');
  }
});

module.exports = router;
