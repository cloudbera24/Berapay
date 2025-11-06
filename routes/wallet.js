const express = require('express');
const router = express.Router();
const { User, Transaction } = require('../models');
const bcrypt = require('bcryptjs');

// Get wallet balance
router.get('/balance/:phone', async (req, res) => {
  try {
    const { phone } = req.params;
    
    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      success: true,
      balance: user.balance,
      name: user.name,
      phone: user.phone
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Send money to another user
router.post('/send', async (req, res) => {
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
    const session = await User.startSession();
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
    res.status(500).json({ error: error.message });
  }
});

// Update user profile
router.put('/profile/:phone', async (req, res) => {
  try {
    const { phone } = req.params;
    const { name, currentPin, newPin } = req.body;

    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current PIN if changing PIN
    if (newPin) {
      if (!currentPin) {
        return res.status(400).json({ error: 'Current PIN is required to change PIN' });
      }

      const isPinValid = await user.comparePin(currentPin);
      if (!isPinValid) {
        return res.status(401).json({ error: 'Invalid current PIN' });
      }

      user.pinHash = newPin;
    }

    // Update name if provided
    if (name) {
      user.name = name;
    }

    await user.save();

    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        name: user.name,
        phone: user.phone
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
