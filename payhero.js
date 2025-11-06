const axios = require('axios');
const { User, Transaction, Wallet } = require('./models');
const crypto = require('crypto');

class PayHeroService {
  constructor() {
    this.apiKey = process.env.PAYHERO_API_KEY;
    this.shortcode = process.env.PAYHERO_SHORTCODE;
    this.callbackUrl = process.env.PAYHERO_CALLBACK_URL;
    this.authToken = process.env.AUTH_TOKEN;
    this.channelId = process.env.CHANNEL_ID;
  }

  async generateAuthToken() {
    try {
      const response = await axios.post('https://api.payhero.co.ke/oauth/token', {
        grant_type: 'client_credentials'
      }, {
        headers: {
          'Authorization': this.authToken,
          'Content-Type': 'application/json'
        }
      });
      
      return response.data.access_token;
    } catch (error) {
      console.error('PayHero auth error:', error.response?.data || error.message);
      throw new Error('Failed to authenticate with PayHero');
    }
  }

  async initiateSTKPush(phone, amount, reference) {
    try {
      const token = await this.generateAuthToken();
      
      const payload = {
        BusinessShortCode: this.shortcode,
        Password: this.generatePassword(),
        Timestamp: this.getTimestamp(),
        TransactionType: 'CustomerPayBillOnline',
        Amount: amount,
        PartyA: phone,
        PartyB: this.shortcode,
        PhoneNumber: phone,
        CallBackURL: this.callbackUrl,
        AccountReference: reference,
        TransactionDesc: `BeraPay Deposit - ${reference}`
      };

      const response = await axios.post('https://api.payhero.co.ke/mpesa/stkpush/v1/processrequest', payload, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      return response.data;
    } catch (error) {
      console.error('STK Push error:', error.response?.data || error.message);
      throw error;
    }
  }

  async processB2C(phone, amount, remarks) {
    try {
      const token = await this.generateAuthToken();
      
      const payload = {
        InitiatorName: 'berapay',
        SecurityCredential: this.generateSecurityCredential(),
        CommandID: 'BusinessPayment',
        Amount: amount,
        PartyA: this.shortcode,
        PartyB: phone,
        Remarks: remarks,
        QueueTimeOutURL: this.callbackUrl,
        ResultURL: this.callbackUrl,
        Occasion: 'BeraPay Payout'
      };

      const response = await axios.post('https://api.payhero.co.ke/mpesa/b2c/v1/paymentrequest', payload, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      return response.data;
    } catch (error) {
      console.error('B2C error:', error.response?.data || error.message);
      throw error;
    }
  }

  generatePassword() {
    const timestamp = this.getTimestamp();
    const password = Buffer.from(`${this.shortcode}${process.env.PAYHERO_PASSKEY}${timestamp}`).toString('base64');
    return password;
  }

  getTimestamp() {
    return new Date().toISOString().replace(/[^0-9]/g, '').slice(0, -3);
  }

  generateSecurityCredential() {
    // This should be encrypted with the public certificate
    // For production, implement proper certificate encryption
    return Buffer.from(`${this.shortcode}${Date.now()}`).toString('base64');
  }
}

const payhero = new PayHeroService();

// Deposit processing
async function processDeposit(phone, amount) {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const user = await User.findOne({ phone }).session(session);
    if (!user) {
      throw new Error('User not found');
    }

    const reference = `DP${Date.now()}${Math.random().toString(36).substr(2, 5)}`.toUpperCase();
    
    // Create pending transaction
    const transaction = new Transaction({
      transactionId: reference,
      receiver: phone,
      amount,
      type: 'deposit',
      status: 'pending',
      description: `Deposit to BeraPay wallet`,
      metadata: { reference, phone, amount }
    });

    await transaction.save({ session });

    // Initiate STK Push
    const stkResult = await payhero.initiateSTKPush(phone, amount, reference);
    
    if (stkResult.ResponseCode === '0') {
      await session.commitTransaction();
      return {
        success: true,
        message: 'STK Push initiated. Check your phone to complete payment.',
        reference,
        checkoutRequestID: stkResult.CheckoutRequestID
      };
    } else {
      await session.abortTransaction();
      return {
        success: false,
        message: stkResult.ResponseDescription || 'Failed to initiate payment'
      };
    }
  } catch (error) {
    await session.abortTransaction();
    console.error('Deposit error:', error);
    return {
      success: false,
      message: error.message || 'Deposit processing failed'
    };
  } finally {
    session.endSession();
  }
}

// Transfer processing
async function processTransfer(senderPhone, recipientPhone, amount) {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const sender = await User.findOne({ phone: senderPhone }).session(session);
    const recipient = await User.findOne({ phone: recipientPhone }).session(session);

    if (!sender) throw new Error('Sender not found');
    if (!recipient) throw new Error('Recipient not found');
    if (sender.balance < amount) throw new Error('Insufficient balance');

    const reference = `TX${Date.now()}${Math.random().toString(36).substr(2, 5)}`.toUpperCase();

    // Deduct from sender
    sender.balance -= amount;
    await sender.save({ session });

    // Add to recipient
    recipient.balance += amount;
    await recipient.save({ session });

    // Create transaction record
    const transaction = new Transaction({
      transactionId: reference,
      sender: senderPhone,
      receiver: recipientPhone,
      amount,
      type: 'transfer',
      status: 'completed',
      description: `Transfer to ${recipientPhone}`,
      metadata: { reference, senderPhone, recipientPhone, amount }
    });

    await transaction.save({ session });
    await session.commitTransaction();

    return {
      success: true,
      message: 'Transfer completed successfully',
      newBalance: sender.balance,
      reference
    };
  } catch (error) {
    await session.abortTransaction();
    console.error('Transfer error:', error);
    return {
      success: false,
      message: error.message || 'Transfer failed'
    };
  } finally {
    session.endSession();
  }
}

// Withdrawal processing
async function processWithdrawal(phone, amount) {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const user = await User.findOne({ phone }).session(session);
    if (!user) throw new Error('User not found');
    if (user.balance < amount) throw new Error('Insufficient balance');

    const reference = `WD${Date.now()}${Math.random().toString(36).substr(2, 5)}`.toUpperCase();

    // Deduct from user balance
    user.balance -= amount;
    await user.save({ session });

    // Create pending withdrawal transaction
    const transaction = new Transaction({
      transactionId: reference,
      sender: phone,
      amount,
      type: 'withdrawal',
      status: 'pending',
      description: `Withdrawal to M-Pesa`,
      metadata: { reference, phone, amount }
    });

    await transaction.save({ session });

    // Process B2C payout
    const b2cResult = await payhero.processB2C(phone, amount, `BeraPay Withdrawal - ${reference}`);
    
    if (b2cResult.ResponseCode === '0') {
      transaction.status = 'completed';
      await transaction.save({ session });
      await session.commitTransaction();

      return {
        success: true,
        message: 'Withdrawal processed successfully',
        newBalance: user.balance,
        reference
      };
    } else {
      // Refund user if B2C fails
      user.balance += amount;
      await user.save({ session });
      transaction.status = 'failed';
      await transaction.save({ session });
      
      await session.commitTransaction();
      return {
        success: false,
        message: b2cResult.ResponseDescription || 'Withdrawal failed'
      };
    }
  } catch (error) {
    await session.abortTransaction();
    console.error('Withdrawal error:', error);
    return {
      success: false,
      message: error.message || 'Withdrawal processing failed'
    };
  } finally {
    session.endSession();
  }
}

module.exports = {
  processDeposit,
  processTransfer,
  processWithdrawal,
  payhero
};
