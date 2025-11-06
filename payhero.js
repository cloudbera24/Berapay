const axios = require('axios');
const crypto = require('crypto');
const { Transaction, User } = require('./models');

class PayHero {
  constructor() {
    this.apiKey = process.env.PAYHERO_API_KEY;
    this.shortcode = process.env.PAYHERO_SHORTCODE;
    this.callbackURL = process.env.PAYHERO_CALLBACK_URL;
    this.authToken = process.env.AUTH_TOKEN;
    this.channelID = process.env.CHANNEL_ID;
  }

  // Generate security credentials
  generateSecurityCredentials() {
    const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14);
    const password = Buffer.from(`${this.shortcode}${this.apiKey}${timestamp}`).toString('base64');
    return password;
  }

  // Initiate STK Push for deposits
  async initiateSTKPush(phone, amount, description) {
    try {
      const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14);
      const password = this.generateSecurityCredentials();

      const payload = {
        BusinessShortCode: this.shortcode,
        Password: password,
        Timestamp: timestamp,
        TransactionType: 'CustomerPayBillOnline',
        Amount: amount,
        PartyA: phone,
        PartyB: this.shortcode,
        PhoneNumber: phone,
        CallBackURL: this.callbackURL,
        AccountReference: 'BERAPAY',
        TransactionDesc: description
      };

      const response = await axios.post(
        'https://api.payhero.co.ke/v2/stkpush',
        payload,
        {
          headers: {
            'Authorization': this.authToken,
            'Content-Type': 'application/json'
          }
        }
      );

      // Create pending transaction
      const transaction = new Transaction({
        ref: `DEP${Date.now()}`,
        sender: phone,
        receiver: 'BERAPAY',
        amount,
        type: 'deposit',
        status: 'pending',
        payheroRef: response.data.CheckoutRequestID,
        description
      });

      await transaction.save();

      return response.data;
    } catch (error) {
      console.error('STK Push Error:', error.response?.data || error.message);
      throw new Error(error.response?.data?.ResponseDescription || 'Payment initiation failed');
    }
  }

  // Handle PayHero callback
  async handleCallback(callbackData) {
    try {
      const { Body } = callbackData;
      const stkCallback = Body.stkCallback;

      if (stkCallback.ResultCode === 0) {
        // Payment successful
        const metadata = stkCallback.CallbackMetadata.Item;
        const amount = metadata.find(item => item.Name === 'Amount').Value;
        const mpesaReceipt = metadata.find(item => item.Name === 'MpesaReceiptNumber').Value;
        const phone = metadata.find(item => item.Name === 'PhoneNumber').Value;

        // Find pending transaction
        const transaction = await Transaction.findOne({
          payheroRef: stkCallback.CheckoutRequestID,
          status: 'pending'
        });

        if (transaction) {
          // Update transaction status
          transaction.status = 'completed';
          transaction.payheroRef = mpesaReceipt;
          await transaction.save();

          // Update user balance
          await User.findOneAndUpdate(
            { phone: transaction.sender },
            { $inc: { balance: amount } }
          );

          console.log(`✅ Deposit completed: ${amount} for ${phone}`);
        }
      } else {
        // Payment failed
        const transaction = await Transaction.findOne({
          payheroRef: stkCallback.CheckoutRequestID,
          status: 'pending'
        });

        if (transaction) {
          transaction.status = 'failed';
          await transaction.save();
        }

        console.log(`❌ Payment failed: ${stkCallback.ResultDesc}`);
      }

      return { ResultCode: 0, ResultDesc: 'Success' };
    } catch (error) {
      console.error('Callback handling error:', error);
      return { ResultCode: 1, ResultDesc: 'Failed' };
    }
  }

  // Send money (disbursement)
  async sendMoney(phone, amount, description) {
    try {
      const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14);
      const password = this.generateSecurityCredentials();

      const payload = {
        InitiatorName: 'berapay',
        SecurityCredential: password,
        CommandID: 'BusinessPayment',
        Amount: amount,
        PartyA: this.shortcode,
        PartyB: phone,
        Remarks: description,
        QueueTimeOutURL: this.callbackURL,
        ResultURL: this.callbackURL,
        Occasion: 'BeraPay Payout'
      };

      const response = await axios.post(
        'https://api.payhero.co.ke/v2/disburse',
        payload,
        {
          headers: {
            'Authorization': this.authToken,
            'Content-Type': 'application/json'
          }
        }
      );

      return response.data;
    } catch (error) {
      console.error('Disbursement Error:', error.response?.data || error.message);
      throw new Error(error.response?.data?.ResponseDescription || 'Payout failed');
    }
  }
}

module.exports = new PayHero();
