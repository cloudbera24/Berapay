require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { makeWASocket, useMultiFileAuthState, Browsers, delay } = require('@whiskeysockets/baileys');
const path = require('path');
const fs = require('fs-extra');

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const { User, Session, Transaction } = require('./models');
const { generateRef } = require('./utils');

// WhatsApp bot setup
async function startBot() {
  const { state, saveCreds } = await useMultiFileAuthState('./bot_sessions');
  
  const sock = makeWASocket({
    auth: state,
    printQRInTerminal: true,
    browser: Browsers.ubuntu('Chrome')
  });

  sock.ev.on('creds.update', saveCreds);

  sock.ev.on('connection.update', (update) => {
    const { connection, lastDisconnect } = update;
    if (connection === 'close') {
      const shouldReconnect = lastDisconnect.error?.output?.statusCode !== 401;
      console.log('Connection closed. Reconnecting:', shouldReconnect);
      if (shouldReconnect) {
        startBot();
      }
    } else if (connection === 'open') {
      console.log('✅ BeraPay WhatsApp Bot is connected!');
    }
  });

  sock.ev.on('messages.upsert', async ({ messages }) => {
    const msg = messages[0];
    if (!msg.message || msg.key.remoteJid === 'status@broadcast') return;

    const messageType = Object.keys(msg.message)[0];
    let body = '';
    
    if (messageType === 'conversation') {
      body = msg.message.conversation;
    } else if (messageType === 'extendedTextMessage') {
      body = msg.message.extendedTextMessage.text;
    }

    const sender = msg.key.remoteJid;
    const phone = sender.split('@')[0];

    try {
      // Handle .link command
      if (body.startsWith('.link ')) {
        const code = body.split(' ')[1];
        await handleLinkCommand(sock, phone, code, sender);
      }
      
      // Handle .menu command
      else if (body === '.menu') {
        await showMainMenu(sock, sender);
      }
      
      // Handle button responses
      else if (msg.message?.buttonsResponseMessage) {
        const buttonId = msg.message.buttonsResponseMessage.selectedButtonId;
        await handleButtonResponse(sock, phone, buttonId, sender);
      }

    } catch (error) {
      console.error('Bot error:', error);
      await sock.sendMessage(sender, { 
        text: '❌ An error occurred. Please try again.' 
      });
    }
  });

  // Handle link command
  async function handleLinkCommand(sock, phone, code, sender) {
    const session = await Session.findOne({ phone, code });
    
    if (!session) {
      return await sock.sendMessage(sender, { 
        text: '❌ Invalid link code. Please generate a new code from the website.' 
      });
    }

    if (session.expiresAt < new Date()) {
      return await sock.sendMessage(sender, { 
        text: '❌ Link code has expired. Please generate a new code.' 
      });
    }

    session.verified = true;
    await session.save();

    await sock.sendMessage(sender, { 
      text: '✅ Account linked successfully! Type *.menu* to see wallet options.' 
    });
  }

  // Show main menu
  async function showMainMenu(sock, sender) {
    const menuMessage = {
      text: `🏦 *BeraPay Wallet*\n\nWelcome to your digital wallet! Choose an option:`,
      buttons: [
        { buttonId: 'register', buttonText: { displayText: '📝 Register' } },
        { buttonId: 'balance', buttonText: { displayText: '💰 Balance' } },
        { buttonId: 'send', buttonText: { displayText: '💸 Send Money' } },
        { buttonId: 'deposit', buttonText: { displayText: '📥 Deposit' } },
        { buttonId: 'transactions', buttonText: { displayText: '📜 Transactions' } }
      ],
      headerType: 1
    };

    await sock.sendMessage(sender, menuMessage);
  }

  // Handle button responses
  async function handleButtonResponse(sock, phone, buttonId, sender) {
    const user = await User.findOne({ phone });
    
    switch (buttonId) {
      case 'register':
        await handleRegistration(sock, phone, sender);
        break;
      case 'balance':
        await showBalance(sock, user, sender);
        break;
      case 'send':
        await handleSendMoney(sock, user, sender);
        break;
      case 'deposit':
        await handleDeposit(sock, user, sender);
        break;
      case 'transactions':
        await showTransactions(sock, phone, sender);
        break;
    }
  }

  // Handle user registration
  async function handleRegistration(sock, phone, sender) {
    const existingUser = await User.findOne({ phone });
    if (existingUser) {
      return await sock.sendMessage(sender, { 
        text: '✅ You are already registered!' 
      });
    }

    await sock.sendMessage(sender, { 
      text: '📝 *Registration*\n\nPlease visit our website to complete registration:\nhttps://berapay.onrender.com' 
    });
  }

  // Show balance
  async function showBalance(sock, user, sender) {
    if (!user) {
      return await sock.sendMessage(sender, { 
        text: '❌ Please register first using the website.' 
      });
    }

    await sock.sendMessage(sender, { 
      text: `💰 *Your Balance*\n\nAmount: KES ${user.balance.toLocaleString()}\n\nType *.menu* for more options.` 
    });
  }

  // Handle send money
  async function handleSendMoney(sock, user, sender) {
    if (!user) {
      return await sock.sendMessage(sender, { 
        text: '❌ Please register first.' 
      });
    }

    await sock.sendMessage(sender, { 
      text: `💸 *Send Money*\n\nPlease visit our website to send money securely:\nhttps://berapay.onrender.com/dashboard\n\nYour current balance: KES ${user.balance.toLocaleString()}` 
    });
  }

  // Handle deposit
  async function handleDeposit(sock, user, sender) {
    if (!user) {
      return await sock.sendMessage(sender, { 
        text: '❌ Please register first.' 
      });
    }

    await sock.sendMessage(sender, { 
      text: `📥 *Deposit Money*\n\nVisit our website to deposit via M-Pesa:\nhttps://berapay.onrender.com/dashboard\n\nMinimum deposit: KES 10` 
    });
  }

  // Show transactions
  async function showTransactions(sock, phone, sender) {
    const transactions = await Transaction.find({
      $or: [{ sender: phone }, { receiver: phone }]
    }).sort({ createdAt: -1 }).limit(5);

    if (transactions.length === 0) {
      return await sock.sendMessage(sender, { 
        text: '📜 No transactions found.' 
      });
    }

    let transactionText = '📜 *Recent Transactions*\n\n';
    transactions.forEach((txn, index) => {
      const type = txn.sender === phone ? 'Sent' : 'Received';
      const amount = `KES ${txn.amount.toLocaleString()}`;
      const date = new Date(txn.createdAt).toLocaleDateString();
      
      transactionText += `${index + 1}. ${type} ${amount}\n`;
      transactionText += `   Status: ${txn.status}\n`;
      transactionText += `   Date: ${date}\n\n`;
    });

    transactionText += 'View full history on website.';

    await sock.sendMessage(sender, { text: transactionText });
  }
}

// Start the bot
startBot().catch(console.error);
