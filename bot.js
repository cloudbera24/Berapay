require('dotenv').config();
const { sms, downloadMediaMessage } = require('./msg');
const { makeWASocket, useMultiFileAuthState, Browsers, delay } = require('@whiskeysockets/baileys');
const axios = require('axios');
const path = require('path');
const fs = require('fs-extra');
const { User, Transaction } = require('./models');

const PREFIX = '.';
const SESSION_PATH = './bot_sessions';

class BeraPayBot {
  constructor() {
    this.sockets = new Map();
    this.setupBot();
  }

  async setupBot() {
    try {
      await this.initializeBot();
    } catch (error) {
      console.error('Bot setup error:', error);
      setTimeout(() => this.setupBot(), 5000);
    }
  }

  async initializeBot() {
    const { state, saveCreds } = await useMultiFileAuthState(SESSION_PATH);
    
    const socket = makeWASocket({
      auth: state,
      printQRInTerminal: true,
      browser: Browsers.ubuntu('Chrome')
    });

    socket.ev.on('creds.update', saveCreds);

    socket.ev.on('connection.update', (update) => {
      const { connection, lastDisconnect } = update;
      if (connection === 'close') {
        console.log('Connection closed, reconnecting...');
        setTimeout(() => this.setupBot(), 5000);
      } else if (connection === 'open') {
        console.log('✅ BeraPay Bot connected successfully');
      }
    });

    socket.ev.on('messages.upsert', async ({ messages }) => {
      const msg = messages[0];
      if (!msg.message || msg.key.remoteJid === 'status@broadcast') return;

      try {
        await this.handleMessage(socket, msg);
      } catch (error) {
        console.error('Message handling error:', error);
      }
    });

    this.socket = socket;
  }

  async handleMessage(socket, msg) {
    const m = sms(socket, msg);
    const from = m.key.remoteJid;
    const sender = m.sender;
    const body = m.body?.toString().toLowerCase() || '';
    
    if (!body.startsWith(PREFIX) && body !== 'menu') return;

    const command = body.startsWith(PREFIX) ? body.slice(PREFIX.length).split(' ')[0] : 'menu';
    const args = body.slice(PREFIX.length).split(' ').slice(1);

    try {
      switch (command) {
        case 'menu':
          await this.showMainMenu(socket, from, sender);
          break;
        
        case 'register':
          await this.handleRegistration(socket, from, sender, args);
          break;
        
        case 'balance':
          await this.handleBalance(socket, from, sender);
          break;
        
        case 'send':
          await this.handleSendMoney(socket, from, sender, args);
          break;
        
        case 'deposit':
          await this.handleDeposit(socket, from, sender, args);
          break;
        
        case 'transactions':
          await this.handleTransactions(socket, from, sender);
          break;
        
        case 'profile':
          await this.handleProfile(socket, from, sender);
          break;
        
        default:
          await socket.sendMessage(from, { 
            text: '❌ Unknown command. Type "menu" to see available options.' 
          });
      }
    } catch (error) {
      console.error('Command error:', error);
      await socket.sendMessage(from, { 
        text: '❌ An error occurred. Please try again.' 
      });
    }
  }

  async showMainMenu(socket, from, sender) {
    const menuText = `👋 *Welcome to BeraPay* 💰

Please choose an option:

📝 *Register* - Create your BeraPay account
💰 *Balance* - Check your wallet balance  
💸 *Send* - Send money to others
📥 *Deposit* - Add money to your wallet
📜 *Transactions* - View recent transactions
⚙️ *Profile* - View your profile info

*Usage Examples:*
• Type "register John 1234" to register
• Type "send 100 0712345678 1234" to send money
• Type "deposit 500" to add funds
• Type "balance" to check balance

*Need help?* Contact support.`;

    await socket.sendMessage(from, { text: menuText });
  }

  async handleRegistration(socket, from, sender, args) {
    const phone = sender.split('@')[0];
    
    // Check if already registered
    const existingUser = await User.findOne({ phone });
    if (existingUser) {
      return await socket.sendMessage(from, { 
        text: '✅ You are already registered!\n\n' +
              `Name: ${existingUser.name}\n` +
              `Balance: KSh ${existingUser.balance}\n\n` +
              'Type "menu" to see available options.'
      });
    }

    if (args.length < 2) {
      return await socket.sendMessage(from, { 
        text: '📝 *Registration*\n\n' +
              'Please provide your name and PIN:\n' +
              'Format: register <name> <4-digit PIN>\n\n' +
              'Example: register John 1234\n\n' +
              '⚠️ Keep your PIN secure!'
      });
    }

    const name = args[0];
    const pin = args[1];

    if (pin.length !== 4 || !/^\d+$/.test(pin)) {
      return await socket.sendMessage(from, { 
        text: '❌ PIN must be 4 digits only!\n\n' +
              'Example: register John 1234'
      });
    }

    try {
      // Call registration API
      const response = await axios.post(`${process.env.BASE_URL || 'http://localhost:3000'}/api/register`, {
        phone: phone,
        name: name,
        pin: pin
      });

      if (response.data.success) {
        await socket.sendMessage(from, { 
          text: `🎉 *Registration Successful!*\n\n` +
                `Welcome to BeraPay, ${name}! 🎊\n\n` +
                `Your account has been created successfully.\n` +
                `Starting balance: KSh 0\n\n` +
                `Type "menu" to explore features or "deposit" to add funds.`
        });
      }
    } catch (error) {
      const errorMsg = error.response?.data?.error || 'Registration failed';
      await socket.sendMessage(from, { 
        text: `❌ Registration failed: ${errorMsg}\n\nPlease try again.`
      });
    }
  }

  async handleBalance(socket, from, sender) {
    const phone = sender.split('@')[0];
    const user = await User.findOne({ phone });

    if (!user) {
      return await socket.sendMessage(from, { 
        text: '❌ You are not registered yet!\n\n' +
              'Type "register <name> <PIN>" to create your account.\n' +
              'Example: register John 1234'
      });
    }

    await socket.sendMessage(from, { 
      text: `💰 *Your BeraPay Balance*\n\n` +
            `Name: ${user.name}\n` +
            `Balance: *KSh ${user.balance}*\n` +
            `Account: ${user.phone}\n\n` +
            `💸 To send money: "send <amount> <phone> <PIN>"\n` +
            `📥 To deposit: "deposit <amount> <PIN>"`
    });
  }

  async handleSendMoney(socket, from, sender, args) {
    const phone = sender.split('@')[0];
    const user = await User.findOne({ phone });

    if (!user) {
      return await socket.sendMessage(from, { 
        text: '❌ Please register first!\n\nType "register <name> <PIN>"'
      });
    }

    if (args.length < 3) {
      return await socket.sendMessage(from, { 
        text: '💸 *Send Money*\n\n' +
              'Format: send <amount> <recipient-phone> <your-PIN>\n\n' +
              'Example: send 100 0712345678 1234\n\n' +
              'You can send to any M-Pesa number or BeraPay user.'
      });
    }

    const [amount, recipient, pin] = args;

    if (isNaN(amount) || parseFloat(amount) <= 0) {
      return await socket.sendMessage(from, { 
        text: '❌ Invalid amount! Please enter a valid number.'
      });
    }

    try {
      const response = await axios.post(`${process.env.BASE_URL || 'http://localhost:3000'}/api/send`, {
        recipient: recipient,
        amount: parseFloat(amount),
        pin: pin
      }, {
        headers: {
          'Authorization': `Bearer ${this.getUserToken(phone)}`
        }
      });

      if (response.data.success) {
        await socket.sendMessage(from, { 
          text: `✅ *Money Sent Successfully!*\n\n` +
                `Amount: KSh ${amount}\n` +
                `To: ${recipient}\n` +
                `Reference: ${response.data.reference}\n` +
                `New Balance: KSh ${response.data.newBalance}\n\n` +
                `💚 Thank you for using BeraPay!`
        });
      }
    } catch (error) {
      const errorMsg = error.response?.data?.error || 'Send money failed';
      await socket.sendMessage(from, { 
        text: `❌ Send money failed: ${errorMsg}`
      });
    }
  }

  async handleDeposit(socket, from, sender, args) {
    const phone = sender.split('@')[0];
    const user = await User.findOne({ phone });

    if (!user) {
      return await socket.sendMessage(from, { 
        text: '❌ Please register first!\n\nType "register <name> <PIN>"'
      });
    }

    if (args.length < 2) {
      return await socket.sendMessage(from, { 
        text: '📥 *Deposit Funds*\n\n' +
              'Format: deposit <amount> <your-PIN>\n\n' +
              'Example: deposit 500 1234\n\n' +
              'You will receive an STK Push on your phone to complete the deposit.'
      });
    }

    const [amount, pin] = args;

    if (isNaN(amount) || parseFloat(amount) <= 0) {
      return await socket.sendMessage(from, { 
        text: '❌ Invalid amount! Please enter a valid number.'
      });
    }

    try {
      const response = await axios.post(`${process.env.BASE_URL || 'http://localhost:3000'}/api/deposit`, {
        amount: parseFloat(amount),
        pin: pin
      }, {
        headers: {
          'Authorization': `Bearer ${this.getUserToken(phone)}`
        }
      });

      if (response.data.success) {
        await socket.sendMessage(from, { 
          text: `📥 *Deposit Initiated!*\n\n` +
                `Amount: KSh ${amount}\n` +
                `Reference: ${response.data.reference}\n\n` +
                `Check your phone for STK Push to complete payment.\n` +
                `You will be notified when deposit is successful.`
        });
      }
    } catch (error) {
      const errorMsg = error.response?.data?.error || 'Deposit failed';
      await socket.sendMessage(from, { 
        text: `❌ Deposit failed: ${errorMsg}`
      });
    }
  }

  async handleTransactions(socket, from, sender) {
    const phone = sender.split('@')[0];
    const user = await User.findOne({ phone });

    if (!user) {
      return await socket.sendMessage(from, { 
        text: '❌ Please register first!\n\nType "register <name> <PIN>"'
      });
    }

    try {
      const response = await axios.get(`${process.env.BASE_URL || 'http://localhost:3000'}/api/transactions`, {
        headers: {
          'Authorization': `Bearer ${this.getUserToken(phone)}`
        }
      });

      if (response.data.success) {
        const transactions = response.data.transactions;
        
        if (transactions.length === 0) {
          return await socket.sendMessage(from, { 
            text: '📜 *Your Transactions*\n\nNo transactions yet.\n\nStart by depositing or sending money!'
          });
        }

        let transactionsText = `📜 *Your Recent Transactions*\n\n`;
        
        transactions.forEach((tx, index) => {
          const emoji = tx.isOutgoing ? '📤' : '📥';
          const type = tx.isOutgoing ? 'Sent' : 'Received';
          const sign = tx.isOutgoing ? '-' : '+';
          
          transactionsText += `${emoji} ${type}: ${sign}KSh ${tx.amount}\n`;
          transactionsText += `📝 ${tx.description}\n`;
          transactionsText += `🆔 ${tx.ref}\n`;
          transactionsText += `📅 ${new Date(tx.date).toLocaleDateString()}\n`;
          transactionsText += `---\n\n`;
        });

        transactionsText += `View full history on web dashboard.`;

        await socket.sendMessage(from, { text: transactionsText });
      }
    } catch (error) {
      const errorMsg = error.response?.data?.error || 'Failed to fetch transactions';
      await socket.sendMessage(from, { 
        text: `❌ Could not fetch transactions: ${errorMsg}`
      });
    }
  }

  async handleProfile(socket, from, sender) {
    const phone = sender.split('@')[0];
    const user = await User.findOne({ phone });

    if (!user) {
      return await socket.sendMessage(from, { 
        text: '❌ Please register first!\n\nType "register <name> <PIN>"'
      });
    }

    const transactionCount = await Transaction.countDocuments({
      $or: [{ sender: user.phone }, { receiver: user.phone }]
    });

    await socket.sendMessage(from, { 
      text: `⚙️ *Your BeraPay Profile*\n\n` +
            `👤 Name: ${user.name}\n` +
            `📱 Phone: ${user.phone}\n` +
            `💰 Balance: KSh ${user.balance}\n` +
            `📊 Total Transactions: ${transactionCount}\n` +
            `📅 Member Since: ${user.createdAt.toLocaleDateString()}\n\n` +
            `💚 Thank you for using BeraPay!`
    });
  }

  getUserToken(phone) {
    // In production, implement proper token management
    return 'temp-token';
  }

  async sendNotification(phone, message) {
    try {
      const jid = `${phone}@s.whatsapp.net`;
      if (this.socket) {
        await this.socket.sendMessage(jid, { text: message });
      }
    } catch (error) {
      console.error('Notification error:', error);
    }
  }
}

// Start the bot
const bot = new BeraPayBot();

module.exports = { BeraPayBot };
