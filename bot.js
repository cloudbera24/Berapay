const connectToWhatsApp = require('./pair');
const { sms } = require('./msg');
const { User, Session, Transaction, Wallet } = require('./models');
const { processDeposit, processWithdrawal, processTransfer } = require('./payhero');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected for BeraPay Bot'))
  .catch(err => console.log('❌ MongoDB Error:', err));

async function startBot() {
  const conn = await connectToWhatsApp();
  console.log('🤖 BeraPay WhatsApp Bot Started');

  conn.ev.on('messages.upsert', async ({ messages }) => {
    const m = sms(conn, messages[0]);
    if (!m.body) return;
    
    const text = m.body.toLowerCase().trim();
    const phone = m.from.replace('@s.whatsapp.net', '');

    try {
      // Link WhatsApp to wallet
      if (text.startsWith('.link')) {
        const code = text.split(' ')[1];
        if (!code) return m.reply('⚠️ Please provide a link code. Usage: .link <code>');
        
        const session = await Session.findOne({ code, verified: false });
        if (!session) return m.reply('❌ Invalid or expired link code.');
        
        if (session.expiresAt < new Date()) {
          return m.reply('❌ Link code has expired. Please generate a new one.');
        }

        await Session.updateOne({ code }, { verified: true });
        await User.updateOne({ phone: session.phone }, { linked: true });
        
        return m.reply(`✅ WhatsApp linked successfully!\n\nType *.menu* to access your BeraPay wallet.`);
      }

      // Main menu
      if (text === '.menu' || text === 'menu') {
        const user = await User.findOne({ phone, linked: true });
        if (!user) {
          return m.reply(`🔗 You need to link your WhatsApp first.\n\n1. Visit the BeraPay website\n2. Generate a link code\n3. Send: .link <your_code>\n\nThen type .menu again.`);
        }

        await conn.sendMessage(m.from, {
          text: `👋 Welcome to BeraPay, ${user.name}!\n💰 Current Balance: KES ${user.balance}\n\nSelect an option:`,
          footer: "BeraPay - Secure Money Wallet",
          buttons: [
            { buttonId: "balance", buttonText: { displayText: "💰 Check Balance" }, type: 1 },
            { buttonId: "deposit", buttonText: { displayText: "📥 Deposit" }, type: 1 },
            { buttonId: "send", buttonText: { displayText: "💸 Send Money" }, type: 1 },
            { buttonId: "transactions", buttonText: { displayText: "📜 Transactions" }, type: 1 },
            { buttonId: "help", buttonText: { displayText: "❓ Help" }, type: 1 }
          ],
          headerType: 1
        });
      }

      // Balance check
      if (text === 'balance') {
        const user = await User.findOne({ phone, linked: true });
        if (!user) return m.reply('❌ Please link your WhatsApp first using .link <code>');
        
        return m.reply(`💰 Your BeraPay Balance: KES ${user.balance}\n\nType *.menu* for more options.`);
      }

      // Deposit
      if (text.startsWith('.deposit')) {
        const user = await User.findOne({ phone, linked: true });
        if (!user) return m.reply('❌ Please link your WhatsApp first.');
        
        const amount = parseFloat(text.split(' ')[1]);
        if (!amount || amount < 10) {
          return m.reply('⚠️ Please specify a valid amount (minimum KES 10).\nUsage: .deposit 100');
        }

        m.reply(`🔄 Initiating deposit of KES ${amount}...`);
        
        try {
          const result = await processDeposit(user.phone, amount);
          if (result.success) {
            m.reply(`📥 Deposit initiated!\n\nAmount: KES ${amount}\nStatus: ${result.message}\n\nYou will receive an M-Pesa prompt to complete the payment.`);
          } else {
            m.reply(`❌ Deposit failed: ${result.message}`);
          }
        } catch (error) {
          m.reply('❌ Error processing deposit. Please try again.');
        }
      }

      // Send money
      if (text.startsWith('.send')) {
        const user = await User.findOne({ phone, linked: true });
        if (!user) return m.reply('❌ Please link your WhatsApp first.');
        
        const parts = text.split(' ');
        if (parts.length < 3) {
          return m.reply('⚠️ Usage: .send <phone> <amount>\nExample: .send 254712345678 500');
        }
        
        const recipientPhone = parts[1];
        const amount = parseFloat(parts[2]);
        
        if (!amount || amount < 1) {
          return m.reply('❌ Please specify a valid amount (minimum KES 1).');
        }
        
        if (user.balance < amount) {
          return m.reply(`❌ Insufficient balance. Your balance: KES ${user.balance}`);
        }

        m.reply(`🔐 To send KES ${amount} to ${recipientPhone}, please reply with your 4-digit PIN:`);
        
        // Store pending transaction
        const pendingTx = {
          phone,
          type: 'transfer',
          recipient: recipientPhone,
          amount,
          timestamp: Date.now()
        };
        
        // Wait for PIN response
        const pinHandler = async (pinMsg) => {
          const pinText = pinMsg.body.trim();
          if (pinText.length === 4 && /^\d+$/.test(pinText)) {
            // Verify PIN
            const isValidPin = await user.verifyPin(pinText);
            if (!isValidPin) {
              conn.ev.off('messages.upsert', pinHandler);
              return m.reply('❌ Invalid PIN. Transaction cancelled.');
            }
            
            // Process transfer
            try {
              const result = await processTransfer(user.phone, recipientPhone, amount);
              if (result.success) {
                m.reply(`✅ Transfer successful!\n\nSent: KES ${amount}\nTo: ${recipientPhone}\nNew Balance: KES ${result.newBalance}`);
              } else {
                m.reply(`❌ Transfer failed: ${result.message}`);
              }
            } catch (error) {
              m.reply('❌ Error processing transfer. Please try again.');
            }
            
            conn.ev.off('messages.upsert', pinHandler);
          }
        };
        
        // Listen for PIN response (timeout after 2 minutes)
        conn.ev.on('messages.upsert', pinHandler);
        setTimeout(() => {
          conn.ev.off('messages.upsert', pinHandler);
        }, 120000);
      }

      // Transaction history
      if (text === 'transactions') {
        const user = await User.findOne({ phone, linked: true });
        if (!user) return m.reply('❌ Please link your WhatsApp first.');
        
        const transactions = await Transaction.find({
          $or: [{ sender: phone }, { receiver: phone }]
        })
        .sort({ createdAt: -1 })
        .limit(5);
        
        if (transactions.length === 0) {
          return m.reply('📜 No transactions found.');
        }
        
        let txList = '📜 Recent Transactions:\n\n';
        transactions.forEach(tx => {
          const type = tx.sender === phone ? 'Sent' : 'Received';
          const amount = tx.sender === phone ? `-${tx.amount}` : `+${tx.amount}`;
          const date = new Date(tx.createdAt).toLocaleDateString();
          
          txList += `${type}: KES ${amount}\n`;
          txList += `To/From: ${tx.sender === phone ? tx.receiver : tx.sender}\n`;
          txList += `Date: ${date}\nStatus: ${tx.status}\n\n`;
        });
        
        m.reply(txList);
      }

      // Help
      if (text === 'help' || text === '.help') {
        const helpText = `❓ BeraPay Help Guide\n\n` +
          `🔗 *Linking WhatsApp:*\n` +
          `1. Visit BeraPay website\n` +
          `2. Generate link code\n` +
          `3. Send: .link <code>\n\n` +
          `💳 *Available Commands:*\n` +
          `• .menu - Main menu\n` +
          `• .deposit <amount> - Add money\n` +
          `• .send <phone> <amount> - Send money\n` +
          `• balance - Check balance\n` +
          `• transactions - View history\n\n` +
          `📞 Support: 254740007567`;
        
        m.reply(helpText);
      }

      // Registration (via web only)
      if (text.startsWith('.register')) {
        m.reply(`📝 Registration is done on our website.\n\nPlease visit the BeraPay website to create your account and get your link code.`);
      }

    } catch (error) {
      console.error('Bot error:', error);
      m.reply('❌ An error occurred. Please try again.');
    }
  });

  // Handle connection updates
  conn.ev.on('connection.update', (update) => {
    const { connection, lastDisconnect } = update;
    if (connection === 'close') {
      console.log('❌ WhatsApp connection closed. Reconnecting...');
      setTimeout(startBot, 5000);
    } else if (connection === 'open') {
      console.log('✅ WhatsApp connected successfully');
    }
  });
}

// Start bot with error handling
startBot().catch(console.error);
