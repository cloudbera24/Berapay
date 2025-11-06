require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { sms } = require('./msg');
const {
    default: makeWASocket,
    useMultiFileAuthState,
    delay,
    makeCacheableSignalKeyStore,
    Browsers
} = require('@whiskeysockets/baileys');

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
.catch(err => console.error('❌ MongoDB Error:', err));

// MongoDB Models
const userSchema = new mongoose.Schema({
    name: String,
    phone: { type: String, unique: true, required: true },
    pinHash: String,
    balance: { type: Number, default: 0 },
    linked: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const transactionSchema = new mongoose.Schema({
    ref: String,
    sender: String,
    receiver: String,
    amount: Number,
    type: String,
    status: { type: String, default: 'pending' },
    description: String,
    createdAt: { type: Date, default: Date.now }
});

const sessionSchema = new mongoose.Schema({
    phone: String,
    code: String,
    verified: { type: Boolean, default: false },
    expiresAt: Date,
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Session = mongoose.model('Session', sessionSchema);

// Import MEGA storage (from your working bot)
const MegaStorage = require('./megaStorage');
const megaStorage = new MegaStorage(
    process.env.MEGA_EMAIL || 'tohidkhan9050482152@gmail.com',
    process.env.MEGA_PASSWORD || 'Rvpy.B.6YeZn7CR'
);

// Active sockets map (EXACTLY like your working bot)
const activeSockets = new Map();
const socketCreationTime = new Map();
const SESSION_BASE_PATH = './sessions';

// WhatsApp Bot Setup (EXACTLY like your working bot)
async function createWhatsAppBot(phoneNumber) {
    const sanitizedNumber = phoneNumber.replace(/[^0-9]/g, '');
    const sessionPath = path.join(SESSION_BASE_PATH, `session_${sanitizedNumber}`);

    await fs.promises.mkdir(sessionPath, { recursive: true });

    const { state, saveCreds } = await useMultiFileAuthState(sessionPath);

    const socket = makeWASocket({
        auth: {
            creds: state.creds,
            keys: makeCacheableSignalKeyStore(state.keys, console),
        },
        printQRInTerminal: false,
        logger: console,
        browser: Browsers.ubuntu('Chrome')
    });

    socketCreationTime.set(sanitizedNumber, Date.now());

    // Setup wallet message handlers
    setupWalletHandlers(socket, sanitizedNumber);
    
    socket.ev.on('creds.update', saveCreds);
    
    socket.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect } = update;
        
        if (connection === 'open') {
            console.log(`✅ WhatsApp connected for: ${sanitizedNumber}`);
            activeSockets.set(sanitizedNumber, socket);
            
            // Send welcome message
            socket.sendMessage(socket.user.id, {
                text: `🤝 *Welcome to BeraPay Wallet!*\n\nType *.menu* to see available commands.`
            });
        }
        
        if (connection === 'close') {
            console.log(`🔌 WhatsApp disconnected for: ${sanitizedNumber}`);
            activeSockets.delete(sanitizedNumber);
        }
    });

    return socket;
}

// Wallet Command Handlers (like your working bot)
function setupWalletHandlers(socket, phoneNumber) {
    socket.ev.on('messages.upsert', async ({ messages }) => {
        const msg = messages[0];
        if (!msg.message || msg.key.remoteJid === 'status@broadcast') return;

        const m = sms(socket, msg);
        const body = m.body || '';
        const isGroup = m.isGroup;

        // Ignore group messages and non-command messages
        if (isGroup || !body.startsWith('.')) return;

        const command = body.slice(1).trim().split(' ')[0].toLowerCase();
        const args = body.slice(1).trim().split(' ').slice(1);

        await handleWalletCommand(socket, m, command, args);
    });
}

// Wallet Commands (like your working bot structure)
async function handleWalletCommand(socket, m, command, args) {
    const sender = m.sender;
    
    try {
        switch (command) {
            case 'link':
                await handleLinkCommand(socket, m, args);
                break;
                
            case 'register':
                await handleRegisterCommand(socket, m, args);
                break;
                
            case 'balance':
                await handleBalanceCommand(socket, m);
                break;
                
            case 'deposit':
                await handleDepositCommand(socket, m, args);
                break;
                
            case 'send':
                await handleSendCommand(socket, m, args);
                break;
                
            case 'menu':
                await handleMenuCommand(socket, m);
                break;
                
            case 'help':
                await handleHelpCommand(socket, m);
                break;
                
            default:
                await socket.sendMessage(sender, {
                    text: `❌ Unknown command. Type *.menu* for available commands.`
                });
        }
    } catch (error) {
        console.error('Wallet command error:', error);
        await socket.sendMessage(sender, {
            text: `❌ Error: ${error.message}`
        });
    }
}

// Command implementations
async function handleLinkCommand(socket, m, args) {
    if (args.length === 0) {
        return await socket.sendMessage(m.sender, {
            text: `🔗 *Usage:* .link <code>\n\nGet your code from the BeraPay website.`
        });
    }

    const code = args[0];
    const session = await Session.findOne({ code, verified: false });
    
    if (!session) {
        return await socket.sendMessage(m.sender, {
            text: `❌ Invalid or expired code. Generate a new one from the website.`
        });
    }

    if (Date.now() > session.expiresAt) {
        await Session.deleteOne({ _id: session._id });
        return await socket.sendMessage(m.sender, {
            text: `❌ Code expired. Generate a new one.`
        });
    }

    session.verified = true;
    await session.save();

    await User.findOneAndUpdate(
        { phone: session.phone },
        { linked: true }
    );

    await socket.sendMessage(m.sender, {
        text: `✅ *Account Linked!*\n\n📱 ${session.phone}\n💰 Wallet connected to WhatsApp!\n\nType *.menu* for commands.`
    });
}

async function handleRegisterCommand(socket, m, args) {
    const user = await User.findOne({ phone: m.sender.replace(/[^0-9]/g, '') });
    
    if (user) {
        return await socket.sendMessage(m.sender, {
            text: `✅ Already registered!\n💰 Balance: KSh ${user.balance}\nType *.menu* for commands.`
        });
    }

    if (args.length < 2) {
        return await socket.sendMessage(m.sender, {
            text: `📝 *Usage:* .register <name> <4-digit-PIN>\nExample: .register John Doe 1234`
        });
    }

    const name = args.slice(0, -1).join(' ');
    const pin = args[args.length - 1];

    if (!/^\d{4}$/.test(pin)) {
        return await socket.sendMessage(m.sender, {
            text: `❌ PIN must be 4 digits.`
        });
    }

    try {
        const newUser = new User({
            name,
            phone: m.sender.replace(/[^0-9]/g, ''),
            pinHash: pin,
            linked: true
        });

        await newUser.save();

        await socket.sendMessage(m.sender, {
            text: `🎉 *Registration Successful!*\n\n👤 ${name}\n📱 ${newUser.phone}\n💰 Balance: KSh 0\n\nType *.menu* for commands.`
        });
    } catch (error) {
        await socket.sendMessage(m.sender, {
            text: `❌ Registration failed: ${error.message}`
        });
    }
}

async function handleBalanceCommand(socket, m) {
    const user = await User.findOne({ phone: m.sender.replace(/[^0-9]/g, '') });
    
    if (!user) {
        return await socket.sendMessage(m.sender, {
            text: `❌ Not registered. Type *.register* to create wallet.`
        });
    }

    await socket.sendMessage(m.sender, {
        text: `💰 *Balance:* KSh ${user.balance}\n👤 ${user.name}\n📱 ${user.phone}`
    });
}

async function handleMenuCommand(socket, m) {
    const menuText = `
💰 *BERAPAY WALLET MENU*

📝 *.register* - Create wallet
🔗 *.link <code>* - Link account
💰 *.balance* - Check balance
📥 *.deposit <amount>* - Add funds
💸 *.send <phone> <amount>* - Send money
📜 *.transactions* - View history
🆘 *.help* - Get help

💡 Visit web dashboard for more features!
    `;

    await socket.sendMessage(m.sender, { text: menuText });
}

async function handleHelpCommand(socket, m) {
    const helpText = `
🆘 *BERAPAY HELP*

*Getting Started:*
1. Visit website to generate link code
2. Type *.link <code>* to connect
3. Type *.register <name> <PIN>* to create wallet

*Support:*
📞 Contact: +254740007567
🌐 Website: Your BeraPay URL

*Security:*
🔒 Never share your PIN
🔒 Keep WhatsApp secure
    `;

    await socket.sendMessage(m.sender, { text: helpText });
}

// Web Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Generate link code endpoint
app.post('/generate-code', async (req, res) => {
    try {
        const { phone } = req.body;
        
        if (!phone || !phone.match(/^254[0-9]{9}$/)) {
            return res.status(400).json({ 
                success: false,
                error: 'Valid Kenyan number required (2547...)' 
            });
        }

        const code = Math.floor(100000 + Math.random() * 900000).toString();
        
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
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// API Routes
app.get('/api/wallet/:phone', async (req, res) => {
    try {
        const { phone } = req.params;
        
        const user = await User.findOne({ phone });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const transactions = await Transaction.find({
            $or: [{ sender: phone }, { receiver: phone }]
        }).sort({ createdAt: -1 }).limit(10);

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

app.post('/api/wallet/send', async (req, res) => {
    try {
        const { fromPhone, toPhone, amount, pin } = req.body;

        const sender = await User.findOne({ phone: fromPhone });
        const recipient = await User.findOne({ phone: toPhone });

        if (!sender || !recipient) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (sender.pinHash !== pin) {
            return res.status(401).json({ error: 'Invalid PIN' });
        }

        const amountNum = parseFloat(amount);
        if (sender.balance < amountNum) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        sender.balance -= amountNum;
        recipient.balance += amountNum;

        await sender.save();
        await recipient.save();

        const transaction = new Transaction({
            ref: `TRF${Date.now()}`,
            sender: fromPhone,
            receiver: toPhone,
            amount: amountNum,
            type: 'transfer',
            status: 'completed',
            description: `Transfer to ${recipient.name}`
        });

        await transaction.save();

        res.json({
            success: true,
            message: 'Transfer successful',
            newBalance: sender.balance,
            transactionRef: transaction.ref
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// WhatsApp pairing endpoint
app.get('/pair', async (req, res) => {
    const { number } = req.query;
    
    if (!number) {
        return res.status(400).json({ error: 'Number parameter required' });
    }

    try {
        const socket = await createWhatsAppBot(number);
        
        if (!socket.authState.creds.registered) {
            const code = await socket.requestPairingCode(number);
            res.json({ code });
        } else {
            res.json({ status: 'already_registered' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        activeBots: activeSockets.size,
        environment: process.env.NODE_ENV || 'development'
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`
💰 BeraPay Wallet System Running
📍 Port: ${PORT}
🤖 WhatsApp: Baileys + MEGA Storage
💾 Database: MongoDB
🏠 Main Page: http://localhost:${PORT}/
📊 Dashboard: http://localhost:${PORT}/dashboard

🔧 Architecture:
✅ Baileys WhatsApp connection
✅ MEGA storage for sessions
✅ MongoDB for users/transactions
✅ Glass morphism frontend
✅ Real wallet commands
    `);
});

module.exports = app;
