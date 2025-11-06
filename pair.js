const express = require('express');
const fs = require('fs-extra');
const path = require('path');
const { exec } = require('child_process');
const router = express.Router();
const pino = require('pino');
const axios = require('axios');

const { sms } = require("./msg");
const {
    default: makeWASocket,
    useMultiFileAuthState,
    delay,
    makeCacheableSignalKeyStore,
    Browsers
} = require('@whiskeysockets/baileys');

// Import wallet models
const { User, Transaction, Session } = require('./models');

const config = {
    PREFIX: '.',
    OWNER_NUMBER: '254740007567',
    SESSION_BASE_PATH: './sessions'
};

const activeSockets = new Map();

// Ensure sessions directory exists
if (!fs.existsSync(config.SESSION_BASE_PATH)) {
    fs.mkdirSync(config.SESSION_BASE_PATH, { recursive: true });
}

// Wallet-specific command handlers
async function handleWalletCommand(socket, m, command, args) {
    const sender = m.sender;
    const body = m.body || '';
    
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
                
            case 'transactions':
                await handleTransactionsCommand(socket, m);
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

// Command implementations (similar to bot.js but adapted for pair.js structure)
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

// Setup wallet message handlers
function setupWalletHandlers(socket, phoneNumber) {
    socket.ev.on('messages.upsert', async ({ messages }) => {
        const msg = messages[0];
        if (!msg.message || msg.key.remoteJid === 'status@broadcast') return;

        const m = sms(socket, msg);
        const body = m.body || '';
        const isGroup = m.isGroup;

        // Ignore group messages and non-command messages
        if (isGroup || !body.startsWith(config.PREFIX)) return;

        const command = body.slice(config.PREFIX.length).trim().split(' ')[0].toLowerCase();
        const args = body.slice(config.PREFIX.length).trim().split(' ').slice(1);

        await handleWalletCommand(socket, m, command, args);
    });
}

// Modified EmpirePair function for wallet
async function EmpirePair(number, res) {
    const sanitizedNumber = number.replace(/[^0-9]/g, '');
    const sessionPath = path.join(config.SESSION_BASE_PATH, `session_${sanitizedNumber}`);

    await fs.ensureDir(sessionPath);

    const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
    const logger = pino({ level: 'fatal' });

    try {
        const socket = makeWASocket({
            auth: {
                creds: state.creds,
                keys: makeCacheableSignalKeyStore(state.keys, logger),
            },
            printQRInTerminal: false,
            logger,
            browser: Browsers.ubuntu('Chrome')
        });

        // Setup wallet handlers instead of entertainment handlers
        setupWalletHandlers(socket, sanitizedNumber);
        
        socket.ev.on('creds.update', saveCreds);
        
        socket.ev.on('connection.update', async (update) => {
            const { connection } = update;
            
            if (connection === 'open') {
                console.log(`✅ WhatsApp connected for wallet: ${sanitizedNumber}`);
                activeSockets.set(sanitizedNumber, socket);
                
                // Send welcome message
                const user = await User.findOne({ phone: sanitizedNumber });
                if (user) {
                    await socket.sendMessage(socket.user.id, {
                        text: `🔄 *BeraPay Reconnected*\n\n💰 Balance: KSh ${user.balance}\nType *.menu* for commands.`
                    });
                } else {
                    await socket.sendMessage(socket.user.id, {
                        text: `🤝 *Welcome to BeraPay!*\n\nType *.register* to create your wallet or *.link* if you have a code.`
                    });
                }
            }
            
            if (connection === 'close') {
                console.log(`🔌 Connection closed for wallet: ${sanitizedNumber}`);
                activeSockets.delete(sanitizedNumber);
            }
        });

        // Handle pairing code generation for new connections
        if (!socket.authState.creds.registered) {
            try {
                const code = await socket.requestPairingCode(sanitizedNumber);
                if (!res.headersSent) {
                    res.send({ code });
                }
            } catch (error) {
                if (!res.headersSent) {
                    res.status(500).send({ error: 'Failed to generate pairing code' });
                }
            }
        }

    } catch (error) {
        console.error('Wallet pairing error:', error);
        if (!res.headersSent) {
            res.status(503).send({ error: 'Service unavailable' });
        }
    }
}

// Routes
router.get('/', async (req, res) => {
    const { number } = req.query;
    if (!number) {
        return res.status(400).send({ error: 'Number parameter required' });
    }

    if (activeSockets.has(number.replace(/[^0-9]/g, ''))) {
        return res.status(200).send({
            status: 'already_connected',
            message: 'Number already connected'
        });
    }

    await EmpirePair(number, res);
});

router.get('/active', (req, res) => {
    res.status(200).send({
        count: activeSockets.size,
        numbers: Array.from(activeSockets.keys())
    });
});

module.exports = router;
