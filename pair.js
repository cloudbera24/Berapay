const express = require('express');
const fs = require('fs-extra');
const path = require('path');
const { makeid } = require('./Id');
const router = express.Router();

const {
    default: makeWASocket,
    useMultiFileAuthState,
    delay,
    Browsers,
    makeCacheableSignalKeyStore
} = require('@whiskeysockets/baileys');
const pino = require('pino');

const SESSION_BASE_PATH = './sessions';
const activeSockets = new Map();

// Ensure session directory exists
if (!fs.existsSync(SESSION_BASE_PATH)) {
    fs.mkdirSync(SESSION_BASE_PATH, { recursive: true });
}

// Enhanced connection function for BeraPay
async function createBeraPayConnection(number, res) {
    const sanitizedNumber = number.replace(/[^0-9]/g, '');
    const sessionPath = path.join(SESSION_BASE_PATH, `berapay_${sanitizedNumber}`);

    // Check if already connected
    if (activeSockets.has(sanitizedNumber)) {
        return res.json({ 
            status: 'already_connected',
            message: 'This number is already connected to BeraPay',
            number: sanitizedNumber
        });
    }

    const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
    const logger = pino({ level: 'silent' });

    try {
        const socket = makeWASocket({
            auth: {
                creds: state.creds,
                keys: makeCacheableSignalKeyStore(state.keys, logger),
            },
            printQRInTerminal: false,
            logger,
            browser: Browsers.macOS('Safari'),
            markOnlineOnConnect: true,
            syncFullHistory: false,
            transactionOpts: { maxCommitRetries: 3 }
        });

        // Handle credentials update
        socket.ev.on('creds.update', async () => {
            await saveCreds();
            console.log(`✅ Credentials updated for ${sanitizedNumber}`);
        });

        // Handle connection updates
        socket.ev.on('connection.update', async (update) => {
            const { connection, qr, lastDisconnect } = update;
            
            console.log(`🔗 Connection update for ${sanitizedNumber}:`, connection);
            
            if (qr) {
                // Generate pairing code for manual linking
                const pairingCode = await socket.requestPairingCode(sanitizedNumber);
                
                if (!res.headersSent) {
                    res.json({ 
                        status: 'code_required', 
                        code: pairingCode,
                        message: `Send ".link ${pairingCode}" to BeraPay WhatsApp bot`,
                        number: sanitizedNumber
                    });
                }
            }

            if (connection === 'open') {
                activeSockets.set(sanitizedNumber, socket);
                console.log(`✅ BeraPay connected: ${sanitizedNumber}`);
                
                // Send welcome message
                const userJid = `${sanitizedNumber}@s.whatsapp.net`;
                try {
                    await socket.sendMessage(userJid, {
                        text: `🏦 *Welcome to BeraPay!*\n\nYour WhatsApp has been successfully linked to BeraPay wallet.\n\nType *.menu* to see wallet options:\n• Check Balance\n• Send Money\n• Deposit\n• View Transactions`
                    });
                } catch (welcomeError) {
                    console.log('Welcome message skipped (may be first connection)');
                }

                if (!res.headersSent) {
                    res.json({ 
                        status: 'connected',
                        message: 'WhatsApp successfully connected to BeraPay!',
                        number: sanitizedNumber
                    });
                }
            }

            if (connection === 'close') {
                const statusCode = lastDisconnect?.error?.output?.statusCode;
                console.log(`🔴 Connection closed for ${sanitizedNumber}:`, statusCode);
                
                activeSockets.delete(sanitizedNumber);
                
                if (statusCode === 401) {
                    // Session expired, clean up
                    if (fs.existsSync(sessionPath)) {
                        fs.removeSync(sessionPath);
                        console.log(`🧹 Cleaned expired session for ${sanitizedNumber}`);
                    }
                }
            }
        });

        // Handle messages for link verification
        socket.ev.on('messages.upsert', async ({ messages }) => {
            const msg = messages[0];
            if (!msg.message || msg.key.remoteJid === 'status@broadcast') return;

            const messageType = Object.keys(msg.message)[0];
            let body = '';
            
            if (messageType === 'conversation') {
                body = msg.message.conversation;
            } else if (messageType === 'extendedTextMessage') {
                body = msg.message.extendedTextMessage.text;
            }

            // Handle .link command directly in pair.js for immediate response
            if (body.startsWith('.link ')) {
                const code = body.split(' ')[1];
                const sender = msg.key.remoteJid;
                
                // Simple verification - in production, this would check MongoDB
                if (code && code.length === 6) {
                    await socket.sendMessage(sender, {
                        text: `✅ *Account Linked Successfully!*\n\nYour WhatsApp is now connected to BeraPay wallet.\n\nType *.menu* to access:\n💰 Check Balance\n💸 Send Money\n📥 Deposit\n📜 View Transactions\n\nVisit dashboard: https://berapay.onrender.com/dashboard`
                    });
                }
            }
        });

        // If already registered, just connect
        if (socket.authState.creds.registered) {
            console.log(`🔄 Reconnecting existing session: ${sanitizedNumber}`);
        }

    } catch (error) {
        console.error('❌ BeraPay connection error:', error);
        
        // Clean up on error
        if (fs.existsSync(sessionPath)) {
            fs.removeSync(sessionPath);
        }
        activeSockets.delete(sanitizedNumber);
        
        if (!res.headersSent) {
            res.status(500).json({ 
                error: 'Connection failed',
                details: error.message 
            });
        }
    }
}

// Routes
router.get('/', async (req, res) => {
    const { number } = req.query;
    
    if (!number) {
        return res.status(400).json({ error: 'Phone number is required' });
    }

    if (!number.startsWith('254')) {
        return res.status(400).json({ error: 'Phone must start with 254' });
    }

    await createBeraPayConnection(number, res);
});

router.get('/active', (req, res) => {
    const activeConnections = Array.from(activeSockets.keys()).map(phone => ({
        phone,
        connected: true,
        timestamp: new Date().toISOString()
    }));
    
    res.json({
        status: 'success',
        total_connected: activeSockets.size,
        connections: activeConnections
    });
});

router.get('/status/:number', (req, res) => {
    const number = req.params.number.replace(/[^0-9]/g, '');
    const isConnected = activeSockets.has(number);
    
    res.json({
        number,
        connected: isConnected,
        status: isConnected ? 'active' : 'disconnected'
    });
});

router.post('/disconnect', async (req, res) => {
    const { number } = req.body;
    const sanitizedNumber = number.replace(/[^0-9]/g, '');
    
    if (activeSockets.has(sanitizedNumber)) {
        try {
            activeSockets.get(sanitizedNumber).ws.close();
            activeSockets.delete(sanitizedNumber);
            
            // Clean up session files
            const sessionPath = path.join(SESSION_BASE_PATH, `berapay_${sanitizedNumber}`);
            if (fs.existsSync(sessionPath)) {
                fs.removeSync(sessionPath);
            }
            
            res.json({ 
                success: true, 
                message: 'Disconnected successfully',
                number: sanitizedNumber
            });
        } catch (error) {
            res.status(500).json({ 
                error: 'Disconnection failed',
                details: error.message 
            });
        }
    } else {
        res.status(404).json({ 
            error: 'Number not found in active connections' 
        });
    }
});

router.post('/broadcast', async (req, res) => {
    const { message } = req.body;
    
    if (!message) {
        return res.status(400).json({ error: 'Message is required' });
    }

    try {
        const results = [];
        
        for (const [number, socket] of activeSockets) {
            try {
                await socket.sendMessage(`${number}@s.whatsapp.net`, { text: message });
                results.push({ number, status: 'sent' });
            } catch (error) {
                results.push({ number, status: 'failed', error: error.message });
            }
        }
        
        res.json({
            success: true,
            sent_to: results.filter(r => r.status === 'sent').length,
            failed: results.filter(r => r.status === 'failed').length,
            results
        });
    } catch (error) {
        res.status(500).json({ 
            error: 'Broadcast failed',
            details: error.message 
        });
    }
});

// Auto-reconnect on startup
async function reconnectExistingSessions() {
    try {
        if (fs.existsSync(SESSION_BASE_PATH)) {
            const sessions = fs.readdirSync(SESSION_BASE_PATH);
            
            for (const sessionDir of sessions) {
                if (sessionDir.startsWith('berapay_')) {
                    const number = sessionDir.replace('berapay_', '');
                    
                    // Skip if already connected
                    if (activeSockets.has(number)) continue;
                    
                    console.log(`🔄 Attempting to reconnect: ${number}`);
                    
                    const mockRes = {
                        headersSent: false,
                        json: (data) => console.log(`Reconnect result for ${number}:`, data.status),
                        status: () => mockRes
                    };
                    
                    await createBeraPayConnection(number, mockRes);
                    await delay(2000); // Wait between reconnections
                }
            }
        }
    } catch (error) {
        console.error('❌ Auto-reconnect error:', error);
    }
}

// Start auto-reconnect after a delay
setTimeout(() => {
    reconnectExistingSessions();
}, 5000);

module.exports = router;
