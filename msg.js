const { downloadMediaMessage } = require('@whiskeysockets/baileys');
const fs = require('fs-extra');
const path = require('path');

// Ensure uploads directory exists
const UPLOADS_DIR = './uploads';
if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Message helper functions
function sms(socket, msg) {
    const m = {
        ...msg,
        sock: socket,
        reply: async (text, quoted = msg) => {
            return await socket.sendMessage(msg.key.remoteJid, { text }, { quoted });
        },
        send: async (content, options = {}) => {
            return await socket.sendMessage(msg.key.remoteJid, content, { 
                ...options, 
                quoted: msg 
            });
        },
        react: async (emoji) => {
            return await socket.sendMessage(msg.key.remoteJid, {
                react: {
                    text: emoji,
                    key: msg.key
                }
            });
        }
    };
    
    return m;
}

// Download media with enhanced error handling
async function downloadAndSaveMedia(message, filename = null) {
    try {
        const buffer = await downloadMediaMessage(
            message,
            'buffer',
            {},
            {
                logger: console,
                reuploadRequest: async (msg) => {
                    // Handle reupload if needed
                    return msg;
                }
            }
        );

        if (!buffer || buffer.length === 0) {
            throw new Error('Empty buffer received');
        }

        const fileExt = getFileExtension(message);
        const finalFilename = filename || `media_${Date.now()}${fileExt}`;
        const filePath = path.join(UPLOADS_DIR, finalFilename);

        await fs.writeFile(filePath, buffer);
        
        return {
            success: true,
            filePath,
            filename: finalFilename,
            size: buffer.length,
            mimeType: getMimeType(message)
        };
    } catch (error) {
        console.error('Media download error:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

function getFileExtension(message) {
    if (message.imageMessage) return '.jpg';
    if (message.videoMessage) return '.mp4';
    if (message.audioMessage) return '.mp3';
    if (message.documentMessage) {
        const doc = message.documentMessage;
        if (doc.fileName) {
            return path.extname(doc.fileName) || '.bin';
        }
        return '.bin';
    }
    return '.bin';
}

function getMimeType(message) {
    if (message.imageMessage) return message.imageMessage.mimetype || 'image/jpeg';
    if (message.videoMessage) return message.videoMessage.mimetype || 'video/mp4';
    if (message.audioMessage) return message.audioMessage.mimetype || 'audio/mp4';
    if (message.documentMessage) return message.documentMessage.mimetype || 'application/octet-stream';
    return 'application/octet-stream';
}

// Generate transaction message template
function generateTransactionMessage(transaction) {
    const isDeposit = transaction.type === 'deposit';
    const isSend = transaction.type === 'send';
    
    let message = `📊 *Transaction Update*\n\n`;
    message += `🔖 Reference: ${transaction.ref}\n`;
    message += `💰 Amount: KES ${transaction.amount.toLocaleString()}\n`;
    message += `📋 Type: ${transaction.type.toUpperCase()}\n`;
    message += `📊 Status: ${transaction.status}\n`;
    
    if (isSend) {
        message += `👤 To: ${transaction.receiver}\n`;
    } else if (isDeposit) {
        message += `📥 From: ${transaction.sender}\n`;
    }
    
    message += `🕒 Date: ${new Date(transaction.createdAt).toLocaleString()}\n\n`;
    
    if (transaction.status === 'completed') {
        message += `✅ Transaction completed successfully`;
    } else if (transaction.status === 'pending') {
        message += `⏳ Transaction is processing...`;
    } else {
        message += `❌ Transaction failed`;
    }
    
    return message;
}

// Generate balance message
function generateBalanceMessage(user, transactions = []) {
    let message = `🏦 *BeraPay Wallet*\n\n`;
    message += `👤 ${user.name}\n`;
    message += `📱 ${user.phone}\n`;
    message += `💰 Balance: *KES ${user.balance.toLocaleString()}*\n\n`;
    
    if (transactions.length > 0) {
        message += `📜 Recent Activity:\n`;
        transactions.slice(0, 3).forEach((txn, index) => {
            const isSent = txn.sender === user.phone;
            const icon = isSent ? '➡️' : '⬅️';
            const amount = `KES ${txn.amount.toLocaleString()}`;
            
            message += `${icon} ${amount} - ${txn.status}\n`;
        });
    } else {
        message += `No recent transactions\n`;
    }
    
    message += `\nType *.menu* for options`;
    
    return message;
}

// Generate main menu
function generateMainMenu() {
    return {
        text: `🏦 *BeraPay Wallet Menu*\n\nChoose an option below:`,
        buttons: [
            { 
                buttonId: 'register_btn', 
                buttonText: { displayText: '📝 Register' } 
            },
            { 
                buttonId: 'balance_btn', 
                buttonText: { displayText: '💰 Balance' } 
            },
            { 
                buttonId: 'send_btn', 
                buttonText: { displayText: '💸 Send Money' } 
            },
            { 
                buttonId: 'deposit_btn', 
                buttonText: { displayText: '📥 Deposit' } 
            },
            { 
                buttonId: 'transactions_btn', 
                buttonText: { displayText: '📜 Transactions' } 
            }
        ],
        headerType: 1
    };
}

// Validate phone number
function validatePhone(phone) {
    const cleanPhone = phone.replace(/\D/g, '');
    return /^254[0-9]{9}$/.test(cleanPhone);
}

// Format currency
function formatCurrency(amount) {
    return new Intl.NumberFormat('en-KE', {
        style: 'currency',
        currency: 'KES'
    }).format(amount);
}

module.exports = {
    sms,
    downloadAndSaveMedia,
    generateTransactionMessage,
    generateBalanceMessage,
    generateMainMenu,
    validatePhone,
    formatCurrency
};
