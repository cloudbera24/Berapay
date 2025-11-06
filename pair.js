const { makeWASocket, useMultiFileAuthState, DisconnectReason, Browsers } = require('@whiskeysockets/baileys');
const P = require('pino');
const fs = require('fs');
const path = require('path');

// Ensure MegaStorage directory exists
const MEGA_STORAGE_PATH = './MegaStorage';
if (!fs.existsSync(MEGA_STORAGE_PATH)) {
  fs.mkdirSync(MEGA_STORAGE_PATH, { recursive: true });
}

async function connectToWhatsApp() {
  try {
    const { state, saveCreds } = await useMultiFileAuthState(MEGA_STORAGE_PATH);

    const sock = makeWASocket({
      logger: P({ level: 'silent' }),
      printQRInTerminal: true,
      auth: state,
      browser: Browsers.ubuntu('Chrome'),
      markOnlineOnConnect: true,
      generateHighQualityLinkPreview: true,
      syncFullHistory: false,
      linkPreviewImageThumbnailWidth: 192
    });

    sock.ev.on('connection.update', (update) => {
      const { connection, lastDisconnect, qr } = update;
      
      if (qr) {
        console.log('🔄 Scan the QR code above to connect WhatsApp');
      }
      
      if (connection === 'close') {
        const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
        console.log('❌ Connection closed:', lastDisconnect?.error?.message);
        
        if (shouldReconnect) {
          console.log('🔄 Reconnecting...');
          setTimeout(connectToWhatsApp, 5000);
        } else {
          console.log('❌ Logged out. Please delete MegaStorage folder and restart.');
        }
      } else if (connection === 'open') {
        console.log('✅ WhatsApp connected successfully for BeraPay');
      }
    });

    sock.ev.on('creds.update', saveCreds);
    
    return sock;
  } catch (error) {
    console.error('❌ WhatsApp connection error:', error);
    throw error;
  }
}

module.exports = connectToWhatsApp;
