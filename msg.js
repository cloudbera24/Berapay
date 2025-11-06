const { downloadContentFromMessage, getContentType } = require('@whiskeysockets/baileys');
const fs = require('fs');
const path = require('path');

exports.sms = (conn, msg) => {
  if (!msg.message) return null;

  const message = msg.message;
  const type = getContentType(message);
  let text = '';
  
  if (type === 'conversation') {
    text = message.conversation;
  } else if (type === 'extendedTextMessage') {
    text = message.extendedTextMessage.text;
  } else if (type === 'imageMessage') {
    text = message.imageMessage.caption || '';
  } else if (type === 'videoMessage') {
    text = message.videoMessage.caption || '';
  }

  const sender = msg.key.remoteJid;
  const isGroup = sender.endsWith('@g.us');
  const from = sender;
  const name = msg.pushName || 'User';
  const messageId = msg.key.id;

  async function reply(text, options = {}) {
    try {
      await conn.sendMessage(from, { text }, { 
        quoted: msg,
        ...options 
      });
    } catch (error) {
      console.error('Reply error:', error);
    }
  }

  async function downloadMedia() {
    try {
      const m = message.imageMessage || message.videoMessage || message.documentMessage;
      if (!m) return null;
      
      const mediaType = m.mimetype ? m.mimetype.split('/')[0] : 'document';
      const stream = await downloadContentFromMessage(m, mediaType);
      
      let buffer = Buffer.from([]);
      for await (const chunk of stream) {
        buffer = Buffer.concat([buffer, chunk]);
      }
      
      const ext = m.mimetype ? m.mimetype.split('/')[1] : 'bin';
      const fileName = `media_${Date.now()}.${ext}`;
      const filePath = path.join(__dirname, 'uploads', fileName);
      
      // Ensure uploads directory exists
      if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
        fs.mkdirSync(path.join(__dirname, 'uploads'), { recursive: true });
      }
      
      fs.writeFileSync(filePath, buffer);
      return filePath;
    } catch (error) {
      console.error('Download error:', error);
      return null;
    }
  }

  return {
    body: text.trim(),
    type,
    from,
    name,
    isGroup,
    messageId,
    reply,
    downloadMedia,
    rawMessage: msg
  };
};
