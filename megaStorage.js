const Mega = require('megajs');
const fs = require('fs');
const path = require('path');

class MegaStorage {
    constructor(email, password) {
        this.email = email;
        this.password = password;
        this.storage = null;
        this.initialized = false;
    }

    async initialize() {
        if (this.initialized) return;
        
        this.storage = await new Promise((resolve, reject) => {
            const storage = new Mega({
                email: this.email,
                password: this.password
            });
            
            storage.on('ready', () => {
                console.log('MEGA storage initialized successfully');
                resolve(storage);
            });
            
            storage.on('error', (error) => {
                console.error('MEGA initialization error:', error);
                reject(error);
            });
        });
        
        this.initialized = true;
    }

    async uploadFile(filePath, remoteFilename) {
        await this.initialize();
        
        return new Promise((resolve, reject) => {
            fs.stat(filePath, (err, stats) => {
                if (err) return reject(err);
                
                const readStream = fs.createReadStream(filePath);
                this.storage.upload({
                    name: remoteFilename,
                    size: stats.size,
                    allowUploadBuffering: true
                }, readStream).exec((err, file) => {
                    if (err) return reject(err);
                    resolve(file);
                });
            });
        });
    }

    async uploadBuffer(buffer, remoteFilename) {
        await this.initialize();
        
        return new Promise((resolve, reject) => {
            this.storage.upload({
                name: remoteFilename,
                size: buffer.length,
                allowUploadBuffering: true
            }, buffer).exec((err, file) => {
                if (err) return reject(err);
                resolve(file);
            });
        });
    }

    async downloadFile(remoteFilename, localPath) {
        await this.initialize();
        
        return new Promise((resolve, reject) => {
            const files = this.storage.files;
            const file = Object.values(files).find(f => f.name === remoteFilename);
            
            if (!file) {
                return reject(new Error('File not found'));
            }
            
            file.download((err, data) => {
                if (err) return reject(err);
                
                fs.mkdirSync(path.dirname(localPath), { recursive: true });
                fs.writeFileSync(localPath, data);
                resolve(localPath);
            });
        });
    }

    async downloadBuffer(remoteFilename) {
        await this.initialize();
        
        return new Promise((resolve, reject) => {
            const files = this.storage.files;
            const file = Object.values(files).find(f => f.name === remoteFilename);
            
            if (!file) {
                return reject(new Error('File not found'));
            }
            
            file.download((err, data) => {
                if (err) return reject(err);
                resolve(data);
            });
        });
    }

    async listFiles() {
        await this.initialize();
        
        return Object.values(this.storage.files).map(file => file.name);
    }

    async deleteFile(remoteFilename) {
        await this.initialize();
        
        return new Promise((resolve, reject) => {
            const files = this.storage.files;
            const file = Object.values(files).find(f => f.name === remoteFilename);
            
            if (!file) return resolve(false);
            
            file.delete((err) => {
                if (err) return reject(err);
                resolve(true);
            });
        });
    }

    async fileExists(remoteFilename) {
        await this.initialize();
        
        const files = this.storage.files;
        return Object.values(files).some(file => file.name === remoteFilename);
    }

    async getFileLink(remoteFilename) {
        await this.initialize();
        
        return new Promise((resolve, reject) => {
            const files = this.storage.files;
            const file = Object.values(files).find(f => f.name === remoteFilename);
            
            if (!file) return reject(new Error('File not found'));
            
            file.link((err, link) => {
                if (err) return reject(err);
                resolve(link);
            });
        });
    }
}

module.exports = MegaStorage;
