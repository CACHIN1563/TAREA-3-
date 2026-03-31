const NodeRSA = require('node-rsa');

function generateKeyPair(bits = 2048) {
    const key = new NodeRSA({ b: bits });
    return {
        public: key.exportKey('public'),
        private: key.exportKey('private')
    };
}

function encryptText(text, publicKey) {
    const key = new NodeRSA(publicKey);
    return key.encrypt(text, 'base64');
}

function decryptText(encryptedText, privateKey) {
    try {
        const key = new NodeRSA(privateKey);
        return key.decrypt(encryptedText, 'utf8');
    } catch (error) {
        console.error('Error decrypting:', error);
        return null;
    }
}

module.exports = {
    generateKeyPair,
    encryptText,
    decryptText
};
