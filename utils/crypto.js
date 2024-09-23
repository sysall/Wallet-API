const CryptoJS = require('crypto-js')

const CryptoDecryption = {

    encrypt: function(text) {
        try {
            const key = process.env.CRYPTO_PASS;
            const iv = CryptoJS.lib.WordArray.random(16);
            const cipherText = CryptoJS.AES.encrypt(text, CryptoJS.enc.Utf8.parse(key), {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });

            const encryptedText = iv.toString() + ':' + cipherText.toString();
            return encryptedText;
        } catch (err) {
            throw new Error('Error @ encrypt: ' + err.message);
        }
    },

    decrypt: function(text) {
        try {
            const key = process.env.CRYPTO_PASS;
            const textParts = text.split(':');
            const iv = CryptoJS.enc.Hex.parse(textParts[0]);
            const cipherText = textParts[1];

            const decrypted = CryptoJS.AES.decrypt(cipherText, CryptoJS.enc.Utf8.parse(key), {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });

            const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
            return decryptedText;
        } catch (err) {
            throw new Error('Error @ decrypt: ' + err.message);
        }
    },

    randomString: function() {
        try {

            var string = '';
            var characters = Date.now().toString();
            var charactersLength = characters.length;
            for (var i = 0; i < 5; i++) {
                string += characters.charAt(Math.floor(Math.random() *
                    charactersLength));
            }
            string = string;
            return string.toUpperCase();
        } catch (error) {
            console.log('Error @ randomString :', error)
            return false;
        }
    }
}


module.exports = CryptoDecryption

