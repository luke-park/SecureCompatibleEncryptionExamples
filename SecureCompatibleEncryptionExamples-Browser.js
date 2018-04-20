const ALGORITHM_NAME = "AES-GCM";
const ALGORITHM_NONCE_SIZE = 12;
const ALGORITHM_KEY_SIZE = 16 * 8;
const PBKDF2_SALT_SIZE = 16;
const PBKDF2_ITERATIONS = 32767;

function encryptString(plaintext, password) {
    return new Promise((res, rej) => {
        // Generate a 128-bit salt using a CSPRNG and a nonce.
        let salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_SIZE));
        let nonce = crypto.getRandomValues(new Uint8Array(ALGORITHM_NONCE_SIZE));
        let aesGcm = { name: ALGORITHM_NAME, iv: nonce };

        // Derive a key using PBKDF2.
        crypto.subtle.importKey("raw", (new TextEncoder()).encode(password), { name: "PBKDF2" }, false, [ "deriveKey", "deriveBits" ])
        .then((rawKey) => {
            let deriveParams = { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: { name: "SHA-256" } };
            crypto.subtle.deriveKey(deriveParams, rawKey, { name: ALGORITHM_NAME, length: ALGORITHM_KEY_SIZE }, true, [ "encrypt" ])
            .then((cryptoKey) => {
                encryptWithCryptoKey(aesGcm, (new TextEncoder()).encode(plaintext), cryptoKey)
                .then((ciphertext) => {
                    res(base64js.fromByteArray(joinBuffers(salt, ciphertext)));
                }).catch((err) => { rej(err); });
            });
        }).catch((err) => { rej(err); });
    });
}

function decryptString(base64CiphertextAndNonceAndSalt, password) {
    return new Promise((res, rej) => {
        // Decode the base64.
        let ciphertextAndNonceAndSalt = base64js.toByteArray(base64CiphertextAndNonceAndSalt);
        
        // Create buffers of salt and ciphertextAndNonce.
        let salt = ciphertextAndNonceAndSalt.slice(0, PBKDF2_SALT_SIZE);
        let nonce = ciphertextAndNonceAndSalt.slice(PBKDF2_SALT_SIZE, PBKDF2_SALT_SIZE + ALGORITHM_NONCE_SIZE);
        let ciphertext = ciphertextAndNonceAndSalt.slice(PBKDF2_SALT_SIZE + ALGORITHM_NONCE_SIZE);
        let aesGcm = { name: ALGORITHM_NAME, iv: nonce };
        console.log(ciphertextAndNonceAndSalt);
        console.log(salt);
        console.log(nonce);
        console.log(ciphertext);

        // Derive the key using PBKDF2.
        crypto.subtle.importKey("raw", (new TextEncoder()).encode(password), { name: "PBKDF2" }, false, [ "deriveKey", "deriveBits" ])
        .then((rawKey) => {
            let deriveParams = { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: { name: "SHA-256" } };
            crypto.subtle.deriveKey(deriveParams, rawKey, { name: ALGORITHM_NAME, length: ALGORITHM_KEY_SIZE }, true, [ "decrypt" ])
            .then((cryptoKey) => {
                decryptWithCryptoKey(aesGcm, ciphertext, cryptoKey)
                .then((plaintext) => {
                    res((new TextDecoder()).decode(plaintext));
                }).catch((err) => { rej(err); });
            });
        }).catch((err) => { rej(err); });
    });
}

function encrypt(plaintext, key) {
    return new Promise((res, rej) => {

        // Generate a 96-bit nonce using a CSPRNG.
        let nonce = crypto.getRandomValues(new Uint8Array(ALGORITHM_NONCE_SIZE));
        let aesGcm = { name: ALGORITHM_NAME, iv: nonce };
        
        // Create a 'CryptoKey'.
        crypto.subtle.importKey("raw", key, aesGcm, false, ["encrypt"]).then((cryptoKey) => {
            encryptWithCryptoKey(aesGcm, plaintext, cryptoKey)
            .then((ciphertextAndNonce) => {
                res(ciphertextAndNonce);
            }).catch((err) => { rej(err); });
        }).catch((err) => { rej(err); });
    });
}
function encryptWithCryptoKey(aesGcm, plaintext, cryptoKey) {
    return new Promise((res, rej) => {
        crypto.subtle.encrypt(aesGcm, cryptoKey, plaintext)
        .then((ciphertext) => {
            res(joinBuffers(aesGcm.iv, new Uint8Array(ciphertext)));
        }).catch((err) => { rej(err); });
    });
}

function decrypt(ciphertextAndNonce, key) {
    return new Promise((res, rej) => {

        // Create buffers of the nonce and ciphertext.
        let nonce = ciphertextAndNonce.slice(0, ALGORITHM_NONCE_SIZE);
        let ciphertext = ciphertextAndNonce.slice(ALGORITHM_NONCE_SIZE);

        let aesGcm = { name: ALGORITHM_NAME, iv: nonce };
        
        // Create the 'CryptoKey'.
        crypto.subtle.importKey("raw", key, aesGcm, false, ["decrypt"])
        .then((cryptoKey) => {
            decryptWithCryptoKey(aesGcm, ciphertext, cryptoKey)
            .then((plaintext) => {
                res(plaintext);
            }).catch((err) => { rej(err); });
        }).catch((err) => { rej(err); });
    });
}
function decryptWithCryptoKey(aesGcm, ciphertext, cryptoKey) {
    return new Promise((res, rej) => {
        crypto.subtle.decrypt(aesGcm, cryptoKey, ciphertext)
        .then((plaintext) => {
            res(new Uint8Array(plaintext));
        }).catch((err) => { rej(err); });
    });
}

function joinBuffers(a, b) {
    let c = new Uint8Array(a.byteLength + b.byteLength);

    for (let i = 0; i < a.length; i++) {
        c[i] = a[i];
    }
    for (let i = 0; i < b.length; i++) {
        c[i + a.length] = b[i];
    }

    return c;
}
