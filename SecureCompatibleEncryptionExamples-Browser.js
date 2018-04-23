const ALGORITHM_NAME = "AES-GCM";
const ALGORITHM_NONCE_SIZE = 12;
const ALGORITHM_KEY_SIZE = 16 * 8;
const PBKDF2_SALT_SIZE = 16;
const PBKDF2_ITERATIONS = 32767;

function encryptString(plaintext, password) {
    // Generate a 128-bit salt using a CSPRNG and a nonce.
    let salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_SIZE));
    let nonce = crypto.getRandomValues(new Uint8Array(ALGORITHM_NONCE_SIZE));
    let aesGcm = { name: ALGORITHM_NAME, iv: nonce };

    // Derive a key using PBKDF2.
    return crypto.subtle.importKey("raw", (new TextEncoder()).encode(password), { name: "PBKDF2" }, false, ["deriveKey", "deriveBits"])
        .then((rawKey) => {
            let deriveParams = { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: { name: "SHA-256" } };
            return crypto.subtle.deriveKey(deriveParams, rawKey, { name: ALGORITHM_NAME, length: ALGORITHM_KEY_SIZE }, true, ["encrypt"])
        })
        .then((cryptoKey) => {
            return encryptWithCryptoKey(aesGcm, (new TextEncoder()).encode(plaintext), cryptoKey)
        })
        .then((ciphertext) => {
            return base64js.fromByteArray(joinBuffers(salt, ciphertext));
        });
}

function decryptString(base64CiphertextAndNonceAndSalt, password) {
    // Decode the base64.
    let ciphertextAndNonceAndSalt = base64js.toByteArray(base64CiphertextAndNonceAndSalt);

    // Create buffers of salt and ciphertextAndNonce.
    let salt = ciphertextAndNonceAndSalt.slice(0, PBKDF2_SALT_SIZE);
    let nonce = ciphertextAndNonceAndSalt.slice(PBKDF2_SALT_SIZE, PBKDF2_SALT_SIZE + ALGORITHM_NONCE_SIZE);
    let ciphertext = ciphertextAndNonceAndSalt.slice(PBKDF2_SALT_SIZE + ALGORITHM_NONCE_SIZE);
    let aesGcm = { name: ALGORITHM_NAME, iv: nonce };

    // Derive the key using PBKDF2.
    return crypto.subtle.importKey("raw", (new TextEncoder()).encode(password), { name: "PBKDF2" }, false, ["deriveKey", "deriveBits"])
        .then((rawKey) => {
            let deriveParams = { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: { name: "SHA-256" } };
            return crypto.subtle.deriveKey(deriveParams, rawKey, { name: ALGORITHM_NAME, length: ALGORITHM_KEY_SIZE }, true, ["decrypt"])
        })
        .then((cryptoKey) => {
            return decryptWithCryptoKey(aesGcm, ciphertext, cryptoKey)
        })
        .then((plaintext) => {
            return (new TextDecoder()).decode(plaintext);
        });
}

function encrypt(plaintext, key) {
    // Generate a 96-bit nonce using a CSPRNG.
    let nonce = crypto.getRandomValues(new Uint8Array(ALGORITHM_NONCE_SIZE));
    let aesGcm = { name: ALGORITHM_NAME, iv: nonce };

    // Create a 'CryptoKey'.
    return crypto.subtle.importKey("raw", key, aesGcm, false, ["encrypt"])
        .then((cryptoKey) => {
            encryptWithCryptoKey(aesGcm, plaintext, cryptoKey)
        })
        .then((ciphertextAndNonce) => {
            return ciphertextAndNonce;
        });
}
function encryptWithCryptoKey(aesGcm, plaintext, cryptoKey) {
    return crypto.subtle.encrypt(aesGcm, cryptoKey, plaintext)
        .then((ciphertext) => {
            return joinBuffers(aesGcm.iv, new Uint8Array(ciphertext));
        });
}

function decrypt(ciphertextAndNonce, key) {
    // Create buffers of the nonce and ciphertext.
    let nonce = ciphertextAndNonce.slice(0, ALGORITHM_NONCE_SIZE);
    let ciphertext = ciphertextAndNonce.slice(ALGORITHM_NONCE_SIZE);

    let aesGcm = { name: ALGORITHM_NAME, iv: nonce };

    // Create the 'CryptoKey'.
    return crypto.subtle.importKey("raw", key, aesGcm, false, ["decrypt"])
        .then((cryptoKey) => {
            return decryptWithCryptoKey(aesGcm, ciphertext, cryptoKey)
        })
        .then((plaintext) => {
            return plaintext;
        });
}
function decryptWithCryptoKey(aesGcm, ciphertext, cryptoKey) {
    return crypto.subtle.decrypt(aesGcm, cryptoKey, ciphertext)
        .then((plaintext) => {
            return new Uint8Array(plaintext);
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
