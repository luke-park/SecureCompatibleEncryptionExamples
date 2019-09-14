const crypto = require("crypto");

const ALGORITHM_NAME = "aes-128-gcm";
const ALGORITHM_NONCE_SIZE = 12;
const ALGORITHM_TAG_SIZE = 16;
const ALGORITHM_KEY_SIZE = 16;
const PBKDF2_NAME = "sha256";
const PBKDF2_SALT_SIZE = 16;
const PBKDF2_ITERATIONS = 32767;

function encryptString(plaintext, password) {
    // Generate a 128-bit salt using a CSPRNG.
    let salt = crypto.randomBytes(PBKDF2_SALT_SIZE);

    // Derive a key using PBKDF2.
    let key = crypto.pbkdf2Sync(Buffer.from(password, "utf8"), salt, PBKDF2_ITERATIONS, ALGORITHM_KEY_SIZE, PBKDF2_NAME);

    // Encrypt and prepend salt.
    let ciphertextAndNonceAndSalt = Buffer.concat([ salt, encrypt(Buffer.from(plaintext, "utf8"), key) ]);

    // Return as base64 string.
    return ciphertextAndNonceAndSalt.toString("base64");
}

function decryptString(base64CiphertextAndNonceAndSalt, password) {
    // Decode the base64.
    let ciphertextAndNonceAndSalt = Buffer.from(base64CiphertextAndNonceAndSalt, "base64");

    // Create buffers of salt and ciphertextAndNonce.
    let salt = ciphertextAndNonceAndSalt.slice(0, PBKDF2_SALT_SIZE);
    let ciphertextAndNonce = ciphertextAndNonceAndSalt.slice(PBKDF2_SALT_SIZE);

    // Derive the key using PBKDF2.
    let key = crypto.pbkdf2Sync(Buffer.from(password, "utf8"), salt, PBKDF2_ITERATIONS, ALGORITHM_KEY_SIZE, PBKDF2_NAME);

    // Decrypt and return result.
    return decrypt(ciphertextAndNonce, key).toString("utf8");
}

function encrypt(plaintext, key) {
    // Generate a 96-bit nonce using a CSPRNG.
    let nonce = crypto.randomBytes(ALGORITHM_NONCE_SIZE);

    // Create the cipher instance.
    let cipher = crypto.createCipheriv(ALGORITHM_NAME, key, nonce);

    // Encrypt and prepend nonce.
    let ciphertext = Buffer.concat([ cipher.update(plaintext), cipher.final() ]);

    return Buffer.concat([ nonce, ciphertext, cipher.getAuthTag() ]);
}

function decrypt(ciphertextAndNonce, key) {
    // Create buffers of nonce, ciphertext and tag.
    let nonce = ciphertextAndNonce.slice(0, ALGORITHM_NONCE_SIZE);
    let ciphertext = ciphertextAndNonce.slice(ALGORITHM_NONCE_SIZE, ciphertextAndNonce.length - ALGORITHM_TAG_SIZE);
    let tag = ciphertextAndNonce.slice(ciphertext.length + ALGORITHM_NONCE_SIZE);

    // Create the cipher instance.
    let cipher = crypto.createDecipheriv(ALGORITHM_NAME, key, nonce);

    // Decrypt and return result.
    cipher.setAuthTag(tag);
    return Buffer.concat([ cipher.update(ciphertext), cipher.final() ]);
}
