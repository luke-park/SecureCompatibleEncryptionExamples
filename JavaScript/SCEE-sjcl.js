var BITS_PER_WORD = 32;
var ALGORITHM_NONCE_SIZE = 3; // 32-bit words.
var ALGORITHM_KEY_SIZE = 4; // 32-bit words.
var PBKDF2_SALT_SIZE = 4; // 32-bit words.
var PBKDF2_ITERATIONS = 32767;

function encryptString(plaintext, password) {
    // Generate a 128-bit salt using a CSPRNG.
    var salt = sjcl.random.randomWords(PBKDF2_SALT_SIZE);

    // Derive a key using PBKDF2.
    var key = sjcl.misc.pbkdf2(password, salt, PBKDF2_ITERATIONS, ALGORITHM_KEY_SIZE * BITS_PER_WORD);

    // Encrypt and prepend salt.
    var plaintextRaw = sjcl.codec.utf8String.toBits(plaintext);
    var ciphertextAndNonceAndSalt = sjcl.bitArray.concat(salt, encrypt(plaintextRaw, key));

    return sjcl.codec.base64.fromBits(ciphertextAndNonceAndSalt);
}

function decryptString(base64CiphertextAndNonceAndSalt, password) {
    // Decode the base64.
    var ciphertextAndNonceAndSalt = sjcl.codec.base64.toBits(base64CiphertextAndNonceAndSalt);

    // Create buffers of salt and ciphertextAndNonce.
    var salt = sjcl.bitArray.bitSlice(ciphertextAndNonceAndSalt, 0, PBKDF2_SALT_SIZE * BITS_PER_WORD);
    var ciphertextAndNonce = sjcl.bitArray.bitSlice(ciphertextAndNonceAndSalt, PBKDF2_SALT_SIZE * BITS_PER_WORD);

    // Derive the key using PBKDF2.
    var key = sjcl.misc.pbkdf2(password, salt, PBKDF2_ITERATIONS, ALGORITHM_KEY_SIZE * BITS_PER_WORD);
    
    // Decrypt and return result.
    return sjcl.codec.utf8String.fromBits(decrypt(ciphertextAndNonce, key));
}

function encrypt(plaintext, key) {
    // Generate a 96-bit nonce using a CSPRNG.
    var nonce = sjcl.random.randomWords(ALGORITHM_NONCE_SIZE);

    // Encrypt and prepend nonce.
    var ciphertext = sjcl.mode.gcm.encrypt(new sjcl.cipher.aes(key), plaintext, nonce);

    return sjcl.bitArray.concat(nonce, ciphertext);
}

function decrypt(ciphertextAndNonce, key) {
    // Create buffers of nonce and ciphertext.
    var nonce = sjcl.bitArray.bitSlice(ciphertextAndNonce, 0, ALGORITHM_NONCE_SIZE * BITS_PER_WORD);
    var ciphertext = sjcl.bitArray.bitSlice(ciphertextAndNonce, ALGORITHM_NONCE_SIZE * BITS_PER_WORD);

    // Decrypt and return result.
    return sjcl.mode.gcm.decrypt(new sjcl.cipher.aes(key), ciphertext, nonce);
}