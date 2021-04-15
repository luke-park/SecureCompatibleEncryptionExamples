import sjcl from 'sjcl';

export default class EncryptorDecryptor {
    private BITS_PER_WORD: number = 32;
    private ALGORITHM_NONCE_SIZE: number = 3; // 32-bit words.
    private ALGORITHM_KEY_SIZE: number = 4; // 32-bit words.
    private PBKDF2_SALT_SIZE: number = 4; // 32-bit words.
    private PBKDF2_ITERATIONS: number = 32767;

    encryptString = (plaintext: string, password: string): string => {
        // Generate a 128-bit salt using a CSPRNG.
        const salt = sjcl.random.randomWords(this.PBKDF2_SALT_SIZE);

        // Derive a key using PBKDF2.
        const key = sjcl.misc.pbkdf2(
            password, salt,
            this.PBKDF2_ITERATIONS,
            this.ALGORITHM_KEY_SIZE * this.BITS_PER_WORD);

        // Encrypt and prepend salt.
        const plaintextRaw = sjcl.codec.utf8String.toBits(plaintext);
        const ciphertextAndNonceAndSalt = sjcl.bitArray.concat(salt, this.encrypt(plaintextRaw, key));

        return sjcl.codec.base64.fromBits(ciphertextAndNonceAndSalt);
    }

    decryptString = (base64CiphertextAndNonceAndSalt: string, password: string): string => {
        // Decode the base64.
        const ciphertextAndNonceAndSalt = sjcl.codec.base64.toBits(base64CiphertextAndNonceAndSalt);

        // Create buffers of salt and ciphertextAndNonce.
        const salt = sjcl.bitArray.bitSlice(
            ciphertextAndNonceAndSalt,
            0,
            this.PBKDF2_SALT_SIZE * this.BITS_PER_WORD);

        const ciphertextAndNonce = sjcl.bitArray.bitSlice(
            ciphertextAndNonceAndSalt,
            this.PBKDF2_SALT_SIZE * this.BITS_PER_WORD,
            ciphertextAndNonceAndSalt.length * this.BITS_PER_WORD);

        // Derive the key using PBKDF2.
        const key = sjcl.misc.pbkdf2(password, salt,
            this.PBKDF2_ITERATIONS,
            this.ALGORITHM_KEY_SIZE * this.BITS_PER_WORD);

        // Decrypt and return result.
        return sjcl.codec.utf8String.fromBits(this.decrypt(ciphertextAndNonce, key));
    }

    private encrypt = (plaintext: sjcl.BitArray, key: number[]): sjcl.BitArray => {
        // Generate a 96-bit nonce using a CSPRNG.
        const nonce = sjcl.random.randomWords(this.ALGORITHM_NONCE_SIZE);

        // Encrypt and prepend nonce.
        const ciphertext = sjcl.mode.gcm.encrypt(new sjcl.cipher.aes(key), plaintext, nonce);

        return sjcl.bitArray.concat(nonce, ciphertext);
    }

    private decrypt = (ciphertextAndNonce: sjcl.BitArray, key: number[]): sjcl.BitArray => {
        // Create buffers of nonce and ciphertext.
        const nonce = sjcl.bitArray.bitSlice(
            ciphertextAndNonce,
            0,
            this.ALGORITHM_NONCE_SIZE * this.BITS_PER_WORD);

        const ciphertext = sjcl.bitArray.bitSlice(
            ciphertextAndNonce,
            this.ALGORITHM_NONCE_SIZE * this.BITS_PER_WORD,
            ciphertextAndNonce.length * this.BITS_PER_WORD);

        // Decrypt and return result.
        return sjcl.mode.gcm.decrypt(new sjcl.cipher.aes(key), ciphertext, nonce);
    }
}
