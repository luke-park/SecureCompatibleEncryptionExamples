const ALGORITHM_NAME = "AES-GCM";
const ALGORITHM_NONCE_SIZE = 12;
const ALGORITHM_KEY_SIZE = 16 * 8;
const PBKDF2_SALT_SIZE = 16;
const PBKDF2_ITERATIONS = 32767;

async function encryptString(plaintext, password) {
	// Generate a 128-bit salt using a CSPRNG and a nonce.
	let salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_SIZE));
	let nonce = crypto.getRandomValues(new Uint8Array(ALGORITHM_NONCE_SIZE));
	let aesGcm = { name: ALGORITHM_NAME, iv: nonce };

	// Derive a key using PBKDF2.
	let deriveParams = { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: { name: "SHA-256" } };
	let rawKey = await crypto.subtle.importKey("raw", (new TextEncoder()).encode(password), { name: "PBKDF2" }, false, ["deriveKey", "deriveBits"]);
	let cryptoKey = await crypto.subtle.deriveKey(deriveParams, rawKey, { name: ALGORITHM_NAME, length: ALGORITHM_KEY_SIZE }, true, ["encrypt"]);

	// Encrypt the string.
	let ciphertext = await encryptWithCryptoKey(aesGcm, (new TextEncoder()).encode(plaintext), cryptoKey);
	return base64js.fromByteArray(joinBuffers(salt, ciphertext));
}

async function decryptString(base64CiphertextAndNonceAndSalt, password) {
	// Decode the base64.
	let ciphertextAndNonceAndSalt = base64js.toByteArray(base64CiphertextAndNonceAndSalt);

	// Create buffers of salt and ciphertextAndNonce.
	let salt = ciphertextAndNonceAndSalt.slice(0, PBKDF2_SALT_SIZE);
	let nonce = ciphertextAndNonceAndSalt.slice(PBKDF2_SALT_SIZE, PBKDF2_SALT_SIZE + ALGORITHM_NONCE_SIZE);
	let ciphertext = ciphertextAndNonceAndSalt.slice(PBKDF2_SALT_SIZE + ALGORITHM_NONCE_SIZE);
	let aesGcm = { name: ALGORITHM_NAME, iv: nonce };

	// Derive the key using PBKDF2.
	let deriveParams = { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: { name: "SHA-256" } };
	let rawKey = await crypto.subtle.importKey("raw", (new TextEncoder()).encode(password), { name: "PBKDF2" }, false, ["deriveKey", "deriveBits"]);
	let cryptoKey = await crypto.subtle.deriveKey(deriveParams, rawKey, { name: ALGORITHM_NAME, length: ALGORITHM_KEY_SIZE }, true, ["decrypt"]);

	// Decrypt the string.
	let plaintext = await decryptWithCryptoKey(aesGcm, ciphertext, cryptoKey);
	return (new TextDecoder()).decode(plaintext);
}

async function encrypt(plaintext, key) {
	// Generate a 96-bit nonce using a CSPRNG.
	let nonce = crypto.getRandomValues(new Uint8Array(ALGORITHM_NONCE_SIZE));
	let aesGcm = { name: ALGORITHM_NAME, iv: nonce };

	// Create a 'CryptoKey'.
	let cryptoKey = await crypto.subtle.importKey("raw", key, aesGcm, false, ["encrypt"]);

	// Encrypt.
	return await encryptWithCryptoKey(aesGcm, plaintext, cryptoKey);
}
async function encryptWithCryptoKey(aesGcm, plaintext, cryptoKey) {
	let ciphertext = await crypto.subtle.encrypt(aesGcm, cryptoKey, plaintext);
	return joinBuffers(aesGcm.iv, new Uint8Array(ciphertext));
}

async function decrypt(ciphertextAndNonce, key) {
	// Create buffers of the nonce and ciphertext.
	let nonce = ciphertextAndNonce.slice(0, ALGORITHM_NONCE_SIZE);
	let ciphertext = ciphertextAndNonce.slice(ALGORITHM_NONCE_SIZE);

	let aesGcm = { name: ALGORITHM_NAME, iv: nonce };

	// Create the 'CryptoKey'.
	let cryptoKey = await crypto.subtle.importKey("raw", key, aesGcm, false, ["decrypt"]);

	// Decrypt.
	return await decryptWithCryptoKey(aesGcm, ciphertext, cryptoKey)
}
async function decryptWithCryptoKey(aesGcm, ciphertext, cryptoKey) {
	let plaintext = await crypto.subtle.decrypt(aesGcm, cryptoKey, ciphertext);
	return new Uint8Array(plaintext);
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
