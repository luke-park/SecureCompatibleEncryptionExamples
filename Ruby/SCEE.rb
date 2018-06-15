require "OpenSSL"
require "Base64"

ALGORITHM_NAME = "aes-128-gcm"
ALGORITHM_NONCE_SIZE = 12
ALGORITHM_TAG_SIZE = 16
ALGORITHM_KEY_SIZE = 16
PBKDF2_ALGORITHM_NAME = "sha256"
PBKDF2_SALT_SIZE = 16
PBKDF2_ITERATIONS = 32767

def encrypt_string(plaintext, password)
    # Generate a 128-bit salt using a CSPRNG.
    salt = OpenSSL::Random.pseudo_bytes(PBKDF2_SALT_SIZE)

    # Derive a key using PBKDF2.
    key = OpenSSL::KDF.pbkdf2_hmac(password, salt: salt, iterations: PBKDF2_ITERATIONS, length: ALGORITHM_KEY_SIZE, hash: PBKDF2_ALGORITHM_NAME)

    # Encrypt and prepend salt.
    ciphertextAndNonce = encrypt(plaintext, key)
    ciphertextAndNonceAndSalt = salt + ciphertextAndNonce

    return Base64.encode64(ciphertextAndNonceAndSalt)
end

def decrypt_string(base64CiphertextAndNonceAndSalt, password)
    # Decode the base64.
    ciphertextAndNonceAndSalt = Base64.decode64(base64CiphertextAndNonceAndSalt)

    # Get the salt and ciphertextAndNonce.
    salt = ciphertextAndNonceAndSalt[0..PBKDF2_SALT_SIZE - 1]
    ciphertextAndNonce = ciphertextAndNonceAndSalt[PBKDF2_SALT_SIZE..ciphertextAndNonceAndSalt.bytesize - 1]

    # Derive a key using PBKDF2.
    key = OpenSSL::KDF.pbkdf2_hmac(password, salt: salt, iterations: PBKDF2_ITERATIONS, length: ALGORITHM_KEY_SIZE, hash: PBKDF2_ALGORITHM_NAME)

    # Decrypt and return result.
    return decrypt(ciphertextAndNonce, key)
end

def encrypt(data, key)
    # Generate a 96-bit nonce using a CSPRNG.
    nonce = OpenSSL::Random.pseudo_bytes(ALGORITHM_NONCE_SIZE)

    # Create the cipher.
    cipher = OpenSSL::Cipher.new(ALGORITHM_NAME)
    cipher.encrypt
    cipher.key = key
    cipher.iv = nonce

    # Encrypt and prepend nonce.
    ciphertext = cipher.update(data) + cipher.final
    tag = cipher.auth_tag(ALGORITHM_TAG_SIZE)
    ciphertextAndNonce = nonce + ciphertext + tag

    return ciphertextAndNonce
end

def decrypt(ciphertextAndNonce, key)
    # Get the nonce, ciphertext and tag.
    nonce = ciphertextAndNonce[0..ALGORITHM_NONCE_SIZE - 1]
    ciphertext = ciphertextAndNonce[ALGORITHM_NONCE_SIZE..ciphertextAndNonce.bytesize - ALGORITHM_TAG_SIZE - 1]
    tag = ciphertextAndNonce[ciphertextAndNonce.bytesize - ALGORITHM_TAG_SIZE..ciphertextAndNonce.bytesize - 1]

    # Create the cipher.
    cipher = OpenSSL::Cipher.new(ALGORITHM_NAME)
    cipher.decrypt
    cipher.key = key
    cipher.iv = nonce
    cipher.auth_tag = tag

    # Decrypt and return result.
    plaintext = cipher.update(ciphertext) + cipher.final

    return plaintext
end
