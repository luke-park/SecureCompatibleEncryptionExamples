from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64

ALGORITHM_NONCE_SIZE = 12
ALGORITHM_TAG_SIZE = 16
ALGORITHM_KEY_SIZE = 16
PBKDF2_SALT_SIZE = 16
PBKDF2_ITERATIONS = 32767
PBKDF2_LAMBDA = lambda x, y: HMAC.new(x, y, SHA256).digest()

def encryptString(plaintext, password):
    # Generate a 128-bit salt using a CSPRNG.
    salt = get_random_bytes(PBKDF2_SALT_SIZE)

    # Derive a key using PBKDF2.
    key = PBKDF2(password, salt, ALGORITHM_KEY_SIZE, PBKDF2_ITERATIONS, PBKDF2_LAMBDA)

    # Encrypt and prepend salt.
    ciphertextAndNonce = encrypt(plaintext.encode('utf-8'), key)
    ciphertextAndNonceAndSalt = salt + ciphertextAndNonce

    # Return as base64 string.
    return base64.b64encode(ciphertextAndNonceAndSalt)

def decryptString(base64CiphertextAndNonceAndSalt, password):
    # Decode the base64.
    ciphertextAndNonceAndSalt = base64.b64decode(base64CiphertextAndNonceAndSalt)

    # Get the salt and ciphertextAndNonce.
    salt = ciphertextAndNonceAndSalt[:PBKDF2_SALT_SIZE]
    ciphertextAndNonce = ciphertextAndNonceAndSalt[PBKDF2_SALT_SIZE:]

    # Derive the key using PBKDF2.
    key = PBKDF2(password, salt, ALGORITHM_KEY_SIZE, PBKDF2_ITERATIONS, PBKDF2_LAMBDA)

    # Decrypt and return result.
    plaintext = decrypt(ciphertextAndNonce, key)

    return plaintext.decode('utf-8')

def encrypt(plaintext, key):
    # Generate a 96-bit nonce using a CSPRNG.
    nonce = get_random_bytes(ALGORITHM_NONCE_SIZE)

    # Create the cipher.
    cipher = AES.new(key, AES.MODE_GCM, nonce)

    # Encrypt and prepend nonce.
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    ciphertextAndNonce = nonce + ciphertext + tag

    return ciphertextAndNonce

def decrypt(ciphertextAndNonce, key):
    # Get the nonce, ciphertext and tag.
    nonce = ciphertextAndNonce[:ALGORITHM_NONCE_SIZE]
    ciphertext = ciphertextAndNonce[ALGORITHM_NONCE_SIZE:len(ciphertextAndNonce) - ALGORITHM_TAG_SIZE]
    tag = ciphertextAndNonce[len(ciphertextAndNonce) - ALGORITHM_TAG_SIZE:]

    # Create the cipher.
    cipher = AES.new(key, AES.MODE_GCM, nonce)

    # Decrypt and return result.
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext
