package scee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
    "crypto/sha256"
    "encoding/base64"

	"golang.org/x/crypto/pbkdf2"
)

const AlgorithmNonceSize int = 12
const AlgorithmKeySize int = 16
const PBKDF2SaltSize int = 16
const PBKDF2Iterations int = 32767

func EncryptString(plaintext, password string) (string, error) {
    // Generate a 128-bit salt using a CSPRNG.
    salt := make([]byte, PBKDF2SaltSize)
    _, err := rand.Read(salt)
    if err != nil { return "", err }

    // Derive a key using PBKDF2.
    key := pbkdf2.Key([]byte(password), salt, PBKDF2Iterations, AlgorithmKeySize, sha256.New)

    // Encrypt and prepend salt.
    ciphertextAndNonce, err := Encrypt([]byte(plaintext), key)
    if err != nil { return "", err }

    ciphertextAndNonceAndSalt := make([]byte, 0)
    ciphertextAndNonceAndSalt = append(ciphertextAndNonceAndSalt, salt...)
    ciphertextAndNonceAndSalt = append(ciphertextAndNonceAndSalt, ciphertextAndNonce...)

    // Return as base64 string.
    return base64.StdEncoding.EncodeToString(ciphertextAndNonceAndSalt), nil
}

func DecryptString(base64CiphertextAndNonceAndSalt, password string) (string, error) {
    // Decode the base64.
    ciphertextAndNonceAndSalt, err := base64.StdEncoding.DecodeString(base64CiphertextAndNonceAndSalt)
    if err != nil { return "", err }

    // Create slices pointing to the salt and ciphertextAndNonce.
    salt := ciphertextAndNonceAndSalt[:PBKDF2SaltSize]
    ciphertextAndNonce := ciphertextAndNonceAndSalt[PBKDF2SaltSize:]

    // Derive the key using PBKDF2.
    key := pbkdf2.Key([]byte(password), salt, PBKDF2Iterations, AlgorithmKeySize, sha256.New)

    // Decrypt and return result.
    plaintext, err := Decrypt(ciphertextAndNonce, key)
    if err != nil { return "", err }

    return string(plaintext), nil
}

func Encrypt(plaintext, key []byte) ([]byte, error) {
	// Generate a 96-bit nonce using a CSPRNG.
	nonce := make([]byte, AlgorithmNonceSize)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	// Create the cipher and block.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Encrypt and prepend nonce.
	ciphertext := cipher.Seal(nil, nonce, plaintext, nil)
	ciphertextAndNonce := make([]byte, 0)

	ciphertextAndNonce = append(ciphertextAndNonce, nonce...)
	ciphertextAndNonce = append(ciphertextAndNonce, ciphertext...)

	return ciphertextAndNonce, nil
}

func Decrypt(ciphertextAndNonce, key []byte) ([]byte, error) {
	// Create slices pointing to the ciphertext and nonce.
	nonce := ciphertextAndNonce[:AlgorithmNonceSize]
	ciphertext := ciphertextAndNonce[AlgorithmNonceSize:]

	// Create the cipher and block.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt and return result.
	plaintext, err := cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
