<?php

define("ALGORITHM_NAME", "aes-128-gcm");
define("ALGORITHM_NONCE_SIZE", 12);
define("ALGORITHM_TAG_SIZE", 16);
define("ALGORITHM_KEY_SIZE", 16);
define("PBKDF2_NAME", "sha256");
define("PBKDF2_SALT_SIZE", 16);
define("PBKDF2_ITERATIONS", 32767);

function encryptString($plaintext, $password) {
    // Generate a 128-bit salt using a CSPRNG.
    $salt = random_bytes(PBKDF2_SALT_SIZE);

    // Derive a key.
    $key = hash_pbkdf2(PBKDF2_NAME, $password, $salt, PBKDF2_ITERATIONS, ALGORITHM_KEY_SIZE, true);

    // Encrypt and prepend salt and return as base64 string.
    return base64_encode($salt . encrypt($plaintext, $key));
}

function decryptString($base64CiphertextAndNonceAndSalt, $password) {
    // Decode the base64.
    $ciphertextAndNonceAndSalt = base64_decode($base64CiphertextAndNonceAndSalt);

    // Retrieve the salt and ciphertextAndNonce.
    $salt = substr($ciphertextAndNonceAndSalt, 0, PBKDF2_SALT_SIZE);
    $ciphertextAndNonce = substr($ciphertextAndNonceAndSalt, PBKDF2_SALT_SIZE);

    // Derive the key.
    $key = hash_pbkdf2(PBKDF2_NAME, $password, $salt, PBKDF2_ITERATIONS, ALGORITHM_KEY_SIZE, true);

    // Decrypt and return result.
    return decrypt($ciphertextAndNonce, $key);
}

function encrypt($plaintext, $key) {
    // Generate a 96-bit nonce using a CSPRNG.
    $nonce = random_bytes(ALGORITHM_NONCE_SIZE);

    // Encrypt and prepend nonce.
    $ciphertext = openssl_encrypt($plaintext, ALGORITHM_NAME, $key, OPENSSL_RAW_DATA, $nonce, $tag);

    return $nonce . $ciphertext . $tag;
}

function decrypt($ciphertextAndNonce, $key) {
    // Retrieve the nonce and ciphertext.
    $nonce = substr($ciphertextAndNonce, 0, ALGORITHM_NONCE_SIZE);
    $ciphertext = substr($ciphertextAndNonce, ALGORITHM_NONCE_SIZE, strlen($ciphertextAndNonce) - ALGORITHM_NONCE_SIZE - ALGORITHM_TAG_SIZE);
    $tag = substr($ciphertextAndNonce, strlen($ciphertextAndNonce) - ALGORITHM_TAG_SIZE);

    // Decrypt and return result.
    return openssl_decrypt($ciphertext, ALGORITHM_NAME, $key, OPENSSL_RAW_DATA, $nonce, $tag);
}

?>
