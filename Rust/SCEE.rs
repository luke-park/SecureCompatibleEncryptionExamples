use ring::aead;
use ring::rand::*;
use ring::digest;
use ring::pbkdf2;
use base64::encode;
use base64::decode;
use std::str::from_utf8;

static ALGORITHM_NAME: &'static aead::Algorithm = &aead::AES_128_GCM;
const ALGORITHM_NONCE_SIZE: usize = 12;
const ALGORITHM_TAG_SIZE: usize = 16;
const ALGORITHM_KEY_SIZE: usize = 16;
static PBKDF2_NAME: &'static digest::Algorithm = &digest::SHA256;
const PBKDF2_SALT_SIZE: usize = 16;
const PBKDF2_ITERATIONS: u32 = 32767;

pub fn encrypt_string(plaintext: &String, password: &String) -> Option<String> {
    // Generate a 128-bit salt using a CSPRNG.
    let rand_provider: SystemRandom = SystemRandom::new();
    let mut salt: [u8; PBKDF2_SALT_SIZE] = [0; PBKDF2_SALT_SIZE];
    let err = rand_provider.fill(&mut salt);
    if err.is_err() {
        return None;
    }

    // Derive a key using PBKDF2.
    let mut key: [u8; ALGORITHM_KEY_SIZE] = [0; ALGORITHM_KEY_SIZE];
    pbkdf2::derive(PBKDF2_NAME, PBKDF2_ITERATIONS, &salt, password.as_bytes(), &mut key);

    // Encrypt and prepend salt.
    let mut ciphertext_and_nonce: Vec<u8> = vec![0; plaintext.len() + ALGORITHM_NONCE_SIZE + ALGORITHM_TAG_SIZE];
    let size = match encrypt(plaintext.as_bytes(), &key, ciphertext_and_nonce.as_mut_slice()) {
        Some(size) => size,
        None => return None
    };

    let mut ciphertext_and_nonce_and_salt: Vec<u8> = vec![0; ciphertext_and_nonce.len() + salt.len()];
    ciphertext_and_nonce_and_salt[..PBKDF2_SALT_SIZE].copy_from_slice(&salt);
    ciphertext_and_nonce_and_salt[PBKDF2_SALT_SIZE..].copy_from_slice(&ciphertext_and_nonce[..size]);

    // Return as base64 string.
    return Some(encode(&ciphertext_and_nonce_and_salt[..]));
}

pub fn decrypt_string(base64_ciphertext_and_nonce_and_salt: &String, password: &String) -> Option<String> {
    // Decode the base64.
    let ciphertext_and_nonce_and_salt: Vec<u8> = match decode(base64_ciphertext_and_nonce_and_salt.as_bytes()) {
        Ok(r) => r,
        Err(_) => return None
    };

    // Get slices of salt and ciphertext_and_nonce.
    let salt: &[u8] = &ciphertext_and_nonce_and_salt[..PBKDF2_SALT_SIZE];
    let ciphertext_and_nonce: &[u8] = &ciphertext_and_nonce_and_salt[PBKDF2_SALT_SIZE..];

    // Derive the key using PBKDF2.
    let mut key: [u8; ALGORITHM_KEY_SIZE] = [0; ALGORITHM_KEY_SIZE];
    pbkdf2::derive(PBKDF2_NAME, PBKDF2_ITERATIONS, &salt, password.as_bytes(), &mut key);

    // Decrypt and return result.
    let mut plaintext: Vec<u8> = vec![0; ciphertext_and_nonce.len() - ALGORITHM_NONCE_SIZE];
    let size = match decrypt(ciphertext_and_nonce, &key, &mut plaintext) {
        Some(size) => size,
        None => return None
    };

    let result = match from_utf8(&plaintext[..size]) {
        Ok(r) => String::from(r),
        Err(_) => return None
    };
    
    return Some(result);
}

pub fn encrypt(plaintext: &[u8], key: &[u8], ciphertext_and_nonce: &mut [u8]) -> Option<usize> {
    // Panic if ciphertext_and_nonce is not large enough.
    let minimum_size: usize = plaintext.len() + ALGORITHM_NONCE_SIZE + ALGORITHM_TAG_SIZE;
    if ciphertext_and_nonce.len() < minimum_size {
        panic!("Expected ciphertext_and_nonce to be at least {} bytes in size, but was {}", minimum_size, ciphertext_and_nonce.len());
    }

    // Generate a 96-bit nonce using a CSPRNG.
    let rand_provider: SystemRandom = SystemRandom::new();
    let mut nonce: [u8; ALGORITHM_NONCE_SIZE] = [0; ALGORITHM_NONCE_SIZE];
    let err = rand_provider.fill(&mut nonce);
    if err.is_err() {
        return None;
    }

    // Create a sealing key from key.
    let sealing_key = match aead::SealingKey::new(ALGORITHM_NAME, key) {
        Ok(k) => k,
        Err(_) => return None
    };

    // We don't have any additional data.
    let ad: [u8; 0] = [ ];

    // Copy plaintext to ciphertext_and_nonce to use as in_out.
    ciphertext_and_nonce[ALGORITHM_NONCE_SIZE..plaintext.len() + ALGORITHM_NONCE_SIZE].copy_from_slice(plaintext);

    // Perform encryption.
    let result = aead::seal_in_place(&sealing_key, &nonce, &ad, &mut ciphertext_and_nonce[ALGORITHM_NONCE_SIZE..], ALGORITHM_TAG_SIZE);
    if result.is_err() {
        return None;
    }

    // Prepend nonce.
    ciphertext_and_nonce[..ALGORITHM_NONCE_SIZE].copy_from_slice(&nonce);

    return Some(plaintext.len() + ALGORITHM_NONCE_SIZE + ALGORITHM_TAG_SIZE);
}

pub fn decrypt(ciphertext_and_nonce: &[u8], key: &[u8], plaintext: &mut [u8]) -> Option<usize> {
    // Panic if plaintext is not large enough.
    let minimum_size: usize = ciphertext_and_nonce.len() - ALGORITHM_NONCE_SIZE;
    if plaintext.len() < minimum_size {
        panic!("Expected plaintext to be at least {} bytes in size, but was {}", minimum_size, plaintext.len());
    }

    // Retrieve the nonce.
    let mut nonce: [u8; ALGORITHM_NONCE_SIZE] = [0; ALGORITHM_NONCE_SIZE];
    nonce[..].copy_from_slice(&ciphertext_and_nonce[..ALGORITHM_NONCE_SIZE]);

    // Put the ciphertext into plaintext to use as in_out.
    let ciphertext_with_tag = &ciphertext_and_nonce[ALGORITHM_NONCE_SIZE..];
    let ciphertext_with_tag_len = ciphertext_with_tag.len();
    plaintext.copy_from_slice(ciphertext_with_tag);

    // We don't have any additional data.
    let ad: [u8; 0] = [ ];

    // Create a opening key from key.
    let opening_key = match aead::OpeningKey::new(ALGORITHM_NAME, key) {
        Ok(k) => k,
        Err(_) => return None
    };

    // Perform decryption.
    let result = aead::open_in_place(&opening_key, &nonce, &ad, 0, plaintext);
    if result.is_err() {
        return None;
    }

    return Some(ciphertext_with_tag_len - ALGORITHM_TAG_SIZE);
}
