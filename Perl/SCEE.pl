use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use Crypt::PRNG qw(random_bytes);
use Crypt::KeyDerivation qw(pbkdf2);
use MIME::Base64 qw(encode_base64 decode_base64);


use constant ALGORITHM_NONCE_SIZE => 12;
use constant ALGORITHM_TAG_SIZE   => 16;
use constant ALGORITHM_KEY_SIZE   => 16;
use constant PBKDF2_SALT_SIZE     => 16;
use constant PBKDF2_ITERATIONS    => 32767;
use constant PBKDF2_NAME          => "SHA256";


sub encrypt_string {
    my ($plaintext, $password) = @_;

    # Generate a 128-bit salt using a CSPRNG.
    my $salt = random_bytes(PBKDF2_SALT_SIZE);

    # Derive a key.
    my $key = pbkdf2($password, $salt, PBKDF2_ITERATIONS, PBKDF2_NAME, ALGORITHM_KEY_SIZE);

    # Encrypt and prepend salt and return as base64 string.
    return encode_base64($salt . encrypt($plaintext, $key), '');
}

sub decrypt_string {
    my ($base64CiphertextAndNonceAndSalt, $password) = @_;

    # Decode the base64.
    my $ciphertextAndNonceAndSalt = decode_base64($base64CiphertextAndNonceAndSalt);

    # Retrieve the salt and ciphertextAndNonce.
    my ($salt, $ciphertextAndNonce) = unpack("a" . PBKDF2_SALT_SIZE . "a*", $ciphertextAndNonceAndSalt);

    # Derive the key.
    my $key = pbkdf2($password, $salt, PBKDF2_ITERATIONS, PBKDF2_NAME, ALGORITHM_KEY_SIZE);

    # Decrypt and return result.
    return decrypt($ciphertextAndNonce, $key);
}

sub encrypt {
    my ($plaintext, $key) = @_;

    # Generate a 96-bit nonce using a CSPRNG.
    my $nonce = random_bytes(ALGORITHM_NONCE_SIZE);

    # Encrypt and prepend nonce.
    my ($ciphertext, $tag) = gcm_encrypt_authenticate('AES', $key, $nonce, '', $plaintext);
    die "Invalid tag size" unless length $tag == ALGORITHM_TAG_SIZE;
    my $ciphertextAndNonce = $nonce . $ciphertext . $tag;

    return $ciphertextAndNonce;
}

sub decrypt {
    my ($ciphertextAndNonce, $key) = @_;

    # Retrieve the nonce and ciphertext.
    my ($nonce, $ciphertext, $tag) = unpack("a" . ALGORITHM_NONCE_SIZE . 
                                            "a" . (length($ciphertextAndNonce) - ALGORITHM_NONCE_SIZE - ALGORITHM_TAG_SIZE) .
                                            "a" . ALGORITHM_TAG_SIZE, $ciphertextAndNonce);

    # Decrypt and return result.
    my $plaintext = gcm_decrypt_verify('AES', $key, $nonce, '', $ciphertext, $tag);

    return $plaintext;
}


1;
