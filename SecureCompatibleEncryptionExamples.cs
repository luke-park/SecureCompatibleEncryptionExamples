using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Text;

namespace scee
{
    internal class SecureCompatibleEncryptionExamples
    {
        private const string ALGORITHM_NAME = "AES";
        private const int ALGORITHM_NONCE_SIZE = 12;
        private const int ALGORITHM_KEY_SIZE = 16;
        private const int PBKDF2_SALT_SIZE = 16;
        private const int PBKDF2_ITERATIONS = 32767;

        public static string EncryptString(string plaintext, string password)
        {
            // Generate a 128-bit salt using a CSPRNG.
            SecureRandom rand = new SecureRandom();
            byte[] salt = new byte[PBKDF2_SALT_SIZE];
            rand.NextBytes(salt);

            // Create an instance of PBKDF2 and derive a key.
            Pkcs5S2ParametersGenerator pbkdf2 = new Pkcs5S2ParametersGenerator(new Sha256Digest());
            pbkdf2.Init(Encoding.UTF8.GetBytes(password), salt, PBKDF2_ITERATIONS);
            byte[] key = ((KeyParameter)pbkdf2.GenerateDerivedMacParameters(ALGORITHM_KEY_SIZE * 8)).GetKey();

            // Encrypt and prepend salt.
            byte[] ciphertextAndNonce = Encrypt(Encoding.UTF8.GetBytes(plaintext), key);
            byte[] ciphertextAndNonceAndSalt = new byte[salt.Length + ciphertextAndNonce.Length];
            Array.Copy(salt, 0, ciphertextAndNonceAndSalt, 0, salt.Length);
            Array.Copy(ciphertextAndNonce, 0, ciphertextAndNonceAndSalt, salt.Length, ciphertextAndNonce.Length);

            // Return as base64 string.
            return Convert.ToBase64String(ciphertextAndNonceAndSalt);
        }

        public static string DecryptString(string base64CiphertextAndNonceAndSalt, string password)
        {
            // Decode the base64.
            byte[] ciphertextAndNonceAndSalt = Convert.FromBase64String(base64CiphertextAndNonceAndSalt);

            // Retrieve the salt and ciphertextAndNonce.
            byte[] salt = new byte[PBKDF2_SALT_SIZE];
            byte[] ciphertextAndNonce = new byte[ciphertextAndNonceAndSalt.Length - PBKDF2_SALT_SIZE];
            Array.Copy(ciphertextAndNonceAndSalt, 0, salt, 0, salt.Length);
            Array.Copy(ciphertextAndNonceAndSalt, salt.Length, ciphertextAndNonce, 0, ciphertextAndNonce.Length);

            // Create an instance of PBKDF2 and derive a key.
            Pkcs5S2ParametersGenerator pbkdf2 = new Pkcs5S2ParametersGenerator(new Sha256Digest());
            pbkdf2.Init(Encoding.UTF8.GetBytes(password), salt, PBKDF2_ITERATIONS);
            byte[] key = ((KeyParameter)pbkdf2.GenerateDerivedMacParameters(ALGORITHM_KEY_SIZE * 8)).GetKey();

            // Decrypt and return result.
            return Encoding.UTF8.GetString(Decrypt(ciphertextAndNonce, key));
        }

        public static byte[] Encrypt(byte[] plaintext, byte[] key)
        {
            // Generate a 96-bit nonce using a CSPRNG.
            SecureRandom rand = new SecureRandom();
            byte[] nonce = new byte[ALGORITHM_NONCE_SIZE];
            rand.NextBytes(nonce);

            // Create the cipher instance and initialize.
            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine());
            KeyParameter keyParam = ParameterUtilities.CreateKeyParameter(ALGORITHM_NAME, key);
            ParametersWithIV cipherParameters = new ParametersWithIV(keyParam, nonce);
            cipher.Init(true, cipherParameters);

            // Encrypt and prepend nonce.
            byte[] ciphertext = new byte[cipher.GetOutputSize(plaintext.Length)];
            int length = cipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
            cipher.DoFinal(ciphertext, length);

            byte[] ciphertextAndNonce = new byte[nonce.Length + ciphertext.Length];
            Array.Copy(nonce, 0, ciphertextAndNonce, 0, nonce.Length);
            Array.Copy(ciphertext, 0, ciphertextAndNonce, nonce.Length, ciphertext.Length);

            return ciphertextAndNonce;
        }

        public static byte[] Decrypt(byte[] ciphertextAndNonce, byte[] key)
        {
            // Retrieve the nonce and ciphertext.
            byte[] nonce = new byte[ALGORITHM_NONCE_SIZE];
            byte[] ciphertext = new byte[ciphertextAndNonce.Length - ALGORITHM_NONCE_SIZE];
            Array.Copy(ciphertextAndNonce, 0, nonce, 0, nonce.Length);
            Array.Copy(ciphertextAndNonce, nonce.Length, ciphertext, 0, ciphertext.Length);

            // Create the cipher instance and initialize.
            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine());
            KeyParameter keyParam = ParameterUtilities.CreateKeyParameter(ALGORITHM_NAME, key);
            ParametersWithIV cipherParameters = new ParametersWithIV(keyParam, nonce);
            cipher.Init(false, cipherParameters);

            // Decrypt and return result.
            byte[] plaintext = new byte[cipher.GetOutputSize(ciphertext.Length)];
            int length = cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, plaintext, 0);
            cipher.DoFinal(plaintext, length);

            return plaintext;
        }
    }
}
