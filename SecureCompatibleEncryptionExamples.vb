Imports Org.BouncyCastle.Crypto.Digests
Imports Org.BouncyCastle.Crypto.Engines
Imports Org.BouncyCastle.Crypto.Generators
Imports Org.BouncyCastle.Crypto.Modes
Imports Org.BouncyCastle.Crypto.Parameters
Imports Org.BouncyCastle.Security
Imports System.Text

Namespace scee

    Friend Class SecureCompatibleEncryptionExamples

        Private Const ALGORITHM_NAME As String = "AES"
        Private Const ALGORITHM_NONCE_SIZE As Integer = 12
        Private Const ALGORITHM_KEY_SIZE As Integer = 16
        Private Const PBKDF2_SALT_SIZE As Integer = 16
        Private Const PBKDF2_ITERATIONS As Integer = 32767

        Public Shared Function EncryptString(ByVal plaintext As String, ByVal password As String) As String
            ' Generate a 128-bit salt using a CSPRNG.
            Dim rand As SecureRandom = New SecureRandom()
            Dim salt As Byte() = New Byte(PBKDF2_SALT_SIZE - 1) {}
            rand.NextBytes(salt)

            ' Create an instance of PBKDF2 and derive a key.
            Dim pbkdf2 As Pkcs5S2ParametersGenerator = New Pkcs5S2ParametersGenerator(New Sha256Digest())
            pbkdf2.Init(Encoding.UTF8.GetBytes(password), salt, PBKDF2_ITERATIONS)
            Dim key As Byte() = (CType(pbkdf2.GenerateDerivedMacParameters(ALGORITHM_KEY_SIZE * 8), KeyParameter)).GetKey()

            ' Encrypt and prepend salt.
            Dim ciphertextAndNonce As Byte() = Encrypt(Encoding.UTF8.GetBytes(plaintext), key)
            Dim ciphertextAndNonceAndSalt As Byte() = New Byte(salt.Length + ciphertextAndNonce.Length - 1) {}
            Array.Copy(salt, 0, ciphertextAndNonceAndSalt, 0, salt.Length)
            Array.Copy(ciphertextAndNonce, 0, ciphertextAndNonceAndSalt, salt.Length, ciphertextAndNonce.Length)

            ' Return as base64 string.
            Return Convert.ToBase64String(ciphertextAndNonceAndSalt)
        End Function

        Public Shared Function DecryptString(ByVal base64CiphertextAndNonceAndSalt As String, ByVal password As String) As String
            ' Decode the base64.
            Dim ciphertextAndNonceAndSalt As Byte() = Convert.FromBase64String(base64CiphertextAndNonceAndSalt)

            ' Retrieve the salt and ciphertextAndNonce.
            Dim salt As Byte() = New Byte(PBKDF2_SALT_SIZE - 1) {}
            Dim ciphertextAndNonce As Byte() = New Byte(ciphertextAndNonceAndSalt.Length - PBKDF2_SALT_SIZE - 1) {}
            Array.Copy(ciphertextAndNonceAndSalt, 0, salt, 0, salt.Length)
            Array.Copy(ciphertextAndNonceAndSalt, salt.Length, ciphertextAndNonce, 0, ciphertextAndNonce.Length)

            ' Create an instance of PBKDF2 and derive the key.
            Dim pbkdf2 As Pkcs5S2ParametersGenerator = New Pkcs5S2ParametersGenerator(New Sha256Digest())
            pbkdf2.Init(Encoding.UTF8.GetBytes(password), salt, PBKDF2_ITERATIONS)
            Dim key As Byte() = (CType(pbkdf2.GenerateDerivedMacParameters(ALGORITHM_KEY_SIZE * 8), KeyParameter)).GetKey()

            ' Decrypt and return result.
            Return Encoding.UTF8.GetString(Decrypt(ciphertextAndNonce, key))
        End Function

        Public Shared Function Encrypt(ByVal plaintext As Byte(), ByVal key As Byte()) As Byte()
            ' Generate a 96-bit nonce using a CSPRNG.
            Dim rand As SecureRandom = New SecureRandom()
            Dim nonce As Byte() = New Byte(ALGORITHM_NONCE_SIZE - 1) {}
            rand.NextBytes(nonce)

            ' Create the cipher instance and initialize.
            Dim cipher As GcmBlockCipher = New GcmBlockCipher(New AesFastEngine())
            Dim keyParam As KeyParameter = ParameterUtilities.CreateKeyParameter(ALGORITHM_NAME, key)
            Dim cipherParameters As ParametersWithIV = New ParametersWithIV(keyParam, nonce)
            cipher.Init(True, cipherParameters)

            ' Encrypt and prepend nonce.
            Dim ciphertext As Byte() = New Byte(cipher.GetOutputSize(plaintext.Length) - 1) {}
            Dim length As Integer = cipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0)
            cipher.DoFinal(ciphertext, length)

            Dim ciphertextAndNonce As Byte() = New Byte(nonce.Length + ciphertext.Length - 1) {}
            Array.Copy(nonce, 0, ciphertextAndNonce, 0, nonce.Length)
            Array.Copy(ciphertext, 0, ciphertextAndNonce, nonce.Length, ciphertext.Length)

            Return ciphertextAndNonce
        End Function

        Public Shared Function Decrypt(ByVal ciphertextAndNonce As Byte(), ByVal key As Byte()) As Byte()
            ' Retrieve the nonce and ciphertext.
            Dim nonce As Byte() = New Byte(ALGORITHM_NONCE_SIZE - 1) {}
            Dim ciphertext As Byte() = New Byte(ciphertextAndNonce.Length - ALGORITHM_NONCE_SIZE - 1) {}
            Array.Copy(ciphertextAndNonce, 0, nonce, 0, nonce.Length)
            Array.Copy(ciphertextAndNonce, nonce.Length, ciphertext, 0, ciphertext.Length)

            ' Create the cipher instance and initialize.
            Dim cipher As GcmBlockCipher = New GcmBlockCipher(New AesFastEngine())
            Dim keyParam As KeyParameter = ParameterUtilities.CreateKeyParameter(ALGORITHM_NAME, key)
            Dim cipherParameters As ParametersWithIV = New ParametersWithIV(keyParam, nonce)
            cipher.Init(False, cipherParameters)

            ' Decrypt and return result.
            Dim plaintext As Byte() = New Byte(cipher.GetOutputSize(ciphertext.Length) - 1) {}
            Dim length As Integer = cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, plaintext, 0)
            cipher.DoFinal(plaintext, length)

            Return plaintext
        End Function
    End Class
End Namespace
