import Foundation

public class SecureCompatibleEncryptionExamples {
    private static let algorithmNonceSize: Int = 12
    private static let algorithmKeySize: Int = 16
    private static let PBKDF2SaltSize: Int = 16
    private static let PBKDF2Iterations: UInt32 = 32767
    
    public static func encryptString(plaintext: String, password: String) throws -> String {
        // Generate a 128-bit salt using a CSPRNG.
        var saltBytes: [UInt8] = [UInt8](repeating: 0, count: PBKDF2SaltSize)
        if SecRandomCopyBytes(kSecRandomDefault, PBKDF2SaltSize, &saltBytes) != errSecSuccess {
            throw SCEEError.CSPRNGFailure
        }
        let salt: Data = Data(bytes: saltBytes)
        
        // Use PBKDF2 to derive a key.
        let passwordData: Data = password.data(using: String.Encoding.utf8)!
        var key: Data = Data(repeating: 0, count: algorithmKeySize)
        
        let status = key.withUnsafeMutableBytes { keyBytes in
            salt.withUnsafeBytes { saltBytes in
                passwordData.withUnsafeBytes { passwordBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes,
                        passwordData.count,
                        saltBytes,
                        PBKDF2SaltSize,
                        CCPBKDFAlgorithm(kCCPRFHmacAlgSHA256),
                        PBKDF2Iterations,
                        keyBytes,
                        algorithmKeySize)
                }
            }
        }
        
        if status != kCCSuccess { throw SCEEError.PBKDF2Failure }
        
        // Encrypt and prepend salt.
        let ciphertextAndNonce: Data = try encrypt(plaintext: plaintext.data(using: String.Encoding.utf8)!, key: key)
        var ciphertextAndNonceAndSalt: Data = Data()
        ciphertextAndNonceAndSalt.append(salt)
        ciphertextAndNonceAndSalt.append(ciphertextAndNonce)
        
        // Return as base64 string.
        return ciphertextAndNonceAndSalt.base64EncodedString()
    }
    
    public static func decryptString(ciphertext: String, password: String) throws -> String {
        // Decode the base64.
        let ciphertextAndNonceAndSalt: Data! = Data(base64Encoded: ciphertext)
        if ciphertextAndNonceAndSalt == nil { throw SCEEError.Base64Failure }
        
        // Retrieve the salt and ciphertextAndNonce.
        let salt: Data = ciphertextAndNonceAndSalt[0..<PBKDF2SaltSize]
        let ciphertextAndNonce: Data = ciphertextAndNonceAndSalt[PBKDF2SaltSize...]
        
        // Use PBKDF2 to derive a key.
        let passwordData: Data = password.data(using: String.Encoding.utf8)!
        var key: Data = Data(repeating: 0, count: algorithmKeySize)
        
        let status = key.withUnsafeMutableBytes { keyBytes in
            salt.withUnsafeBytes { saltBytes in
                passwordData.withUnsafeBytes { passwordBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes,
                        passwordData.count,
                        saltBytes,
                        PBKDF2SaltSize,
                        CCPBKDFAlgorithm(kCCPRFHmacAlgSHA256),
                        PBKDF2Iterations,
                        keyBytes,
                        algorithmKeySize)
                }
            }
        }
        
        if status != kCCSuccess { throw SCEEError.PBKDF2Failure }
        
        // Decrypt and return result.
        return String(data: try decrypt(ciphertextAndNonce: ciphertextAndNonce, key: key), encoding: String.Encoding.utf8)!
    }
    
    public static func encrypt(plaintext: Data, key: Data) throws -> Data {
        // Generate a 96-bit nonce using a CSPRNG.
        var nonceBytes: [UInt8] = [UInt8](repeating: 0, count: algorithmNonceSize)
        if SecRandomCopyBytes(kSecRandomDefault, algorithmNonceSize, &nonceBytes) != errSecSuccess {
            throw SCEEError.CSPRNGFailure
        }
        let nonce: Data = Data(bytes: nonceBytes)
        
        // Create the cipher instance and initialize.
        let gcm: SwiftGCM = try SwiftGCM(key: key, nonce: nonce, tagSize: 16)
        
        // Encrypt and prepend nonce.
        let ciphertext: Data = try gcm.encrypt(auth: nil, plaintext: plaintext)
        var ciphertextAndNonce: Data = Data()
        ciphertextAndNonce.append(nonce)
        ciphertextAndNonce.append(ciphertext)
        
        return ciphertextAndNonce
    }
    
    public static func decrypt(ciphertextAndNonce: Data, key: Data) throws -> Data {
        // Retrieve the nonce and ciphertext.
        let nonce: Data = ciphertextAndNonce[ciphertextAndNonce.startIndex..<ciphertextAndNonce.startIndex + algorithmNonceSize]
        
        let ciphertext: Data = ciphertextAndNonce[ciphertextAndNonce.startIndex + algorithmNonceSize..<ciphertextAndNonce.startIndex + ciphertextAndNonce.count]
        
        // Create the cipher instance and initialize.
        let gcm: SwiftGCM = try SwiftGCM(key: key, nonce: nonce, tagSize: 16)
        
        // Decrypt and return result.
        return try gcm.decrypt(auth: nil, ciphertext: ciphertext)
    }
}

public enum SCEEError: Error {
    case CSPRNGFailure
    case PBKDF2Failure
    case Base64Failure
}
