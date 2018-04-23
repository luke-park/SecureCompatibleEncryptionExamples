![](icon.png)

# Secure Compatible Encryption Examples
This repository was created to address the ever-growing number of poor
encryption code examples that float about the internet.  This repository will
expand over time to include examples in more languages.

Reviewing of these examples is encouraged and any improvements are welcome, provided they contribute to the security of the
code.

## Algorithms
- **Encryption**: AES-128-GCM
- **Key Deriviation**: PBKDF2
- **PBKDF2 Underlying Hash**: SHA-256

AES with a 128-bit key was chosen due to the Java *Unlimited Strength Policy*
that requires key sizes of no more than 128-bits due to US law.  While the
examples are shown using AES-128, they can be trivially changed to 256-bit AES
by changing the `ALGORITHM_KEY_SIZE` (and in some cases, `ALGORITHM_NAME`) parameter.

## Compatibility
Every example shown here is compatible across platforms and/or languages.  The result of `encryptString` in any language can be decrypted by `decryptString` in any language.  Please do not submit pull requests for examples that are not compatible with the existing examples.

## Methods
Each example exposes 4 methods with signatures that are roughly equivalent to
the following:
- `string encryptString(plaintext: string, password: string)`
- `string decryptString(ciphertext: string, password: string)`
- `byte[] encrypt(plaintext: byte[], key: byte[])`
- `byte[] decrypt(ciphertext: byte[], key: byte[])`

As is expected, the `encrypt` and `decrypt` methods operate on and return raw
binary data.  The `*string` methods, however, take string parameters and return
strings.  The `password` parameter is fed through PBKDF2 first.  `password` can be of any length but `key` must be 128-bits in length.  You can change the AES key size by adjusting the `ALGORITHM_KEY_SIZE` parameter, and in some examples, the `ALGORITHM_NAME` parameter too.

**NOTE**: Because of the use of PBKDF2, the binary vs string methods are **not**
compatible.

## OpenSSL CLI Compatability
Note that while OpenSSL supports `AES-128-GCM` as an algorithm, the OpenSSL CLI tool does not properly implement `AES-128-GCM` and as such it cannot be used to produce or consume plaintexts/ciphertexts that are compatible with the examples in this repository.

## Test Vectors
The following strings are the results of `encryptString`.  If your implementation can `encryptString` and `decryptString` using the code you've written, and can also `decryptString` the test vectors below, then it is suitable for inclusion in this repository.  Recall that, due to a randomly generated salt and nonce, the following are not expected outputs for `encryptString`, they are for testing `decryptString` only.

| Plaintext | Password | Result |
|-----------|----------|--------|
|XCbJbjd72q|DTY62mV2Cv|`CqjxsXq6Y5ebtW6w98UQfgwdOpaCCkCy0l1qK5gJfhZnKVhp4+OuvxoiigHi8mO1R8CAyl5t`|
|SOJHSCm4qR|Pl4WODjq4k|`VtHh3Z6jqJpIDK0yLe4+/UNpxqBqcmaiJWmaecb7qfCyOlAcVJ973zBNM51VCup5UTuVlu3H`|
|NYzd53moLT|BZO8PUEysY|`SNQHdWnlcmJELLKewNTxBhzmJ1U+ChqKK5Kdvd/FSKssHW5b8y8SOrNVHdm78JUAYpGKlEUD`|
|vW1Qjb30mt|OziaxPFGYh|`5EmCwwSWj6YYgxBlld6DFW8I+QXCWxz5g/laEwUYV/DuoCGvxbW4ZlMd1Tsj4N07WbBOhIJU`|
|9z19eFctoZ|gkLDY5mmzT|`7miUNuhjJPAlbIHYKA2v/iBH3aplFF0pGw6HQAD5tKluh/1M69MLQ9xIkVcGfTr0CycsTFLU`|
|||`0iqwbC8/1YvTsl2dog6aXaGfXVypsv1BcbnDE06C7nl9REITn3NW18+ZUmc=`|

## Dependencies
|Language|Minimum Version|Dependencies|
|--------|---------------|------------|
|Java|Java 8 JRE||
|JavaScript (Node)|NodeJS 4.0.0+||
|JavaScript (Browser)|Requires WebCrypto support|Requires [base64-js](https://github.com/beatgammit/base64-js)|
|Go|Go 1.9|`golang.org/x/crypto/pbkdf2`|
|C#|.NET 4|Requires `BouncyCastle`, see [this NuGet package](https://www.nuget.org/packages/BouncyCastle/).|
|PHP|PHP 7.1||
|Swift|Swift 4.0|[SwiftGCM Library](https://github.com/luke-park/SwiftGCM) (single-file), also requires a bridge for CommonCrypto.|
