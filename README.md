![](icon.png)

# Secure Compatible Encryption Examples
This repository was created to address the ever-growing number of poor
encryption code examples that float about the internet.  This repository will
expand over time to include examples in more languages.

As of October 2018, there are **16** different compatible examples for **14**
different languages across **5** different platforms.

## Algorithms
- **Encryption**: AES-128-GCM
- **Key Deriviation**: PBKDF2
- **PBKDF2 Underlying Hash**: SHA-256

AES with a 128-bit key was chosen due to the Java *Unlimited Strength Policy*
that requires key sizes of no more than 128-bits due to cryptography export laws.  While the
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
binary data.  The `*string` methods, however, take string parameters and return base64 encoded strings.  The `password` parameter is fed through PBKDF2 first.  `password` can be of any length but `key` must be 128-bits in length.  You can change the AES key size by adjusting the `ALGORITHM_KEY_SIZE` parameter, and in some examples, the `ALGORITHM_NAME` parameter too.

**NOTE**: Because of the use of PBKDF2, the binary vs string methods are **not**
compatible.

## Dependencies
|Language|Version Tested|Dependencies|Notes|
|--------|---------------|------------|-----|
|Java|Java 8 JRE|||
|Kotlin|Java 8 JRE|||
|JavaScript (Node)|NodeJS 8.4.0||Tested on 8.4.0, but supported in versions as early as 4.0.0|
|JavaScript (Browser)||Requires [base64-js](https://github.com/beatgammit/base64-js)|Uses the WebCrypto API, ensure browser support before using this example.|
|Go|Go 1.9|`golang.org/x/crypto/pbkdf2`|Tested on 1.9 but supported in earlier versions.|
|Python|v3.6.4|Requires [PyCryptodome](https://github.com/Legrandin/pycryptodome)|No support for Python 2.|
|Ruby|v2.4.4|Uses the [OpenSSL Gem](https://rubygems.org/gems/openssl/versions/2.0.0.beta.1)||
|Visual Basic .NET|.NET 4.5|Requires [BouncyCastle](https://www.nuget.org/packages/BouncyCastle/).||
|C#|.NET 4.5|Requires [BouncyCastle](https://www.nuget.org/packages/BouncyCastle/).||
|C||Requires OpenSSL libssl-dev|Uses `SCEE.h` header file.|
|C++|Requires C++11 Compiler|Requires OpenSSL libssl-dev|Wrapper for the C example.  Requires `SCEE.h` and `SCEE_cpp.h`|
|Objective-C||Requires OpenSSL libssl-dev|Wrapper for the C example.  Requires `SCEE.h` and `SCEE_objc.h`|
|Rust|v1.30.0|Requires the ring v0.13.2 and base64 v0.9.3 crates||
|Swift|Swift 4.0|Requires [SwiftGCM](https://github.com/luke-park/SwiftGCM).|Must use a bridge for CommonCrypto.|
|PHP|Requires PHP 7||Uses `random_bytes` which requires PHP 7.|

## Test Vectors
The following ciphertexts are the results of `encryptString` using the given password.  If your implementation can `encryptString` and `decryptString` using the code you've written, and can also `decryptString` the ciphertexts below to the same given result, then it is suitable for inclusion in this repository.  Recall that, due to a randomly generated salt and nonce, the following are not expected outputs for `encryptString`, they are for testing `decryptString` only.

| Ciphertext | Password | Plaintext |
|-----------|----------|--------|
|`CqjxsXq6Y5ebtW6w98UQfgwdOpaCCkCy0l1qK5gJfhZnKVhp4+OuvxoiigHi8mO1R8CAyl5t`|DTY62mV2Cv|XCbJbjd72q|
|`VtHh3Z6jqJpIDK0yLe4+/UNpxqBqcmaiJWmaecb7qfCyOlAcVJ973zBNM51VCup5UTuVlu3H`|Pl4WODjq4k|SOJHSCm4qR|
|`SNQHdWnlcmJELLKewNTxBhzmJ1U+ChqKK5Kdvd/FSKssHW5b8y8SOrNVHdm78JUAYpGKlEUD`|BZO8PUEysY|NYzd53moLT|
|`5EmCwwSWj6YYgxBlld6DFW8I+QXCWxz5g/laEwUYV/DuoCGvxbW4ZlMd1Tsj4N07WbBOhIJU`|OziaxPFGYh|vW1Qjb30mt|
|`7miUNuhjJPAlbIHYKA2v/iBH3aplFF0pGw6HQAD5tKluh/1M69MLQ9xIkVcGfTr0CycsTFLU`|gkLDY5mmzT|9z19eFctoZ|
|`0iqwbC8/1YvTsl2dog6aXaGfXVypsv1BcbnDE06C7nl9REITn3NW18+ZUmc=`|*Empty String*|*Empty String*|

## C Example
The C example requires a bit more effort to understand and use properly due to varying buffer sizes with regard to base64 padding.  The example below shows how to use `crypt_string_get_length` to determine what buffer size you will need to allocate to store the result.
```c
#include "SCEE.h"
#include <stdio.h>

int main(int argc, char* argv[]) {

    // Our plaintext and password.
    unsigned char plaintext[] = "Hello, World!";
    unsigned char password[] = "OddShapelyOak7332";

    // Make enough space for our ciphertext.
    // Note that scee_crypt_string_get_length will give us the size of the buffer we
    // need INCLUDING the null character.
    size_t ct_length = scee_crypt_string_get_length(strlen(plaintext), SCEE_CRYPT_ENCRYPT);
    unsigned char ciphertext[ct_length];

    // Encryption.
    // The operation places the null character at the end of the buffer for us.
    int r = scee_encrypt_string(plaintext, strlen(plaintext), password, strlen(password), ciphertext);
    if (r != SCEE_OK) { return 1; }

    // Output for Encryption.
    printf("Ciphertext Buffer Size: %zu\n", ct_length);
    printf("Ciphertext strlen     : %zu\n", strlen(ciphertext));
    printf("Ciphertext            : %s\n\n", ciphertext);

    // Make enough space for our plaintext again.
    // Note that because of base64 padding, scee_crypt_string_get_length will
    // usually tell us that we need more space than we do.  We can get the
    // actual length of the plaintext after we decrypt.
    size_t pt_max_length = scee_crypt_string_get_length(strlen(ciphertext), SCEE_CRYPT_DECRYPT);
    size_t pt_actual_length;
    unsigned char plaintext2[pt_max_length];

    // Decryption.
    // The operation places the null character at the end of the buffer for us.
    r = scee_decrypt_string(ciphertext, strlen(ciphertext), password, strlen(password), plaintext2, &pt_actual_length);
    if (r != SCEE_OK) { return 1; }

    // Output for Decryption.
    printf("Plaintext Buffer Size: %zu\n", pt_max_length);
    printf("Plaintext Actual Size: %zu\n", pt_actual_length);
    printf("Plaintext strlen     : %zu\n", strlen(plaintext));
    printf("Plaintext            : %s\n\n", plaintext);

    return 0;
}
```
