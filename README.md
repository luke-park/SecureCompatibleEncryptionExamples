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
|Language|Minimum Version|Dependencies/Notes|
|--------|---------------|------------|
|Java|Java 8 JRE||
|Kotlin|Java 8 JRE||
|JavaScript (Node)|NodeJS 4.0.0+||
|JavaScript (Browser)||Requires [base64-js](https://github.com/beatgammit/base64-js) and a browser that supports the Web Crypto API.|
|Go|Go 1.9|`golang.org/x/crypto/pbkdf2`|
|Python|Tested on v3.6.4|Requires [PyCryptodome](https://github.com/Legrandin/pycryptodome), tested with v3.4.7.
|C#|.NET 4|Requires `BouncyCastle`, see [this NuGet package](https://www.nuget.org/packages/BouncyCastle/).|
|C||Requires OpenSSL libssl-dev.|
|Visual Basic .NET|.NET 4|Requires `BouncyCastle`, see [this NuGet package](https://www.nuget.org/packages/BouncyCastle/).|
|PHP|PHP 7.1||
|Swift|Swift 4.0|[SwiftGCM Library](https://github.com/luke-park/SwiftGCM) (single-file), also requires a bridge for CommonCrypto.|

## Test Vectors
The following strings are the results of `encryptString`.  If your implementation can `encryptString` and `decryptString` using the code you've written, and can also `decryptString` the test vectors below, then it is suitable for inclusion in this repository.  Recall that, due to a randomly generated salt and nonce, the following are not expected outputs for `encryptString`, they are for testing `decryptString` only.

| Plaintext | Password | Result |
|-----------|----------|--------|
|XCbJbjd72q|DTY62mV2Cv|`CqjxsXq6Y5ebtW6w98UQfgwdOpaCCkCy0l1qK5gJfhZnKVhp4+OuvxoiigHi8mO1R8CAyl5t`|
|SOJHSCm4qR|Pl4WODjq4k|`VtHh3Z6jqJpIDK0yLe4+/UNpxqBqcmaiJWmaecb7qfCyOlAcVJ973zBNM51VCup5UTuVlu3H`|
|NYzd53moLT|BZO8PUEysY|`SNQHdWnlcmJELLKewNTxBhzmJ1U+ChqKK5Kdvd/FSKssHW5b8y8SOrNVHdm78JUAYpGKlEUD`|
|vW1Qjb30mt|OziaxPFGYh|`5EmCwwSWj6YYgxBlld6DFW8I+QXCWxz5g/laEwUYV/DuoCGvxbW4ZlMd1Tsj4N07WbBOhIJU`|
|9z19eFctoZ|gkLDY5mmzT|`7miUNuhjJPAlbIHYKA2v/iBH3aplFF0pGw6HQAD5tKluh/1M69MLQ9xIkVcGfTr0CycsTFLU`|
|<Empty String>|<Empty String>|`0iqwbC8/1YvTsl2dog6aXaGfXVypsv1BcbnDE06C7nl9REITn3NW18+ZUmc=`|

## C Example
The C example requires a bit more effort to understand and use properly due to varying buffer sizes with regard to base64 padding.  The example below shows how to use `crypt_string_get_length` to determine what buffer size you will need to allocate to store the result.
```c
#include "scee.h"
#include <stdio.h>

int main(int argc, char* argv[]) {

    // Our plaintext and password.
    char plaintext[] = "Hello, World!";
    char password[] = "OddShapelyOak7332";

    // Make enough space for our ciphertext.
    // Note that crypt_string_get_length will give us the size of the buffer we
    // need INCLUDING the null character.
    size_t ct_length = crypt_string_get_length(strlen(plaintext), SCEE_CRYPT_ENCRYPT);
    char ciphertext[ct_length];

    // Encryption.
    // The operation places the null character at the end of the buffer for us.
    int r = encrypt_string(plaintext, strlen(plaintext), password, strlen(password), ciphertext);
    if (r != SCEE_OK) { return 1; }

    // Output for Encryption.
    printf("Ciphertext Buffer Size: %zu\n", ct_length);
    printf("Ciphertext strlen     : %zu\n", strlen(ciphertext));
    printf("Ciphertext            : %s\n\n", ciphertext);

    // Make enough space for our plaintext again.
    // Note that because of base64 padding, crypt_string_get_length will
    // usually tell us that we need more space than we do.  We can get the
    // actual length of the plaintext after we decrypt.
    size_t pt_max_length = crypt_string_get_length(strlen(ciphertext), SCEE_CRYPT_DECRYPT);
    size_t pt_actual_length;
    char plaintext2[pt_max_length];

    // Decryption.
    // The operation places the null character at the end of the buffer for us.
    r = decrypt_string(ciphertext, strlen(ciphertext), password, strlen(password), plaintext2, &pt_actual_length);
    if (r != SCEE_OK) { return 1; }

    // Output for Decryption.
    printf("Plaintext Buffer Size: %zu\n", pt_max_length);
    printf("Plaintext Actual Size: %zu\n", pt_actual_length);
    printf("Plaintext strlen     : %zu\n", strlen(plaintext));
    printf("Plaintext            : %s\n\n", plaintext);

    return 0;
}
```
