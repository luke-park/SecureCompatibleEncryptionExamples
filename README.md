![](icon.png)

# Secure Compatible Encryption Examples
This repository was created to address the ever-growing number of poor
encryption code examples that float about the internet.  I intend on expanding
this repository over time to include examples in more languages.

The code provided in these examples is intended to be secure by industry
standards as of *1st January 2018*.  Reviewing of these examples is encouraged,
any improvements are welcome, provided they contribute to the security of the
code.

## Algorithms
- **Encryption**: AES-128-GCM
- **Key Deriviation**: PBKDF2
- **PBKDF2 Underlying Hash**: SHA-256

AES with a 128-bit key was chosen due to the Java *Unlimited Strength Policy*
that requires key sizes of no more than 128-bits due to US law.  While the
examples are shown using AES-128, they can be trivially changed to 256-bit AES
by changing the `ALGORITHM_KEY_SIZE` parameter.

## Compatibility
All of the methods in all of the code examples are all compatible with each
other.  That is, encrypted data from the Java example can be decrypted in the
Golang or NodeJS example, and vice versa.

## Methods
Each example exposes 4 methods with signatures that are roughly equivalent to
the following:
- `string encryptString(plaintext: string, password: string)`
- `string decryptString(ciphertext: string, password: string)`
- `byte[] encrypt(plaintext: byte[], key: byte[])`
- `byte[] decrypt(ciphertext: byte[], key: byte[])`

As is expected, the `encrypt` and `decrypt` methods operate on and return raw
binary data.  The `*string` methods, however, take string parameters and return
strings.  The `password` parameter is fed through PBKDF2 first.

**NOTE**: Because of the use of PBKDF2, the binary vs string methods are **not**
compatible.

## Test Vector
The following result of `encryptString` was used as a test vector.
> +0ACFp6Q6l7ZruERTYgJpElm0aI/E6spg1fVmHNzzaBhZKmqx+5no0ieoVK0h/Fhpw==

When decrypted using the password "world", the result should be "hello".  I
very much welcome examples in other languages provided they keep compatibility
with the existing examples.

## Dependencies
- Java: No dependencies, requires Java 8 JRE.
- NodeJS: No dependencies.
- Golang: Requires `golang.org/x/crypto/pbkdf2`, installed using `go get`.
