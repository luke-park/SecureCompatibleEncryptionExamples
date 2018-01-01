![](icon.png)

# Secure Compatible Encryption Examples
This repository was created to address the ever-growing number of poor
encryption code examples that float about the internet.  This repository will
expand over time to include examples in more languages.

The code provided in these examples is intended to be secure by industry
standards as of *1st January 2018*.  Reviewing of these examples is encouraged,
any improvements are welcome, provided they contribute to the security of the
code.

**WARNING**: The examples given in this repository are meant to demonstrate best-practice encryption techniques ***ONLY***.  The code layout, packaging and/or structure of the code may not be optimal or fitting for use.  The examples given are not meant to be drop-in code excerpts that you can use in your project, they are for demonstration purpose only.  You should carefully implement the examples manually in your own code as required, do not use them directly.

## Algorithms
- **Encryption**: AES-128-GCM
- **Key Deriviation**: PBKDF2
- **PBKDF2 Underlying Hash**: SHA-256

AES with a 128-bit key was chosen due to the Java *Unlimited Strength Policy*
that requires key sizes of no more than 128-bits due to US law.  While the
examples are shown using AES-128, they can be trivially changed to 256-bit AES
by changing the `ALGORITHM_KEY_SIZE` parameter.

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
strings.  The `password` parameter is fed through PBKDF2 first.

**NOTE**: Because of the use of PBKDF2, the binary vs string methods are **not**
compatible.

## Test Vector
The following result of `encryptString` was used as a test vector.
> +0ACFp6Q6l7ZruERTYgJpElm0aI/E6spg1fVmHNzzaBhZKmqx+5no0ieoVK0h/Fhpw==

When decrypted using the password "world", the result should be "hello".
Examples in other languages are very much welcome provided they keep
compatibility with the existing examples.

## Dependencies
- **Java**: No dependencies, requires Java 8 JRE.
- **NodeJS**: No dependencies.
- **Golang**: Requires `golang.org/x/crypto/pbkdf2`, installed using `go get`.  View on GoDoc [here](https://godoc.org/golang.org/x/crypto/pbkdf2).
- **C#**: Requires `BouncyCastle`, see [this NuGet package](https://www.nuget.org/packages/BouncyCastle/) or view [on the web](http://www.bouncycastle.org/csharp/).
- **PHP**: Requires at least PHP 7.1, no actual dependencies.
