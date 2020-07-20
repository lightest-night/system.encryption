# Lightest Night
## Encryption

Tools and utilities useful in encrypting data

### Build Status
![](https://github.com/lightest-night/system.encryption/workflows/CI/badge.svg)
![](https://github.com/lightest-night/system.encryption/workflows/Release/badge.svg)

#### How To Use
##### Key Generation
* Use the `KeyFactory.GenerateKeyPair` function to generate a Public & Private key

##### Encryption
* Serialize the object
* Use the `Encryptor.Encrypt(byte[] publicKey, string dataToEncrypt)` function

##### Decryption
* Use the `Decryptor.Decrypt<TValue>(byte[] privateKey, EncryptedDataBlock dataBlock)` function

#### Delegation
The `GenerateKeyPair` delegate can be mapped in your IoC container to a singleton for ease of use