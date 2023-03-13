# RSA Toy Implementation

This is a simple implementation of RSA encryption and decryption for educational purposes only. It is mostly based on this course: https://www.educative.io/courses/everyday-cryptography/JPpNR32rK0v.

## Synopsis

```go
private, public, err := GenerateKeysPair()
original_plaintext := "Lorem ipsum"
ciphertext := Encrypt(original_plaintext, public)
decrypted_plaintext := Decrypt(ciphertext, private)
```

## Features
* Key pair generation
* Encryption and decryption
* Randomized padding - outputs different ciphertexts on each encryption

## Limitations
This toy implementation has several limitations:

* Uses short primes that fit into 16 bits.
* Uses int32 for each byte, which is not an efficient encoding scheme.
* Does not use cryptographically strong random number generators.

To enhance clarity and simplicity, I have omitted all these complications.

# Disclaimer
This is a toy implementation and should not be used for any real-world cryptographic tasks.

# Enjoy!
I hope this code helps you understand the basics of RSA. Feel free to explore and experiment with the code.

# Future information

Great advanced course on Cryptography: https://www.coursera.org/learn/crypto 