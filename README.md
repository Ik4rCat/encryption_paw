# encryption_paw !WIP!
- encryption_paw - College Project on c++ 

### How it works
#### XOR
The idea is that each byte of the file is combined with a byte of the key using an exclusive-OR operation (XOR): output = input ⊕ key[i].
The key is a short string; the key index is taken modulo the length, and the key is repeated throughout the file.
Symmetry: (a ⊕ k) ⊕ k = a, so the same operation with the same key both "encrypts" and "decrypts." There is no separate "decryption mode" in mathematics.

#### RSA
The idea: a pair of keys - a public and a private one. Data encrypted with the public key can only be decrypted with the private key (and vice versa in other scenarios, but in our program: encryption with the public key, reading with the private key).
Mathematics (simplified): the message and keys are numbers modulo a large prime product; encryption is raising to the e power, decryption is raising to the d power, chosen so that the operations are mutually inverse.
In our program, this is done by OpenSSL, with OAEP + SHA-256 padding to ensure short messages cannot be guessed and the block length is secure.
RSA doesn't encrypt a long file in one piece (there's a limit on the size of a single block), so the file is cut into blocks, each block encrypted separately. The length of the original data is written at the beginning of the file to indicate where to stop during decryption.

| **Technologies** |
|---|
| `с++`, `G++`, `make`, `OpenSSL (libcrypto) rsa` & `xor (own implementation) encryptions`, `PEM-keys` |

## Authors

| Project performance assessment | ☆☆☆☆☆ | ☆☆☆☆☆ | ☆☆☆☆☆ |
|---|---|---|---|
| **Digital face** | <img src="https://avatars.githubusercontent.com/Ik4rCat" width="100" height="100" style="border-radius: 100%"> | <img src="https://avatars.githubusercontent.com/gkfosl" width="100" height="100" style="border-radius: 100%">  | <img src="https://avatars.githubusercontent.com/artitiam" width="100" height="100" style="border-radius: 100%"> |
| **Names** | [@awsk](https://github.com/Ik4rCat) | [@gkfosl](https://github.com/gkfosl) | [@artitiam](https://github.com/artitiam) |
| **Work on the project** | `main program` | `presentation` & <br> `documentation` | `main program` |


from B.D.S.M. with <3

