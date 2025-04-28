


# RSA-OAEP Encryption Tool

## RSA Implementation
- **Key Size:** 2048-bit keys by default
- **Public Exponent (e):** Fixed at 65537
- **Optimization:** Uses Chinese Remainder Theorem (CRT) for faster decryption

## OAEP Implementation
- **Hash Function:** SHA-256
- **Security:** Provides semantic security against chosen plaintext attacks
- **Padding:** Adds random padding to prevent deterministic encryption



## Installation

Install all dependencies:

```bash
pip install -r requirements.txt
```

> It's just pillow for the GUI


## How to Use
Run `main.py` and gui with the following options will appear:

### Key Generation
1. Click **Generate Key Pair** to create a new 2048-bit RSA key pair.
2. Save the **public key** when prompted (default extension: `.txt`).
3. Save the **private key** when prompted (default extension: `.txt`).

### File Encryption
1. In the **Encryption** section, click **Select File** to choose a file to encrypt.
2. Click **Select Key** to choose the public key file (`.txt`).
3. Click **Encrypt File** and select where to save the encrypted output.
4. Wait for the encryption process to complete.

### File Decryption
1. In the **Decryption** section, click **Select File** to choose a file to decrypt.
2. Click **Select Key** to choose the private key file (`.txt`).
3. Click **Decrypt File** and select where to save the decrypted output.
4. Wait for the decryption process to complete.



## Input and Output File Formats

### Key Files

- **Format:** Text files containing hexadecimal representations of key components.
- **Public Key:** Contains the RSA modulus (`n`) and public exponent (`e`).
- **Private Key:** Contains the RSA modulus (`n`), private exponent (`d`), and prime factors (`p`, `q`).

#### Example Public Key

```text
e:10001
n:e4050f1e9ff5ddf2e62689e693b644e7265cd00d705985841f042380cf6e799aab1685515d7e9096a69220a3cd2200813274e0e0fde4add485126cb70f0dd6d8ff3ea8963c1d2db27be49c177dfd98813f49edca3c27bdac502d995d6b1a8e386b2157031fb695714a15a4f1c1773dead517a814aece66c268ae48a5ad23f68863cb162dddb38d7e5a4f6858f135d7ccf4f2b7c872378c314a8792d91709f31a321277a7b9456b64a267de2107a34c7d158a356e0af9e2ff8de72b66a15372569a37297dff86dd41414beeb59827ee950018ab20da4e6adae225036dfea8660b6674704cc4d610f84e4b36fe1a670f779478c8373ec42cde649adc75a3fe9b1d
```

#### Example Private Key

```text
d:e05a45f52908be983771a5efb458fbd4bfbf448a648800c1edcea1ac24ed1b435ea16b0d92c36c3a7eac7ae710782b2cf3db62449e2bba09c7e1480c9a0850e3f3c8d011fa15ef9795256b9c05c056a49d03fdaf259f2895f9d1d3fbc1dd40202cf081efb5ed6d7f2998c0518abcebb43a74eb516669f95bc1a9f21ae98fe00999499328d503b8a56ee7fc55e6295d895a674a8732cd49789139b214c4eb3e52d3379cf24e4f4747985fac1bd17c8d794cc9205f857b5b01103f65dca065c341cda3fd650833e6814691d431bf6d47dacb310d923d8b16bbe3094288a0b2d7401339017a984265bd53526af3b52a27a35df33d66ccb21022f87100a341ca4955
n:e4050f1e9ff5ddf2e62689e693b644e7265cd00d705985841f042380cf6e799aab1685515d7e9096a69220a3cd2200813274e0e0fde4add485126cb70f0dd6d8ff3ea8963c1d2db27be49c177dfd98813f49edca3c27bdac502d995d6b1a8e386b2157031fb695714a15a4f1c1773dead517a814aece66c268ae48a5ad23f68863cb162dddb38d7e5a4f6858f135d7ccf4f2b7c872378c314a8792d91709f31a321277a7b9456b64a267de2107a34c7d158a356e0af9e2ff8de72b66a15372569a37297dff86dd41414beeb59827ee950018ab20da4e6adae225036dfea8660b6674704cc4d610f84e4b36fe1a670f779478c8373ec42cde649adc75a3fe9b1d
p:f35abb103a7ee7a86939b7a0eabb809df73b3494f77a34933b6f416494a3da77a50feeb39deb100c1df601248858b83920246974768ac3548e397737ff8da1cc1e0fca69e5c069db5bbf8f19f5b01a76b1e25f316eefcb278938fca2bbe8756a1bb4f447a1c48e1bfc7f70b30696a8d3e5675e2960e346bda09f87870ef3484b
q:efde560c63134f0ac7dfc2a5e360b30400f533011e4275e5c14e154c9b445faeb887190eee6f01b1e261fd358c5cf9fa7ae6813a7a86ae13579ef97cad89d21d6487670bda403994e7d5ac58b48c2a7d80bd48689ec9cb3e7a6fbbf99f36cd994854751603c0b57fe38a859deb7383c4fb71f7db18f406f9d84ffc0dbdc85937
```

### Encrypted Files
- **Input:** Any file type.
- **Output:** Binary file with RSA-OAEP encrypted content.
- **Default Extension:** `.enc` (but any extension can be used).

### Decrypted Files
- **Input:** Must be a file previously encrypted with this tool.
- **Output:** Identical to the original file before encryption in binary format.
- **Extension:** User specified (no default extension) so after decrypting have to append the extension previously used for that file.

---

Related Source:
+ [link](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)
+ [link2](https://www.rfc-editor.org/rfc/rfc3447#section-7.1.1)
