Muhammad Radhitya Utomo         [2206830744]
<br> Muhammad Hilmy Abdul Aziz   [2206828701]


# RSA-OAEP Encryption Tool

## RSA Implementation
- **Key Size:** 2048-bit keys by default
- **Public Exponent (e):** Fixed at 65537
    >Reasons:
    - For e higher than 65537 would make it slower, whilst generally a high number is safer. 
    https://crypto.stackexchange.com/questions/3110/impacts-of-not-using-rsa-exponent-of-65537
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
Run `main.py` and gui with the following options will appear (Recommend full screening to see the progress bar):

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
- **Private Key:** Contains the RSA modulus (`n`), private exponent (`d`), and prime factors (`p`, `q`), as well as calculated CRT components(`dp`,`dq`,`qinv`)

#### Example Public Key

```text
e:10001
n:e4050f1e9ff5ddf2e62689e693b644e7265cd00d705985841f042380cf6e799aab1685515d7e9096a69220a3cd2200813274e0e0fde4add485126cb70f0dd6d8ff3ea8963c1d2db27be49c177dfd98813f49edca3c27bdac502d995d6b1a8e386b2157031fb695714a15a4f1c1773dead517a814aece66c268ae48a5ad23f68863cb162dddb38d7e5a4f6858f135d7ccf4f2b7c872378c314a8792d91709f31a321277a7b9456b64a267de2107a34c7d158a356e0af9e2ff8de72b66a15372569a37297dff86dd41414beeb59827ee950018ab20da4e6adae225036dfea8660b6674704cc4d610f84e4b36fe1a670f779478c8373ec42cde649adc75a3fe9b1d
```

#### Example Private Key

```text
d:226796539ba9fe9f1f27bd4f286ccd1e411df212aba75ce3a73c026c5b10e5b29a2debe1afa0bdc76b9654e7f9734caceb73d5b463fc6996e1703a836f7bb1e339323ef72545f95a2dfc1dd2cf387a4f843fb7c6df8215ce86ec04b9a33db153c678a2fd197c3b75c7010302db48bfd6d71f62accdae1c72c589a90308c2522d86b6f1853b52f2cf2ec7270127b08c02194bc40aa5a054027add5d87e642fbaaf59120f4061b234caa205fd9a2d15baba8faa6054436bb382d849aef559026fe1da7334670491b1602d144fc7e60da46983850342159c12e21c511ec9a164ee3b5d6faa035caee65714da6455a51d486ac0260c07aa02d345721e72a81d15095
n:990045f51737ec492109a62be8ee26dc457d0a9fe152adde79c43caaae5326eb962ef90fe2dbc549badbaf6fffa3d493613d6d6ce51b1bf023fa4d283fc5a80c486dc9ffe661269e72eeebb587be6ecb2f0b9f2ed67b64b633c6996ab601163e4a2eaf3c8c090ca9eefd697561f31866438b1688a5fb119cc674e21dbc4f78ecb2edabd332626e055d6b0a65f0441d81d942925fd8a674c7bd2c6fb744b3c78cf56dfc42f6f6d29337bec263094c4baff341f3705397f2adc2a640bc171bf372f19cb4ab1e70bb98457bf1e68bb5289729e777260ce1192413fbeb02920a40425d011cc9df1a1eb9ff3c946f0530480729ab25e2d391e3500b5be5f2247175e9
p:c360d8a777189e354b1368a50fe44192e85a7c39ac7b05cc8ffd6eb8e79f567290dad87b0b1c69fcf168ba73792ac5a7012c68b19b7b939438d3a0a913d88da3bca62e3832fe03ad37408e3083a54aab854e2336dbe0c24508c81f9b5ac2989b3c8b338c998b4f4213836985082790ac0e1c7d96a20bef2eb0304d72d6dfb94f
q:c87958feef11a17faf492171afb0230a3e4c3e44feb132cb0affebc2e7ca9029f413bae406e5ba40ade2a6d02077fd37fe38a635dd4d7d6593ad0f905f528927bca4ef07b1d5eb4cdfeec925570f74bad6aa19e3aa267ea743fc439548c638e0486b7af22f99202b327dfdbfaddebfff7ff1de64e7fab9e0237dc1a8f5a39f47
dp:bc179f5c519ec4a8bfd736963a1f6035c3356184d0953b36fda45994ef8009649029efe13d0824cd5bc79c4090f4e985e6ee4ef8359c99ae47ab0d6fd8e8512bc1f1266bfa436b5cb5e5933e076ef8dcf9a008ecc66fb1f76e05e3cfd767a22d48f326348499863b31b800bd0ee5b034c3fd0fb715d87172bc32344d8ba9a4a7
dq:ebb5c1edfd29bdb9635f98f3129f069404aba08b7eead9cde22106132476070b4cefe5ce364de5b026c3575f5ecdb5ed1ffb7b71d9c242ae2bf44f5870bb9a881e45cec63d5248571af4a78c3fd0ec6ec1f73e797095d254d89ac2dbc3b54d2a67fbf792ca64406e89ef996ac60421bb47b41ac889f942934727958c13454f
qinv:bba0fbbaeb0062e9fade29f01618e380c41a1fbd33d81a17817af9df2d0d2a90d47c0423573dc0a0e2a3eec71ff2dd4803e1e5b6f3dc920dd76c00619288e02c9264f094b6ec4ee4f3b7c169481f9d63dc95dc27cfa24bc6a7c608c234fa5b385ecc07ba705fa587bcf0c3eae481550df22fcbc9b9761ea36a9112be4fd7f5fa

```

### Encrypted Files
- **Input:** Any file type.
- **Output:** Binary file with RSA-OAEP encrypted content. The original file extension is attached to the header.
- **Default Extension:** `.enc` (but any extension can be used).

### Decrypted Files
- **Input:** Must be a file previously encrypted with this tool. The header is then read for the extension.
- **Output:** Identical to the original file before encryption in binary format.
- **Extension:** Depends on the header (no default extension).

---


### Justification:
#### Why RSA OAEP
One of the reason to use RSA OAEP is to avoid having the same cipherttext when encrypting the same plaint text using OAEP allows for different result of ciphert text when encrypting the same plain text, example Exhibit A and B:

A file named `image` was encrypted twice and placed in foldess `exhibit A` and `exhibit B`:
![Screenshot 2025-04-28 193923](https://github.com/user-attachments/assets/3f30903c-e30a-4201-b48d-7d91674ba635)

When looking at the binary file we can see that it has diffrent output of ciphertext despite encrypting the same plaintext:
`Exhibit A`:
![Screenshot 2025-04-28 194010](https://github.com/user-attachments/assets/865e8450-5d5f-419d-b022-527644799635)

`Exhibit B`:
![Screenshot 2025-04-28 194134](https://github.com/user-attachments/assets/a8541e69-2426-4c9f-bafa-591389bff0fe)

And after Decrypting the file contents are the same:
`Exhibit A`:
![Screenshot 2025-04-28 194350](https://github.com/user-attachments/assets/da04c947-87dc-465d-a92a-ad69ded28d75)
`Exhibit B`:
![Screenshot 2025-04-28 194403](https://github.com/user-attachments/assets/7fdd84cd-0431-488f-99fc-10f8652e44bd)

### CRT Format:
In an attempt to slightly Optimize the RSA decryption process instead of following the:
```
m ≡ cᵈ mod n
```

We used CRT because we assume you wouldnt share the private key to anyone anyway so we thought speeding up the decrypting process using CRT would be fine.
The speedup of the operation would be around 4 times ([source](https://crypto.stackexchange.com/questions/99357/rsa-decryption-using-crt-how-does-it-affect-the-complexity)).
The way it works are the CRT components are calculated during key generation and stored in the `private_key`([RSA CRT Flow](https://www.di-mgt.com.au/crt_rsa.html)).


Related Source:
+ [link](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)
+ [link2](https://www.rfc-editor.org/rfc/rfc3447#section-7.1.1)
+ [link3](https://crypto.stackexchange.com/questions/3110/impacts-of-not-using-rsa-exponent-of-65537) 
