# 🛸 Mars - small tool for critical info encryption

## The what?
Sometimes you need to store some critical data (2FA tokens, crypto keys, passwords and etc) on your drives. It's advised to keep them encrypted in case of storage theft or data leaks. The program does encryption and decryption of directories and files.

## The why?
GPG/PGP is pretty outdated and barely customizable to be used in the modern days for data encryption. Its hash functions can be brute forced on a GPU, so it's not as safe as it could be, even with cranking up iteration count to the max. Although GPG may still be suitable for most of the needs, my cryptoanarchism paranoia couldn't let me sleep until I make my own tool with top-notch algorithms and design.

## The how?
In case of data theft a potential attacker has infinite amount of time and/or resources, so the main vector of defense is to make brute force as uniformly slow and expensive as possible.

### KDF
For deriving a symmetric key from password `Argon2d` is used. Side-channel attacks are irrelevant here, so the main goal is to make it hard to brute-force on a GPU, what `d` variant essentially does with data-dependent calculations.

Check out [parameter choice section](https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice) to tweak the KDF duration. I personally aim at several minutes of calculations.


### Encryption
For encryption 256-bit cipher is used (AES-256) with [PCBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Propagating_cipher_block_chaining_(PCBC)) mode, which I had to implement myself, because OpenSSL doesn't support it.

#### Why PCBC?
Because it can't be parallelized, so to gain access to the full data, you have to encrypt all the blocks prior to it.

#### Why not OFB?
Because decryption routine is essentially doing multiple rounds of cipher encryption of IV and any changes in cipher text won't propagate to the following blocks, which opens theoretical possibilities for data tampering to compromise sensitive data. While in PCBC every bit changes everything that follows.

#### Integrity check
I used SHA3-512 (to fit the 256 bit crypto strength) for integrity check. The hash of the unencrypted `.tar.br` is encrypted along with the archive's content in place of prefix: `encrypt(digest || archive)`. This scheme prevents any possible brute-force attempts to uncover the key based on guessing plaintext from first blocks. 512 bits of the digest occupy 4 full blocks, adding SHA3 random output, it's impossible to make anything out of it, comparing to concatenating unencrypted hash to the encrypted archive: `digest || encrypt(archive)`, like I did initially.

#### Files zeroing
Temporary files with sensitive data are being overwritten with zeroes, to prevent possible physical analysis of the drives.

@todo Zero initial folder/files as well

### Scheme

Folder or file is put into tar archive and then compressed with Brotli.

```
archive = brotli(tar("folder" or "file"))

salt = random();
key = Argon2d(salt, password)

digest = SHA3-512(archive)

iv = random();
encrypted = AES256-PCBC(iv, digest || archive)

output = salt || iv || encrypted
```

## Building

It requires at least OpenSSL 3.2 for Argon2 support. You can [build it and install from source](https://github.com/openssl/openssl/blob/master/INSTALL.md).

Then run `make` and it will compile `mars` executable.

## Usage

### Encrypt
Specify path to folder or file:
    `mars path/to/folder`

### Decrypt
Encrypted data is put into single `.mars` file, so if you specify it as first argument it will decrypt it:
    `mars encrypted.mars`
