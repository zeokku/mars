Start:
    * `mars {path = /path/to/folder}`
    * If `path` ends with `.mars` -> decrypt, else -> encrypt
    * Input password {pwd}

Encrypt:
    * Compress folder: {tar} `tar -zcf {path}`
    * Calculate tar hash: {hash} = SHA3-512(tar)
    * Generate random salt: {salt}
    * Derive key from password and salt: {key} = Argon2id(pwd, salt)
    * Encrypt tar: {enc} = XTS-AES-256(tar, key)
    * Compose resulting mars file: {out} = salt || hash || enc

out_file.mars = `salt || sha3-512(tar) || encrypted_tar ( = iv || ciphertext )`

v2:
`salt || encrypted(sha3-512(tar) || tar){ = iv || ciphertext }`
v2 prevents from searching for file prefix signatures, since it starts with a random hash

folder preparation:
https://unix.stackexchange.com/questions/533463/tar-contents-in-current-directory-to-stdout
tar will only write stdout to smth
* `tar -c data` (`tar -x data.tar`)
* `brotli --best data.tar -o data.tar.br` (`brotli -d`)

Result of my paranoidal distrust to GPG

# argon

https://cryptobook.nakov.com/mac-and-key-derivation/argon2
https://www.rfc-editor.org/rfc/rfc9106.html#name-introduction

# symmetric padding

https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method

https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption

https://www.openssl.org/docs/man3.1/man3/EVP_EncryptUpdate.html

# overwrite files with 0s