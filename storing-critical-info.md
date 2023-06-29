#### blog about web development tricks, data safety paranoia, chinese antiques and more

# installing openssl 3
https://nextgentips.com/2022/03/23/how-to-install-openssl-3-on-ubuntu-20-04/

## upgrade ubuntu

```
sudo apt update
sudo apt upgrade -y
```

## openssl deps

sudo apt install build-essential checkinstall zlib1g-dev -y

## setup ssh keys

https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent 


ssh-keygen -t ed25519 -C "22231294+Lutymane@users.noreply.github.com"

eval "$(ssh-agent -s)"

ssh-add ~/.ssh/gh

## gh fingerprints
https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints


## clone repo

cd ~/src/

git clone -b master --single-branch --depth 1 git@github.com:openssl/openssl.git

# remove old openssl

apt-get remove openssl -y

sudo make uninstall

# add lib64

sudo ldconfig /usr/local/lib64/

/lib/x86_64-linux-gnu had previous version openssl libs, so sudo rming them
ls | grep ssl
ls | grep crypto

## config, build, test, install

<!-- ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib -->
<!-- https://github.com/openssl/openssl/blob/master/INSTALL.md -->
./Configure no-deprecated no-apps
make 
<!-- make test -->
<!-- sudo important!!! -->
sudo make install_sw

# show ld dirs
ldconfig -v


## vvvv don't use below vvvv

## remove old bins

sudo mv /usr/bin/c_rehash /usr/bin/c_rehash.BEKUP
sudo mv /usr/bin/openssl /usr/bin/openssl.BEKUP

## env

sudo nano /etc/environment

// append
/usr/local/ssl/bin

## link (needed in case of libssl.so.3 not found error)

cd /etc/ld.so.conf.d/

echo "/usr/local/ssl/lib64" | sudo tee openssl.conf > dev/null

sudo ldconfig -v

<!-- https://linuxhint.com/install-openssl-3-from-source/ -->

<!-- ln -s /usr/local/ssl /usr/bin/ -->

# GPG


https://security.stackexchange.com/questions/14867/how-secure-is-gnupg-conventional-encryption-with-defaults/14874#14874

https://security.stackexchange.com/questions/15581/do-openpgp-gnupg-apply-slow-hash-to-password-when-encrypting-decrypting-key

https://crypto.stackexchange.com/questions/9985/kdf-and-number-of-iterations-for-gpg

https://security.stackexchange.com/questions/15632/what-is-purpose-of-s2k-gnupg-options

# !!! adding openssl development headers
default openssl installation has limited headers, so after compilation and installation from source you should copy headers into /usr/include to be used from angle brackets

sudo cp -a ./include/openssl /usr/include