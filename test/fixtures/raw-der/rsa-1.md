> A standard RSA RAW-DER keypair (2048 bits)

```sh
openssl genrsa 2048 | openssl rsa -out key -outform DER &&
openssl rsa -RSAPublicKey_out -in key -inform DER -outform DER -out key.pub
```
