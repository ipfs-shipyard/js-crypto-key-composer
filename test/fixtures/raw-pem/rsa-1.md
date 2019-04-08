> A standard RSA PKCS1-PEM keypair (2048 bits)

```sh
openssl genrsa -out key 2048 &&
openssl rsa -RSAPublicKey_out -in key -out key.pub
```
