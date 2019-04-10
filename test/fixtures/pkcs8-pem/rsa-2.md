> An encrypted RSA PKCS8-PEM key using PBES+PKDF2+aes128 (2048 bits))

```sh
openssl genpkey -out key -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -aes-128-cbc -pass pass:password
```
