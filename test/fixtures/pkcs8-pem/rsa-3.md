> An encrypted RSA PKCS8-PEM (2048 bits) using PBES+PKDF2+aes256

```sh
openssl genpkey -out key -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -aes-256-cbc -pass pass:password
```
