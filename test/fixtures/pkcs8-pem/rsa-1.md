> A standard RSA PKCS8-PEM key (2048 bits)

```sh
openssl genpkey -out key -algorithm RSA -pkeyopt rsa_keygen_bits:2048
```
