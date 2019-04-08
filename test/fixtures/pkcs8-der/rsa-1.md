> A standard RSA PKCS8-DER key (2048 bits)

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | openssl pkcs8 -topk8 -outform DER -nocrypt -out key
```
