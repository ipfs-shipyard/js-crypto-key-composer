> A standard RSA SPKI-DER key (2048 bits)

```sh
openssl genrsa 2048 | openssl pkey -out key.pub -outform DER
```
