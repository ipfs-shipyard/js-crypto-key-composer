> A standard RSA PKCS1-DER key (2048 bits)

```sh
openssl genrsa 2048 | openssl rsa -out key -outform DER
```
