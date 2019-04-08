> A RSA PKCS1-DER key with 3 primes (2048 bits)

```sh
openssl genrsa -primes 3 2048 | openssl rsa -out key -outform DER
```
