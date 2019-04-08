> A RSA PKCS1-DER key with 4 primes (4096 bits)

```sh
openssl genrsa -primes 4 4096 | openssl rsa -out key -outform DER
```
