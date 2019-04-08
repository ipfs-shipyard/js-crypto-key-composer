> A RSA PKCS8-DER key with 3 primes (2048 bits)

```sh
openssl genrsa -primes 3 2048 | openssl pkcs8 -topk8 -outform DER -nocrypt -out key
```
