> A RSA PKCS8-DER key with 4 primes (4096 bits)

```sh
openssl genrsa -primes 4 4096 | openssl pkcs8 -topk8 -outform DER -nocrypt -out key
```
