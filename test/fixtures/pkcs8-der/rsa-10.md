> An encrypted RSA PKCS8-DER with PBES2+PKDF2+desCBC (2048 bits)

```sh
openssl genrsa 2048 | openssl pkcs8 -topk8 -outform DER -out key -v2 des -v2prf hmacWithSHA256 -passout pass:password
```
