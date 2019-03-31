> An encrypted RSA PKCS8-DER with PBES2+PKDF2+aes256-CBC with hmacWithSHA256 (2048 bits)

```sh
openssl genrsa 2048 | openssl pkcs8 -topk8 -outform DER -out key -v2 aes256 -v2prf hmacWithSHA256 -passout pass:password
```
