> An encrypted RSA PKCS8-DER with PBES2+PKDF2+des-EDE3-CBC with hmacWithSHA384 (2048 bits)

```sh
openssl genrsa 2048 | openssl pkcs8 -topk8 -outform DER -out key -v2prf hmacWithSHA384 -passout pass:password
```
