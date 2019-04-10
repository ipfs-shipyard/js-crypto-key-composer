> An encrypted PKCS8-DER key using PBES2+PKDF2+des-EDE3-CBC and hmacWithSHA384 (2048 bits)

```sh
openssl genrsa 2048 | openssl pkcs8 -topk8 -outform DER -out key -v2 des3 -v2prf hmacWithSHA384 -passout pass:password
```
