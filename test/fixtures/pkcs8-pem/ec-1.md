> A EC PKCS8-PEM secp256k1 key

```sh
openssl ecparam -name secp256k1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out key
```