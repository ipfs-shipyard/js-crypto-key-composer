> A EC RAW-PEM secp256k1 key

```sh
openssl ecparam -name secp256k1 -genkey -noout | openssl ec -out key -outform PEM
```