> A EC SPKI-DER secp256k1 key

```sh
openssl ecparam -name secp256k1 -genkey -noout | openssl pkey -pubout -out key.pub -outform DER
```