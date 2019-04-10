> A EC RAW-DER secp256k1 key (compressed)

```sh
openssl ecparam -name secp256k1 -genkey -noout -out key -outform DER -conv_form compressed
```