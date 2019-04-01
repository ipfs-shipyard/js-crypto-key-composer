# crypto-key-parser

[![NPM version][npm-image]][npm-url] [![Downloads][downloads-image]][npm-url] [![Build Status][travis-image]][travis-url] [![Coverage Status][codecov-image]][codecov-url] [![Dependency status][david-dm-image]][david-dm-url] [![Dev Dependency status][david-dm-dev-image]][david-dm-dev-url]

[npm-url]:https://npmjs.org/package/crypto-key-parser
[downloads-image]:http://img.shields.io/npm/dm/crypto-key-parser.svg
[npm-image]:http://img.shields.io/npm/v/crypto-key-parser.svg
[travis-url]:https://travis-ci.org/ipfs-shipyard/js-crypto-key-parser
[travis-image]:http://img.shields.io/travis/ipfs-shipyard/js-crypto-key-parser/master.svg
[codecov-url]:https://codecov.io/gh/ipfs-shipyard/js-crypto-key-parser
[codecov-image]:https://img.shields.io/codecov/c/github/ipfs-shipyard/js-crypto-key-parser/master.svg
[david-dm-url]:https://david-dm.org/ipfs-shipyard/js-crypto-key-parser
[david-dm-image]:https://img.shields.io/david/ipfs-shipyard/js-crypto-key-parser.svg
[david-dm-dev-url]:https://david-dm.org/ipfs-shipyard/js-crypto-key-parser?type=dev
[david-dm-dev-image]:https://img.shields.io/david/dev/ipfs-shipyard/js-crypto-key-parser.svg

A library to parse crypto keys in different types and formats.


## Installation

```sh
$ npm install crypto-key-parser
```

This library is written in modern JavaScript and is published in both CommonJS and ES module transpiled variants. If you target older browsers please make sure to transpile accordingly.
Moreover, some of this library's dependencies use the native Node [Buffer](https://nodejs.org/api/buffer.html) module. This means that you must compile your app through a bundler that automatically injects a Buffer compatible implementation for the browser, such as Webpack.


## API

### decomposePrivateKey(inputKey, [options])

Parses a key, extracting information such as its format, key algorithm, key  data and encryption algorithm.

```js
import { decomposePrivateKey } from 'crypto-key-parser';

const myPemKey = `
-----BEGIN RSA PRIVATE KEY-----
ACTUAL KEY BASE64 HERE
-----END RSA PRIVATE KEY-----
`

const myDecomposedKey = decomposePrivateKey(myPemKey)

// {
//     format: 'pkcs1-pem',
//     keyAlgorithm: {
//         id: 'rsa-encryption'
//     },
//     keyData: {
//         publicExponent: 65537,
//         prime1: Uint8Array(...),
//         // ...
//     },
//     encryptionAlgorithm: null
// }
```

Returns the decomposed key, which is an object with the following properties:

<details><summary><strong>format</strong></summary>
   
The format of the key.

See [Formats](#formats) for a list of all supported formats.
</details>

<details><summary><strong>keyAlgorithm</strong></summary>
   
The key algorithm object containing its id and parameters.

See [Key Algorithms](#key-algorithms) for a list of all supported key algorithms.

Do not use the `keyAlgorithm.id` to identify the key type. The reason is that several identifiers map to the same key type. As an example, `rsa-encryption`, `rsaes-oaep` and `rsassa-pss` are all RSA keys. Instead, use [`getKeyInfo(keyAlgorithm)`](#get-key-info) to extract human friendly information about the key.
</details>

<details><summary><strong>keyData</strong></summary>
   
The key data object, containing the interpreted private key itself.

The data inside this object varies per key type. As an example, for RSA keys, this object contains `prime1`, `prime2`, `exponent1`, `exponent2`, and other properties that compose the key.

See [Key Data](#key-data) for a list of examples for all key types.
</details>

<details><summary><strong>encryptionAlgorithm</strong></summary>
  
The encryption algorithm used to decrypt the key or `null` if it was unencrypted.

See [Encryption Algorithms](#encryption-algorithms) for a list all the supported encryption algorithms.
</details>

Available options:

| name | type | default | description |
| ---- | ---- | ------- | ----------- |
| format | string/Array | *all formats*  | Limit the parsing to one or more formats |
| password | string | | The password to use to decrypt the key |

Meaningful [errors](src/util/errors.js) with codes are thrown if something went wrong.
When the `inputKey` is not encoded in any of the valid formats, a `AggregatedInvalidInputKeyError` is thrown, containing a `errors` property with the errors indexed by format. If a single `options.format` was specified, a `InvalidInputKeyError` is thrown instead.


### composePrivateKey(decomposedKey, [options])

Composes a private key from its decomposed parts. This function is the inverse of `decomposePrivateKey`.

```js
import { composePrivateKey } from 'crypto-key-parser';

const myPrivateKey = composePrivateKey({
    format: 'pkcs1-pem',
    keyAlgorithm: 'rsa',
    keyData: { ...},
    encryptionAlgorithm: 'aes128-cbc'
});
```

<details><summary><strong>format</strong></summary>
   
The format of the key.

See [Formats](#formats) for a list of all supported formats.
</details>

<details><summary><strong>keyAlgorithm</strong></summary>
   
The key algorithm object containing its id and parameters. You may also pass an alias directly as a string.

See [Key Algorithms](#key-algorithms) for a list of all supported key algorithms and aliases.
</details>

<details><summary><strong>keyData</strong></summary>
   
The key data object, containing the private key itself.

The data inside this object varies per key type. As an example, for RSA keys, this object contains `prime1`, `prime2`, `exponent1`, `exponent2`, and other properties that compose the key.

See [Key Data](#key-data) for a list of examples for all key types.
</details>

<details><summary><strong>encryptionAlgorithm</strong></summary>
  
The encryption algorithm to use to encrypt the key or `null` to use the defaut one for the format. This will not be used unless the `password` option is set.

See [Encryption Algorithms](#encryption-algorithms) for a list all the supported encryption algorithms.
</details>

Available options:


| name | type | default | description |
| ---- | ---- | ------- | ----------- |
| password | string | | The password to use to decrypt the key |

Meaningful [errors](src/util/errors.js) with codes are thrown if something went wrong.


## Supported formats and algorithms

### Formats

<details><summary><strong>pcks1-der</strong></summary>

The `pkcs1-der` is the DER encoded ASN1 format defined in [RFC 8017](https://tools.ietf.org/html/rfc8017).

This format is only capable of storing unencrypted RSA keys. It's recommended to use the newer PKCS8 whenever possible because it's able to store a variety of key types other than RSA.

Supported key algorithms:
- all RSA key algorithms

Supported encryption algorithms: *none*
</details>

<details><summary><strong>pcks1-pem</strong></summary>

The `pkcs1-pem` is the PEM encoded version of `pkcs1-der` and is defined in [RFC 1421](https://tools.ietf.org/html/rfc1421).

Supported key algorithms: *same as `pkcs1-der`*

Supported encryption algorithms:
- keyDerivationFunc: `openssl-derive-bytes` (default)
- encryptionScheme: `aes256-cbc` (default), `aes192-cbc`, `aes128-cbc`, `des-ede3-cbc`, `des-cbc`, `rc2-128`, `rc2-64`, `rc2-40`
</details>

<details><summary><strong>pcks8-der</strong></summary>

The `pkcs1-der` is the DER encoded ASN1 format defined in [RFC 5208](https://tools.ietf.org/html/rfc5208) and [RFC 5985](https://tools.ietf.org/html/rfc5958).

Supported key algorithms:
- all RSA key algorithms
- ED25519 Keys

Supported [PKCS#5](https://tools.ietf.org/html/rfc8018) encryption algorithms:
- keyDerivationFunc: `pbkdf2+hmac-with-sha512` (default), `pbkdf2+hmac-with-sha384`, `pbkdf2+hmac-with-sha256`, `pbkdf2+hmac-with-sha1`
- encryptionScheme: `aes256-cbc` (default), `aes192-cbc`, `aes128-cbc`, `des-ede3-cbc`, `des-cbc`, `rc2-128`, `rc2-64`, `rc2-40`
</details>

<details><summary><strong>pcks8-pem</strong></summary>

The `pkcs8-pem` is the PEM encoded version of `pkcs8-der` and is defined in [RFC 1421](https://tools.ietf.org/html/rfc1421).

Supported key algorithms: *same as `pkcs8-der`*

Supported encryption algorithms: *same as `pkcs8-der`*
</details>

### Key Algorithms

<details><summary><strong>RSA keys</strong></summary>
   
TODO
</details>

<details><summary><strong>ED25519 keys</strong></summary>
   
TODO
</details>


### Key Data

<details><summary><strong>RSA keys</strong></summary>
   
```js
{
    // Version can be 0 or 1
    // It must be 1 if otherPrimeInfos is defined, 0 otherwise
    version: 0,  // or 1
    modulus: Uint8Array(/* ... */),
    publicExponent: 65537,
    privateExponent: Uint8Array(/* ... */),
    prime1: Uint8Array(/* ... */),
    prime2: Uint8Array(/* ... */),
    exponent1: Uint8Array(/* ... */),
    exponent2: Uint8Array(/* ... */),
    coefficient: Uint8Array(/* ... */),
    // Only defined if number of primes is greater than 2
    otherPrimeInfos: [
        {
            prime: Uint8Array(/* ... */),
            exponent: Uint8Array(/* ... */),
            coefficient Uint8Array(/* ... */),
        }
    ]
}
```
</details>

<details><summary><strong>ED25519 keys</strong></summary>
   
```js
{
    seed: Uint8Array( /* 32 bytes */)
}
```
</details>


### Encryption Algorithms

TODO


## Tests

```sh
$ npm test
$ npm test -- --watch # during development
```


## License

Released under the [MIT License](http://www.opensource.org/licenses/mit-license.php).
