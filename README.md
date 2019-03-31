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

### decomposePrivateKey(input, [options])

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
//         type: 'rsa-encryption'
//         parameters: Uint8Array([05, 00]),
//     },
//     keyData: {
//         version: 0,
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

See [Formats]() for a list of all supported formats.
</details>
<details><summary><strong>keyAlgorithm</strong></summary>
   
The key algorithm object containing its id and parameters.

See [Key Algorithms]() for a list of all supported key algorithms.

Do not use the `keyAlgorithm.id` to identify the key type. The reason is that several identifiers map to the same key type. As an example, `rsa-encryption`, `rsaes-oaep` and `rsassa-pss` are all RSA keys. Instead, use [`getKeyInfo(keyAlgorithm`]() to extract human friendly information about the key.
</details>
<details><summary><strong>keyData</strong></summary>
   
The key data object, containing the interpreted private key itself.

The data inside this object varies per key type. As an example, for RSA keys, this object contains `prime1`, `prime2`, `exponent1`, `exponent2`, and other properties that compose the key.

See [Key Data]() for a list of examples for all key types.
</details>
<details><summary><strong>encryptionAlgorithm</strong></summary>
  
The encryption algorithm used to decrypt the key or `null` if it was unencrypted.

See [Encryption Algorithms]() for a list all the supported encryption algorithms.
</details>


Available options:


| name | type | default | description |
| ---- | ---- | ------- | ----------- |
| format | string/Array | *all formats*  | Limit the parsing to one or more formats |
| password | string | | The password to use to decrypt the key |


### composePrivateKey(decomposedKey, [options])

Composes a private key from its decomposed parts.

```js
import { composePrivateKey } from 'crypto-key-parser';

const myPrivateKey = composePrivateKey({
    format: 'pkcs1-pem',
    keyAlgorithm: 'rsa',
    keyData: { ...},
    encryptionAlgorithm: 'aes128-cbc'
});
```


## Tests

```sh
$ npm test
$ npm test -- --watch # during development
```


## License

Released under the [MIT License](http://www.opensource.org/licenses/mit-license.php).
