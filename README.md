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

Parses a key, extracting information such as its format, key algorithm and encryption algorithm.

```js
import { decomposePrivateKey } from 'crypto-key-parser';

const myPemKey = '----------'

const myDecomposedKey = decomposePrivateKey(myPemKey)

// {
//     format: 'pkcs1-pem',
//     keyAlgorithm: {
//         type: 'rsaEncryption'
//         // ...
//     },
//     keyData,
//     encryptionAlgorithm: {
//         type: 'PBES2',
//         // ...
//     }
// }
```

Available options:


| name | type | default | description |
| ---- | ---- | ------- | ----------- |
| format | string/Array | *all formats*  | Limit the parsing to one or more formats |
| password | string | | The password to use if the key is encrypted |


### composePrivateKey(decomposedKey, [options])

Composes a private key from its decomposed parts.

```js
import { composePrivateKey } from 'crypto-key-parser';

const myPrivateKey = composePrivateKey({
    // ...
});
```


## Tests

```sh
$ npm test
$ npm test -- --watch # during development
```


## License

Released under the [MIT License](http://www.opensource.org/licenses/mit-license.php).
