import { encode as encodePem, decode as decodePem } from 'node-forge/lib/pem';
import { decomposePrivateKey as decomposeDerPrivateKey, composePrivateKey as composeDerPrivateKey } from './pkcs8-der';
import { binaryStringToUint8Array, uint8ArrayToBinaryString } from '../../util/binary';
import { InvalidInputKeyError } from '../../util/errors';

export const decomposePrivateKey = (pem, options) => {
    // Decode pem
    const pemStr = uint8ArrayToBinaryString(pem);

    let decodedPem;

    try {
        decodedPem = decodePem(pemStr)[0];
    } catch (err) {
        throw new InvalidInputKeyError('Failed to decode PKCS8 as PEM', { originalErr: err });
    }

    // Decompose key using `pkcs8-der`
    const pkcs8Key = binaryStringToUint8Array(decodedPem.body);
    const decomposedKey = decomposeDerPrivateKey(pkcs8Key, options);

    decomposedKey.format = 'pkcs8-pem';

    return decomposedKey;
};

export const composePrivateKey = (decomposedKey, options) => {
    // Compose key using `pkcs8-der`
    const pkcs8Key = composeDerPrivateKey(decomposedKey, options);

    // Encode pem
    const pem = {
        type: options.password ? 'ENCRYPTED PRIVATE KEY' : 'PRIVATE KEY',
        body: uint8ArrayToBinaryString(pkcs8Key),
    };

    return encodePem(pem).replace(/\r/g, '');
};
