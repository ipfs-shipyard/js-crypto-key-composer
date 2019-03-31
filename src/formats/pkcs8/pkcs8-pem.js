import { encode as encodePem, decode as decodePem } from 'node-forge/lib/pem';
import { decomposeKey as decomposePkc8DerKey, composeKey as composePkcs8DerKey } from './pkcs8-der';
import { binaryStringToUint8Array, uint8ArrayToBinaryString } from '../../util/binary';
import { InvalidInputKeyError } from '../../util/errors';

export const decomposeKey = (pem, options) => {
    const pemStr = uint8ArrayToBinaryString(pem);

    let decodedPem;

    try {
        decodedPem = decodePem(pemStr)[0];
    } catch (err) {
        throw new InvalidInputKeyError('Failed to decode PKCS8 as PEM');
    }

    const pkcs8Key = binaryStringToUint8Array(decodedPem.body);
    const decomposedKey = decomposePkc8DerKey(pkcs8Key, options);

    decomposedKey.format = 'pkcs8-pem';

    return decomposedKey;
};

export const composeKey = (decomposedKey, options) => {
    const pkcs8Key = composePkcs8DerKey(decomposedKey, options);

    const pem = {
        type: options.password ? 'ENCRYPTED PRIVATE KEY' : 'PRIVATE KEY',
        body: uint8ArrayToBinaryString(pkcs8Key),
    };

    return encodePem(pem).replace(/\r/g, '');
};
