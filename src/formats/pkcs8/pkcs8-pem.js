import { encode as encodePem, decode as decodePem } from 'node-forge/lib/pem';
import { decomposeKey as decomposePkc8Key, composeKey as composePkcs8Key } from './pkcs8';
import { binaryStringToArrayBuffer, arrayBufferToBinaryString } from '../../util/binary';

export const decomposeKey = (pemStr, options) => {
    if (typeof pemStr !== 'string') {
        throw Object.assign(
            new Error('The input for PKCS8-PEM must be a string'),
            { code: 'INVALID_INPUT' }
        );
    }

    let pem;

    try {
        pem = decodePem(pemStr)[0];
    } catch (err) {
        throw Object.assign(
            new Error('Failed to decode PKCS8 as PEM'),
            { code: 'INVALID_INPUT', originalError: err }
        );
    }

    const pkcs8Key = binaryStringToArrayBuffer(pem.body);
    const decomposedKey = decomposePkc8Key(pkcs8Key, options);

    decomposedKey.format = 'pkcs8-pem';

    return decomposedKey;
};

export const composeKey = (decomposedKey, options) => {
    const pkcs8Key = composePkcs8Key(decomposedKey, options);

    const pem = {
        type: options.password ? 'ENCRYPTED PRIVATE KEY' : 'PRIVATE KEY',
        body: arrayBufferToBinaryString(pkcs8Key),
    };

    return encodePem(pem).replace(/\r/g, '');
};
