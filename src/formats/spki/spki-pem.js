import { encode as encodePem, decode as decodePem } from 'node-forge/lib/pem';
import { decomposeKey as decomposeSpkiDerKey, composeKey as composeSpkiDerKey } from './spki-der';
import { binaryStringToUint8Array, uint8ArrayToBinaryString } from '../../util/binary';
import { InvalidInputKeyError } from '../../util/errors';

export const decomposeKey = (pem, options) => {
    const pemStr = uint8ArrayToBinaryString(pem);

    let decodedPem;

    try {
        decodedPem = decodePem(pemStr)[0];
    } catch (err) {
        throw new InvalidInputKeyError('Failed to decode SPKI as PEM', { originalErr: err });
    }

    const spkiKey = binaryStringToUint8Array(decodedPem.body);
    const decomposedKey = decomposeSpkiDerKey(spkiKey, options);

    decomposedKey.format = 'spki-pem';

    return decomposedKey;
};

export const composeKey = (decomposedKey, options) => {
    const spkiKey = composeSpkiDerKey(decomposedKey, options);

    const pem = {
        type: 'PUBLIC KEY',
        body: uint8ArrayToBinaryString(spkiKey),
    };

    return encodePem(pem).replace(/\r/g, '');
};
