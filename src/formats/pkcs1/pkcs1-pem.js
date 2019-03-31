import { encode as encodePem, decode as decodePem } from 'node-forge/lib/pem';
import { maybeDecryptPemBody, maybeEncryptPemBody } from './encryption';
import { decomposeKey as decomposePkc1DerKey, composeKey as composePkcs1DerKey } from './pkcs1-der';
import { uint8ArrayToBinaryString } from '../../util/binary';
import { InvalidInputKeyError } from '../../util/errors';

export const decomposeKey = (pem, options) => {
    const pemStr = uint8ArrayToBinaryString(pem);

    let decodedPem;

    try {
        decodedPem = decodePem(pemStr)[0];
    } catch (err) {
        throw new InvalidInputKeyError('Failed to decode PKCS1 as PEM', { originalError: err });
    }

    const { pemBody: pkcs1Key, encryptionAlgorithm } = maybeDecryptPemBody(decodedPem, options.password);

    const decomposedKey = decomposePkc1DerKey(pkcs1Key, options);

    decomposedKey.encryptionAlgorithm = encryptionAlgorithm;
    decomposedKey.format = 'pkcs1-pem';

    return decomposedKey;
};

export const composeKey = ({ encryptionAlgorithm, ...decomposedKey }, options) => {
    const pkcs1Key = composePkcs1DerKey(decomposedKey, options);

    const { pemBody, pemHeaders } = maybeEncryptPemBody(pkcs1Key, encryptionAlgorithm, options.password);

    const pem = {
        type: 'RSA PRIVATE KEY',
        body: uint8ArrayToBinaryString(pemBody),
        ...pemHeaders,
    };

    return encodePem(pem).replace(/\r/g, '');
};
