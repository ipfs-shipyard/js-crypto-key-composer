import { RSAPrivateKey } from './asn1-entities';
import KEY_TYPES from '../../util/key-types';
import { decodeAsn1, encodeAsn1 } from '../../util/asn1';
import { uint8ArrayToInteger } from '../../util/binary';
import { InvalidInputKeyError, UnsupportedAlgorithmError } from '../../util/errors';

export const decomposeKey = (rsaPrivateKeyAsn1) => {
    let rsaPrivateKey;

    try {
        rsaPrivateKey = decodeAsn1(rsaPrivateKeyAsn1, RSAPrivateKey);
    } catch (err) {
        throw new InvalidInputKeyError(err.message, { originalError: err.originalError });
    }

    const keyData = {
        ...rsaPrivateKey,
        // Versions and publicExponent small, so just transform them to numbers
        version: uint8ArrayToInteger(rsaPrivateKey.version),
        publicExponent: uint8ArrayToInteger(rsaPrivateKey.publicExponent),
    };

    return {
        format: 'pkcs1-der',
        encryptionAlgorithm: null,
        keyAlgorithm: {
            id: 'rsa-encryption',
        },
        keyData,
    };
};

export const composeKey = ({ keyAlgorithm, keyData, encryptionAlgorithm }) => {
    const keyType = KEY_TYPES[keyAlgorithm.id];

    if (keyType !== 'rsa') {
        throw new UnsupportedAlgorithmError('The key algorithm id for PKCS1 must be one of RSA\'s');
    }

    if (encryptionAlgorithm) {
        throw new UnsupportedAlgorithmError('PKCS1 keys do not support any kind of encryption');
    }

    return encodeAsn1(keyData, RSAPrivateKey);
};
