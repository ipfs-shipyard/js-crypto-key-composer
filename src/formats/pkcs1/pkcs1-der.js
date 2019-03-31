import { decomposeRsaPrivateKey, composeRsaPrivateKey } from './keys';
import KEY_TYPES from '../../util/key-types';
import { UnsupportedAlgorithmError, DecodeAsn1FailedError, InvalidInputKeyError } from '../../util/errors';

export const decomposeKey = (rsaPrivateKeyAsn1) => {
    let decomposedRsaKey;

    try {
        decomposedRsaKey = decomposeRsaPrivateKey(rsaPrivateKeyAsn1);
    } catch (err) {
        if (err instanceof DecodeAsn1FailedError) {
            throw new InvalidInputKeyError(err.message, { originalError: err });
        }
    }

    const { keyAlgorithm, keyData } = decomposedRsaKey;

    return {
        format: 'pkcs1-der',
        encryptionAlgorithm: null,
        keyAlgorithm,
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

    return composeRsaPrivateKey(keyData);
};
