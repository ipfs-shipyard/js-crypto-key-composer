import { keyTypeFromAlgorithm } from '../../util/oid';
import { decodeAsn1, encodeAsn1, RSAPrivateKey } from '../../util/asn1';
import { integerFromArrayBuffer, binaryStringToArrayBuffer } from '../../util/binary';

export const decomposeKey = (rsaPrivateKeyAsn1) => {
    let rsaPrivateKey;

    try {
        rsaPrivateKey = decodeAsn1(rsaPrivateKeyAsn1, RSAPrivateKey);
    } catch (err) {
        throw Object.assign(
            new Error(err.message),
            { code: 'INVALID_KEY', originalError: err }
        );
    }

    const keyData = {
        ...rsaPrivateKey,
        // Versions and publicExponent small, so just transform them to numbers
        version: integerFromArrayBuffer(rsaPrivateKey.version),
        publicExponent: integerFromArrayBuffer(rsaPrivateKey.publicExponent),
    };

    return {
        format: 'pkcs1',
        keyAlgorithm: {
            id: 'rsaEncryption',
            parameters: binaryStringToArrayBuffer('0500'),
        },
        keyData,
        encryptionAlgorithm: null,
    };
};

export const composeKey = ({ keyAlgorithm, keyData }) => {
    const keyType = keyTypeFromAlgorithm(keyAlgorithm.id);

    if (keyType !== 'rsa') {
        throw Object.assign(
            new Error('The key algorithm id for PKCS1 must be one of RSA\'s'),
            { code: 'UNSUPPORTED_ALGORITHM' }
        );
    }

    return encodeAsn1(keyData, RSAPrivateKey);
};
