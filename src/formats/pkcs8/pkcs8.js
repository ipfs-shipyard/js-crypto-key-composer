import KEY_TYPES from './key-types';
import { maybeDecryptPrivateKeyInfo, encryptPrivateKeyInfo } from './encryption';
import { OIDS, FLIPPED_OIDS, keyTypeFromAlgorithm } from '../../util/oid';
import { decodeAsn1, encodeAsn1, PrivateKeyInfo } from '../../util/asn1';

export const decomposeKey = (maybeEncryptedPrivateKeyInfoAsn1, options) => {
    // Attempt to decrypt privateKeyInfoAsn1 as it might actually be a EncryptedPrivateKeyInfo
    const { privateKeyInfoAsn1, encryptionAlgorithm } = maybeDecryptPrivateKeyInfo(maybeEncryptedPrivateKeyInfoAsn1, options.password);

    // Attempt to decode as PrivateKeyInfo
    let privateKeyInfo;

    try {
        privateKeyInfo = decodeAsn1(privateKeyInfoAsn1, PrivateKeyInfo);
    } catch (err) {
        if (encryptionAlgorithm) {
            throw err;
        }

        throw Object.assign(
            new Error(err.message),
            { code: 'INVALID_KEY', originalError: err }
        );
    }

    // Identity the type of private key and check if we support it
    const keyType = keyTypeFromAlgorithm(privateKeyInfo.algorithm.id);

    if (!KEY_TYPES[keyType]) {
        throw Object.assign(
            new Error(`Unsupported key algorithm OID '${privateKeyInfo.algorithm.id}'`),
            { code: 'UNSUPPORTED_ALGORITHM' }
        );
    }

    // Parse the private key, now that we know its type
    const keyData = KEY_TYPES[keyType].toKeyData(privateKeyInfo.privateKey);

    return {
        format: 'pkcs8',
        keyAlgorithm: {
            ...privateKeyInfo.algorithm,
            id: OIDS[privateKeyInfo.algorithm.id],
        },
        keyData,
        encryptionAlgorithm,
    };
};

export const composeKey = ({ keyAlgorithm, keyData, encryptionAlgorithm }, options) => {
    // Identity the type of private key and check if we support it
    const keyAlgorithmOid = FLIPPED_OIDS[keyAlgorithm.id] || keyAlgorithm.id;
    const keyType = keyTypeFromAlgorithm(keyAlgorithm.id);

    if (!KEY_TYPES[keyType]) {
        throw Object.assign(
            new Error(`Unsupported key algorithm id '${keyAlgorithm.id}'`),
            { code: 'UNSUPPORTED_ALGORITHM' }
        );
    }

    // Generate the PrivateKey based on the key data
    const privateKey = KEY_TYPES[keyType].toPrivateKey(keyData);

    // Generate the PrivateKeyInfo
    const privateKeyInfo = {
        version: 0,
        algorithm: {
            ...keyAlgorithm,
            id: keyAlgorithmOid.split('.'),
        },
        privateKey,
    };

    let privateKeyInfoAsn1;

    try {
        privateKeyInfoAsn1 = encodeAsn1(privateKeyInfo, PrivateKeyInfo);
    } catch (err) {
        throw Object.assign(
            new Error('Unable to encode PrivateKeyInfo'),
            { code: 'INVALID_INPUT', originalError: err }
        );
    }

    // Do we need to encrypt as EncryptedPrivateKeyInfo?
    if (options.password) {
        privateKeyInfoAsn1 = encryptPrivateKeyInfo(encryptionAlgorithm, privateKeyInfoAsn1, options.password);
    }

    return privateKeyInfoAsn1;
};
