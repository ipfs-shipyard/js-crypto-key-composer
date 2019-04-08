import { encode as encodePem, decode as decodePem } from 'node-forge/lib/pem';
import { maybeDecryptPemBody, maybeEncryptPemBody } from './encryption';
import { decomposeRawPrivateKey, composeRawPrivateKey, decomposeRawPublicKey, composeRawPublicKey } from './keys';
import { uint8ArrayToBinaryString, binaryStringToUint8Array } from '../../util/binary';
import { InvalidInputKeyError } from '../../util/errors';
import { KEY_TYPES } from '../../util/key-types';

const getKeyType = (pemType) => {
    const match = /^(\S+?) (PUBLIC|PRIVATE) KEY$/.exec(pemType);

    return match && match[1].toLocaleLowerCase();
};

const getPemType = (keyAlgorithm) => {
    const keyType = KEY_TYPES[keyAlgorithm.id];

    return keyType && keyType.toUpperCase();
};

export const decomposePrivateKey = (pem, options) => {
    // Decode pem
    const pemStr = uint8ArrayToBinaryString(pem);

    let decodedPem;

    try {
        decodedPem = decodePem(pemStr)[0];
    } catch (err) {
        throw new InvalidInputKeyError('Failed to decode RAW as PEM', { originalError: err });
    }

    // Decrypt pem if encrypted
    const { pemBody, encryptionAlgorithm } = maybeDecryptPemBody(decodedPem, options.password);

    // Extract the key type from it
    const keyType = getKeyType(decodedPem.type);

    if (!keyType) {
        throw new InvalidInputKeyError('Unable to extract key type from PEM');
    }

    // Finally decompose the key within it
    const { keyAlgorithm, keyData } = decomposeRawPrivateKey(keyType, pemBody);

    return {
        format: 'raw-pem',
        keyAlgorithm,
        keyData,
        encryptionAlgorithm,
    };
};

export const composePrivateKey = ({ keyAlgorithm, keyData, encryptionAlgorithm }, options) => {
    // Compose the key
    const rawKey = composeRawPrivateKey(keyAlgorithm, keyData);

    // Extract the pem type
    const pemKeyType = getPemType(keyAlgorithm);

    // Encrypt pem if password was specified
    const { pemBody, pemHeaders } = maybeEncryptPemBody(rawKey, encryptionAlgorithm, options.password);

    // Finally build pem
    const pem = {
        type: `${pemKeyType} PRIVATE KEY`,
        body: uint8ArrayToBinaryString(pemBody),
        ...pemHeaders,
    };

    return encodePem(pem).replace(/\r/g, '');
};

export const decomposePublicKey = (pem) => {
    // Decode pem
    const pemStr = uint8ArrayToBinaryString(pem);

    let decodedPem;

    try {
        decodedPem = decodePem(pemStr)[0];
    } catch (err) {
        throw new InvalidInputKeyError('Failed to decode RAW as PEM', { originalError: err });
    }

    // Extract the key type from it
    const keyType = getKeyType(decodedPem.type);

    if (!keyType) {
        throw new InvalidInputKeyError('Unable to extract key type from PEM');
    }

    // Finally decompose the key within it
    const pemBody = binaryStringToUint8Array(decodedPem.body);
    const { keyAlgorithm, keyData } = decomposeRawPublicKey(keyType, pemBody);

    return {
        format: 'raw-pem',
        keyAlgorithm,
        keyData,
    };
};

export const composePublicKey = ({ keyAlgorithm, keyData }) => {
    // Compose the key
    const rawKey = composeRawPublicKey(keyAlgorithm, keyData);

    // Extract the pem type
    const pemKeyType = getPemType(keyAlgorithm);

    if (!pemKeyType) {
        throw new InvalidInputKeyError('Unable to extract pem type from key algorithm');
    }

    // Finally build pem
    const pem = {
        type: `${pemKeyType} PUBLIC KEY`,
        body: uint8ArrayToBinaryString(rawKey),
    };

    return encodePem(pem).replace(/\r/g, '');
};
