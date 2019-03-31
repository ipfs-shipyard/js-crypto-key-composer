import { isPlainObject } from 'lodash';
import { binaryStringToUint8Array, typedArrayToUint8Array } from './binary';
import { KEY_ALIASES } from './key-types';
import { UnexpectedTypeError, UnsupportedFormatError } from './errors';

export const validateInputKey = (input) => {
    // Support strings
    if (typeof input === 'string') {
        return binaryStringToUint8Array(input);
    }
    // Support array buffer or typed arrays
    if (input instanceof ArrayBuffer) {
        return new Uint8Array(input);
    }
    if (ArrayBuffer.isView(input)) {
        return typedArrayToUint8Array(input);
    }

    throw new UnexpectedTypeError('Expecting input key to be one of: Uint8Array, ArrayBuffer, string');
};

export const validateFormat = (format, supportedFormats) => {
    if (typeof format !== 'string') {
        throw new UnexpectedTypeError('Expecting format to be a string');
    }
    if (!supportedFormats[format]) {
        throw new UnsupportedFormatError(format);
    }

    return format;
};

export const validateDecomposedKey = (decomposedKey, supportedFormats) => {
    if (!decomposedKey || !isPlainObject(decomposedKey)) {
        throw new UnexpectedTypeError('Expecting decomposed key to be an object');
    }

    const { format, keyAlgorithm, encryptionAlgorithm } = decomposedKey;

    decomposedKey = { ...decomposedKey };
    decomposedKey.format = validateFormat(format, supportedFormats);
    decomposedKey.keyAlgorithm = validateAlgorithmIdentifier(KEY_ALIASES[keyAlgorithm] || keyAlgorithm, 'key');

    if (!isPlainObject(decomposedKey.keyData)) {
        throw new UnexpectedTypeError('Expecting key data to be an object');
    }

    decomposedKey.encryptionAlgorithm = encryptionAlgorithm ? validateAlgorithmIdentifier(encryptionAlgorithm, 'encryption') : null;

    return decomposedKey;
};

export const validateAlgorithmIdentifier = (algorithmIdentifier, errorContext) => {
    if (typeof algorithmIdentifier === 'string') {
        algorithmIdentifier = { id: algorithmIdentifier };
    }

    if (!isPlainObject(algorithmIdentifier)) {
        throw new UnexpectedTypeError(`Expecting ${errorContext} algorithm to be an object`);
    }

    algorithmIdentifier = { ...algorithmIdentifier };

    if (typeof algorithmIdentifier.id !== 'string') {
        throw new UnexpectedTypeError(`Expecting ${errorContext} algorithm id to be a string`);
    }

    return algorithmIdentifier;
};
