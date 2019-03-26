export const validateInputKey = (input) => {
    if (typeof input !== 'string' && !(input instanceof ArrayBuffer)) {
        throw Object.assign(
            new Error('Expecting input to be a string or an ArrayBuffer'),
            { code: 'INVALID_KEY' }
        );
    }

    return input;
};

export const validateFormat = (format, supportedFormats) => {
    if (!supportedFormats[format]) {
        throw Object.assign(
            new Error(`Unsupported format '${format}'`),
            { code: 'UNSUPPORTED_FORMAT' }
        );
    }

    return format;
};

export const validateFormats = (formats, supportedFormats) =>
    formats.map((format) => validateFormat(format, supportedFormats));

export const validateDecomposedKey = (decomposedKey, supportedFormats) => {
    if (!decomposedKey || typeof decomposedKey !== 'object') {
        throw Object.assign(
            new Error('Expecting decomposed key to be an object'),
            { code: 'INVALID_DECOMPOSED_KEY' }
        );
    }

    decomposedKey = { ...decomposedKey };
    decomposedKey.format = validateFormat(decomposedKey.format, supportedFormats);

    return decomposedKey;
};

export const validateAlgorithmIdentifier = (algorithmIdentifier, defaultId) => {
    if (!algorithmIdentifier || typeof obj === 'string') {
        algorithmIdentifier = { id: algorithmIdentifier };
    }

    if (typeof algorithmIdentifier !== 'object') {
        throw Object.assign(
            new Error('Expecting algorithm identifier to be an object'),
            { code: 'INVALID_ALGORITHM_IDENTIFIER' }
        );
    }

    algorithmIdentifier = { ...algorithmIdentifier };
    algorithmIdentifier.id = algorithmIdentifier.id || defaultId;

    if (typeof algorithmIdentifier.id !== 'string') {
        throw Object.assign(
            new Error('Expecting algorithm identifier id to be a string'),
            { code: 'INVALID_ALGORITHM_IDENTIFIER' }
        );
    }

    return algorithmIdentifier;
};
