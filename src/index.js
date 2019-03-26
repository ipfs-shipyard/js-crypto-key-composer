import { pkcs1, pkcs1Pem, pkcs8, pkcs8Pem } from './formats';
import { validateInputKey, validateFormat, validateFormats, validateDecomposedKey } from './util/validator';

const PRIVATE_FORMATS = {
    'pkcs1-pem': pkcs1Pem,
    'pkcs8-pem': pkcs8Pem,
    pkcs1,
    pkcs8,
};

const PUBLIC_FORMATS = {
    'pkcs1-pem': pkcs1Pem,
    'pkcs8-pem': pkcs8Pem,
    pkcs1,
    pkcs8,
};

const decomposeKey = (FORMATS, inputKey, options) => {
    inputKey = validateInputKey(inputKey);
    options = {
        password: null,
        format: Object.keys(FORMATS),
        ...options,
    };

    if (typeof options.format === 'string') {
        const format = validateFormat(options.format, FORMATS);

        return FORMATS[format].decomposeKey(inputKey, options);
    }

    // Check if any of the passed formats is invalid
    const formats = validateFormats(options.format, FORMATS);

    // Attempt to decompose the keys, until one succeeds
    // Along the way, we collect the errors for each format
    const errors = {};
    let decomposeKey;

    for (let x = 0; x < formats.length; x += 1) {
        const format = formats[x];

        try {
            decomposeKey = FORMATS[format].decomposeKey(inputKey, options);
            break;
        } catch (err) {
            errors[format] = err;

            // If the error code is present and is NOT `INVALID_INPUT`, it means that we were
            // able to recognize the key but some other error occurred
            if (err.code && err.code !== 'INVALID_KEY') {
                throw err;
            }
        }
    }

    if (!decomposeKey) {
        throw Object.assign(
            new Error('No compatible format was found for the given key'),
            { code: 'NO_COMPATIBLE_FORMAT', errors }
        );
    }

    return decomposeKey;
};

const composeKey = (FORMATS, decomposedKey, options) => {
    options = {
        password: null,
        ...options,
    };

    decomposedKey = validateDecomposedKey(decomposedKey, FORMATS);

    return FORMATS[decomposedKey.format].composeKey(decomposedKey, options);
};

export const decomposePrivateKey = (inputKey, options) => decomposeKey(PRIVATE_FORMATS, inputKey, options);

export const decomposePublicKey = (inputKey, options) => decomposeKey(PUBLIC_FORMATS, inputKey, options);

export const composePrivateKey = (decomposedKey, options) => composeKey(PRIVATE_FORMATS, decomposedKey, options);

export const composePublicKey = (decomposedKey, options) => composeKey(PUBLIC_FORMATS, decomposedKey, options);
