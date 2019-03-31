import { pkcs1Der, pkcs1Pem, pkcs8Der, pkcs8Pem } from './formats';
import { validateInputKey, validateFormat, validateDecomposedKey } from './util/validator';
import { UnrecognizedInputKeyError, InvalidInputKeyError } from './util/errors';

const PRIVATE_FORMATS = {
    'pkcs1-pem': pkcs1Pem,
    'pkcs8-pem': pkcs8Pem,
    'pkcs1-der': pkcs1Der,
    'pkcs8-der': pkcs8Der,
};

// const PUBLIC_FORMATS = {
//     'pkcs1-pem': pkcs1Pem,
//     'pkcs8-pem': pkcs8Pem,
//     pkcs1,
//     pkcs8,
// };

const decomposeKey = (supportedFormats, inputKey, options) => {
    inputKey = validateInputKey(inputKey);
    options = {
        password: null,
        format: Object.keys(supportedFormats),
        ...options,
    };

    if (!Array.isArray(options.format)) {
        const format = validateFormat(options.format, supportedFormats);

        return supportedFormats[format].decomposeKey(inputKey, options);
    }

    const formats = options.format.map((format) => validateFormat(format, supportedFormats));

    // Attempt to decompose the keys, until one succeeds
    // Along the way, we collect the errors for each format
    const errors = {};
    let decomposeKey;

    for (let x = 0; x < formats.length; x += 1) {
        const format = formats[x];

        try {
            decomposeKey = supportedFormats[format].decomposeKey(inputKey, options);
            break;
        } catch (err) {
            // Skip If the error is a InvalidInputKeyError
            if (err instanceof InvalidInputKeyError) {
                errors[format] = err;
                continue;
            }

            err.format = format;
            throw err;
        }
    }

    if (!decomposeKey) {
        throw new UnrecognizedInputKeyError(errors);
    }

    return decomposeKey;
};

const composeKey = (supportedFormats, decomposedKey, options) => {
    options = {
        password: null,
        ...options,
    };

    decomposedKey = validateDecomposedKey(decomposedKey, supportedFormats);

    return supportedFormats[decomposedKey.format].composeKey(decomposedKey, options);
};

export const decomposePrivateKey = (inputKey, options) => decomposeKey(PRIVATE_FORMATS, inputKey, options);

// export const decomposePublicKey = (inputKey, options) => decomposeKey(PUBLIC_FORMATS, inputKey, options);

export const composePrivateKey = (decomposedKey, options) => composeKey(PRIVATE_FORMATS, decomposedKey, options);

// export const composePublicKey = (decomposedKey, options) => composeKey(PUBLIC_FORMATS, decomposedKey, options);
