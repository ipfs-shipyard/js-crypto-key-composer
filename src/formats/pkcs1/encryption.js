import {
    createOpenSslKeyDeriver,
    createAesDecrypter, createAesEncrypter,
    createDesDecrypter, createDesEncrypter,
    createRc2Decrypter, createRc2Encrypter,
} from '../../util/pbe';
import { binaryStringToUint8Array, hexStringToUint8Array, uint8ArrayToHexString } from '../../util/binary';
import { validateAlgorithmIdentifier } from '../../util/validator';
import { UnsupportedAlgorithmError, MissingPasswordError } from '../../util/errors';
import randomBytes from '../../util/random';

const decryptPemBody = (pem, password) => {
    if (!password) {
        throw new MissingPasswordError('Please specify the password to decrypt the key');
    }

    let derivedKeyLength;
    let decryptFn;

    let encryptionAlgorithmId;
    const encryptionAlgorithmParams = { iv: hexStringToUint8Array(pem.dekInfo.parameters) };

    switch (pem.dekInfo.algorithm) {
    case 'AES-128-CBC':
        encryptionAlgorithmId = 'aes128-cbc';
        derivedKeyLength = 16;
        decryptFn = createAesDecrypter(encryptionAlgorithmParams);
        break;
    case 'AES-192-CBC':
        encryptionAlgorithmId = 'aes192-cbc';
        derivedKeyLength = 24;
        decryptFn = createAesDecrypter(encryptionAlgorithmParams);
        break;
    case 'AES-256-CBC':
        encryptionAlgorithmId = 'aes256-cbc';
        derivedKeyLength = 32;
        decryptFn = createAesDecrypter(encryptionAlgorithmParams);
        break;
    case 'RC2-40-CBC':
        encryptionAlgorithmId = 'rc2-cbc';
        encryptionAlgorithmParams.bits = 40;
        derivedKeyLength = 5;
        decryptFn = createRc2Decrypter(encryptionAlgorithmParams);
        break;
    case 'RC2-64-CBC':
        encryptionAlgorithmId = 'rc2-cbc';
        encryptionAlgorithmParams.bits = 64;
        derivedKeyLength = 8;
        decryptFn = createRc2Decrypter(encryptionAlgorithmParams);
        break;
    case 'RC2-128-CBC':
    case 'RC2-CBC':
        encryptionAlgorithmId = 'rc2-cbc';
        encryptionAlgorithmParams.bits = 128;
        derivedKeyLength = 16;
        decryptFn = createRc2Decrypter(encryptionAlgorithmParams);
        break;
    case 'DES-CBC':
        encryptionAlgorithmId = 'des-cbc';
        derivedKeyLength = 8;
        decryptFn = createDesDecrypter(encryptionAlgorithmParams);
        break;
    case 'DES-EDE3-CBC':
        encryptionAlgorithmId = 'des-ede3-cbc';
        derivedKeyLength = 24;
        decryptFn = createDesDecrypter(encryptionAlgorithmParams);
        break;
    default:
        throw new UnsupportedAlgorithmError(`Unsupported DEK-INFO algorithm '${pem.dekInfo.algorithm}'`);
    }

    // Use OpenSSL legacy key derivation
    const deriveKeyFn = createOpenSslKeyDeriver({
        salt: encryptionAlgorithmParams.iv.slice(0, 8),
        keyLength: derivedKeyLength,
    });

    const derivedKey = deriveKeyFn(password);
    const decryptedPemBody = decryptFn(derivedKey, binaryStringToUint8Array(pem.body));

    return {
        encryptionAlgorithm: {
            id: encryptionAlgorithmId,
            ...encryptionAlgorithmParams,
        },
        pemBody: decryptedPemBody,
    };
};

const encryptPemBody = (pemBody, encryptionAlgorithm, password) => {
    encryptionAlgorithm = validateAlgorithmIdentifier(encryptionAlgorithm || 'aes256-cbc', 'encryption');

    let derivedKeyLength;
    let iv;
    let encryptFn;

    let dekInfoAlgorithm;

    switch (encryptionAlgorithm.id) {
    case 'aes128-cbc':
        dekInfoAlgorithm = 'AES-128-CBC';
        derivedKeyLength = 16;
        iv = encryptionAlgorithm.iv || randomBytes(16);
        encryptFn = createAesEncrypter({ iv });
        break;
    case 'aes192-cbc':
        dekInfoAlgorithm = 'AES-192-CBC';
        derivedKeyLength = 24;
        iv = encryptionAlgorithm.iv || randomBytes(16);
        encryptFn = createAesEncrypter({ iv });
        break;
    case 'aes256-cbc':
        dekInfoAlgorithm = 'AES-256-CBC';
        derivedKeyLength = 32;
        iv = encryptionAlgorithm.iv || randomBytes(16);
        encryptFn = createAesEncrypter({ iv });
        break;
    case 'rc2-cbc': {
        const bits = encryptionAlgorithm.bits || 128;

        iv = encryptionAlgorithm.iv || randomBytes(8);

        // RC2-CBCParameter encoding of the "effective key bits" as defined in:
        // https://tools.ietf.org/html/rfc2898#appendix-B.2.3
        switch (bits) {
        case 40:
            dekInfoAlgorithm = 'RC2-40-CBC';
            derivedKeyLength = 5;
            break;
        case 64:
            dekInfoAlgorithm = 'RC2-64-CBC';
            derivedKeyLength = 8;
            break;
        case 128:
            dekInfoAlgorithm = 'RC2-CBC';
            derivedKeyLength = 16;
            break;
        default:
            throw new UnsupportedAlgorithmError(`Unsupported RC2 bits parameter with value '${bits}'`);
        }

        encryptFn = createRc2Encrypter({ iv, bits });

        break;
    }
    case 'des-cbc':
        dekInfoAlgorithm = 'DES-CBC';
        derivedKeyLength = 8;
        iv = encryptionAlgorithm.iv || randomBytes(8);
        encryptFn = createDesEncrypter({ iv });
        break;
    case 'des-ede3-cbc':
        dekInfoAlgorithm = 'DES-EDE3-CBC';
        derivedKeyLength = 24;
        iv = encryptionAlgorithm.iv || randomBytes(8);
        encryptFn = createDesEncrypter({ iv });
        break;
    default:
        throw new UnsupportedAlgorithmError(`Unsupported encryption algorithm id '${encryptionAlgorithm.id}'`);
    }

    // Use OpenSSL legacy key derivation
    const deriveKeyFn = createOpenSslKeyDeriver({
        salt: iv.slice(0, 8),
        keyLength: derivedKeyLength,
    });

    const derivedKey = deriveKeyFn(password);
    const encryptedPemBody = encryptFn(derivedKey, pemBody);

    return {
        pemHeaders: {
            procType: { version: '4', type: 'ENCRYPTED' },
            dekInfo: {
                algorithm: dekInfoAlgorithm,
                parameters: uint8ArrayToHexString(iv).toUpperCase(),
            },
        },
        pemBody: encryptedPemBody,
    };
};

export const maybeDecryptPemBody = (pem, password) => {
    const encrypted = pem.procType && pem.procType.type === 'ENCRYPTED' && pem.dekInfo && pem.dekInfo.algorithm;

    return encrypted ?
        decryptPemBody(pem, password) :
        { pemBody: binaryStringToUint8Array(pem.body), encryptionAlgorithm: null };
};

export const maybeEncryptPemBody = (pemBody, encryptionAlgorithm, password) => {
    if (!password && !encryptionAlgorithm) {
        return {
            pemHeaders: null,
            pemBody,
        };
    }

    if (!password && encryptionAlgorithm) {
        throw new MissingPasswordError('An encryption algorithm was specified but no password was set');
    }

    return encryptPemBody(pemBody, encryptionAlgorithm, password);
};
