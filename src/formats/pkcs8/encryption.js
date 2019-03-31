import { OIDS, FLIPPED_OIDS } from './oids';
import { EncryptedPrivateKeyInfo, PBES2Algorithms, PBKDF2params, PBES2ESParams, RC2CBCParameter } from './asn1-entities';
import {
    createPbkdf2KeyDeriver,
    createAesDecrypter, createAesEncrypter,
    createDesDecrypter, createDesEncrypter,
    createRc2Decrypter, createRc2Encrypter,
} from '../../util/pbe';
import { decodeAsn1, encodeAsn1 } from '../../util/asn1';
import { uint8ArrayToInteger, hexStringToUint8Array } from '../../util/binary';
import { UnsupportedAlgorithmError, DecodeAsn1FailedError, MissingPasswordError } from '../../util/errors';
import { validateAlgorithmIdentifier } from '../../util/validator';
import randomBytes from '../../util/random';

export const decryptWithPBES2 = (encryptedData, encryptionAlgorithmParamsAsn1, password) => {
    const { keyDerivationFunc, encryptionScheme } = decodeAsn1(encryptionAlgorithmParamsAsn1, PBES2Algorithms);

    let deriveKeyFn;
    let derivedKeyLength;
    let decryptFn;

    const encryptionSchemeId = OIDS[encryptionScheme.id];
    const keyDerivationFuncId = OIDS[keyDerivationFunc.id];
    let encryptionSchemeParams;
    let keyDerivationParams;

    // Process encryption scheme
    switch (encryptionSchemeId) {
    case 'aes128-cbc':
    case 'aes192-cbc':
    case 'aes256-cbc':
        derivedKeyLength = Number(encryptionSchemeId.match(/^aes(\d+)-/)[1]) / 8;
        encryptionSchemeParams = { iv: decodeAsn1(encryptionScheme.parameters, PBES2ESParams[encryptionSchemeId]) };
        decryptFn = createAesDecrypter({ ...encryptionSchemeParams, mode: 'CBC' });
        break;
    case 'rc2-cbc': {
        const rc2CBCParameter = decodeAsn1(encryptionScheme.parameters, RC2CBCParameter);
        const rc2ParameterVersion = uint8ArrayToInteger(rc2CBCParameter.rc2ParameterVersion);

        encryptionSchemeParams = { iv: rc2CBCParameter.iv };

        // RC2-CBCParameter encoding of the "effective key bits" as defined in:
        // https://tools.ietf.org/html/rfc2898#appendix-B.2.3
        switch (rc2ParameterVersion) {
        case 160:
            derivedKeyLength = 5;
            encryptionSchemeParams.bits = 40;
            break;
        case 120:
            derivedKeyLength = 8;
            encryptionSchemeParams.bits = 64;
            break;
        case 58:
            derivedKeyLength = 16;
            encryptionSchemeParams.bits = 128;
            break;
        default:
            throw new UnsupportedAlgorithmError(`Unsupported RC2 version parameter with value '${rc2ParameterVersion}'`);
        }

        decryptFn = createRc2Decrypter(encryptionSchemeParams);

        break;
    }
    case 'des-ede3-cbc':
        derivedKeyLength = 24;
        encryptionSchemeParams = { iv: decodeAsn1(encryptionScheme.parameters, PBES2ESParams['des-ede3-cbc']) };
        decryptFn = createDesDecrypter({ ...encryptionSchemeParams, mode: 'CBC' });
        break;
    case 'des-cbc':
        derivedKeyLength = 8;
        encryptionSchemeParams = { iv: decodeAsn1(encryptionScheme.parameters, PBES2ESParams['des-cbc']) };
        decryptFn = createDesDecrypter({ ...encryptionSchemeParams, mode: 'CBC' });
        break;
    default:
        throw new UnsupportedAlgorithmError(`Unsupported encryption scheme algorithm OID '${encryptionScheme.id}'`);
    }

    // Process key derivation func
    switch (keyDerivationFuncId) {
    case 'pbkdf2': {
        const pbkdf2Params = decodeAsn1(keyDerivationFunc.parameters, PBKDF2params);
        const prfId = OIDS[pbkdf2Params.prf.id];

        if (pbkdf2Params.salt.type !== 'specified') {
            throw new UnsupportedAlgorithmError('Only \'specified\' salts are supported in PBKDF2');
        }

        if (!prfId) {
            throw new UnsupportedAlgorithmError(`Unsupported prf algorithm OID '${pbkdf2Params.prf.id}'`);
        }

        keyDerivationParams = {
            salt: pbkdf2Params.salt.value,
            iterationCount: uint8ArrayToInteger(pbkdf2Params.iterationCount),
            ...(pbkdf2Params.keyLength ? { keyLength: uint8ArrayToInteger(pbkdf2Params.keyLength) } : {}),
            prf: prfId,
        };

        deriveKeyFn = createPbkdf2KeyDeriver({
            keyLength: derivedKeyLength,
            ...keyDerivationParams,
        });
        break;
    }
    default:
        throw new UnsupportedAlgorithmError(`Unsupported key derivation function algorithm OID '${keyDerivationFunc.id}'`);
    }

    const derivedKey = deriveKeyFn(password);
    const decryptedData = decryptFn(derivedKey, encryptedData);

    return {
        encryptionAlgorithmParams: {
            keyDerivationFunc: { id: keyDerivationFuncId, ...keyDerivationParams },
            encryptionScheme: { id: encryptionSchemeId, ...encryptionSchemeParams },
        },
        decryptedData,
    };
};

export const encryptWithPBES2 = (data, encryptionAlgorithmParams, password) => {
    let { keyDerivationFunc, encryptionScheme } = encryptionAlgorithmParams;

    keyDerivationFunc = validateAlgorithmIdentifier(keyDerivationFunc || 'pbkdf2', 'key derivation func ');
    encryptionScheme = validateAlgorithmIdentifier(encryptionScheme || 'aes256-cbc', 'encryption scheme');

    let deriveKeyFn;
    let derivedKeyLength;
    let encryptFn;

    let keyDerivationFuncParamsAsn1;
    let encryptionSchemeParamsAsn1;

    // Process encryption scheme
    switch (encryptionScheme.id) {
    case 'aes128-cbc':
    case 'aes192-cbc':
    case 'aes256-cbc': {
        const iv = encryptionScheme.iv || randomBytes(16);

        derivedKeyLength = Number(encryptionScheme.id.match(/^aes(\d+)-/)[1]) / 8;
        encryptFn = createAesEncrypter({ iv });
        encryptionSchemeParamsAsn1 = encodeAsn1(iv, PBES2ESParams[encryptionScheme.id]);
        break;
    }
    case 'rc2-cbc': {
        const bits = encryptionScheme.bits || 128;
        const iv = encryptionScheme.iv || randomBytes(16);

        let rc2ParameterVersion;

        // RC2-CBCParameter encoding of the "effective key bits" as defined in:
        // https://tools.ietf.org/html/rfc2898#appendix-B.2.3
        switch (bits) {
        case 40:
            derivedKeyLength = 5;
            rc2ParameterVersion = 160;
            break;
        case 64:
            derivedKeyLength = 8;
            rc2ParameterVersion = 120;
            break;
        case 128:
            derivedKeyLength = 16;
            rc2ParameterVersion = 58;
            break;
        default:
            throw new UnsupportedAlgorithmError(`Unsupported RC2 bits parameter with value '${bits}'`);
        }

        encryptionSchemeParamsAsn1 = encodeAsn1({ iv, rc2ParameterVersion }, RC2CBCParameter);
        encryptFn = createRc2Encrypter({ iv, bits });

        break;
    }
    case 'des-ede3-cbc': {
        const iv = encryptionScheme.iv || randomBytes(8);

        derivedKeyLength = 24;
        encryptFn = createDesEncrypter({ iv });
        encryptionSchemeParamsAsn1 = encodeAsn1(iv, PBES2ESParams['des-ede3-cbc']);
        break;
    }
    case 'des-cbc': {
        const iv = encryptionScheme.iv || randomBytes(8);

        derivedKeyLength = 8;
        encryptFn = createDesEncrypter({ iv });
        encryptionSchemeParamsAsn1 = encodeAsn1(iv, PBES2ESParams['des-cbc']);
        break;
    }
    default:
        throw new UnsupportedAlgorithmError(`Unsupported encryption scheme id '${encryptionScheme.id}'`);
    }

    // Process key derivation name
    switch (keyDerivationFunc.id) {
    case 'pbkdf2': {
        const salt = keyDerivationFunc.salt || randomBytes(16);
        const iterationCount = keyDerivationFunc.iterationCount || 10000;
        const keyLength = keyDerivationFunc.keyLength || derivedKeyLength;
        const prf = keyDerivationFunc.prf || 'hmac-with-sha512';

        deriveKeyFn = createPbkdf2KeyDeriver({
            salt,
            iterationCount,
            keyLength,
            prf,
        });

        keyDerivationFuncParamsAsn1 = encodeAsn1({
            salt: { type: 'specified', value: salt },
            iterationCount,
            keyLength: keyDerivationFunc.keyLength,
            prf: {
                id: FLIPPED_OIDS[prf],
                parameters: hexStringToUint8Array('0500'),
            },
        }, PBKDF2params);

        break;
    }
    default:
        throw new UnsupportedAlgorithmError(`Unsupported key derivation function id '${keyDerivationFunc.id}'`);
    }

    const derivedKey = deriveKeyFn(password);
    const encryptedData = encryptFn(derivedKey, data);

    const encryptionAlgorithmParamsAsn1 = encodeAsn1({
        keyDerivationFunc: {
            id: FLIPPED_OIDS[keyDerivationFunc.id],
            parameters: keyDerivationFuncParamsAsn1,
        },
        encryptionScheme: {
            id: FLIPPED_OIDS[encryptionScheme.id],
            parameters: encryptionSchemeParamsAsn1,
        },
    }, PBES2Algorithms);

    return {
        encryptionAlgorithmParamsAsn1,
        encryptedData,
    };
};

const decryptPrivateKeyInfo = (encryptedPrivateKeyInfoAsn1, password) => {
    const { encryptionAlgorithm, encryptedData } = decodeAsn1(encryptedPrivateKeyInfoAsn1, EncryptedPrivateKeyInfo);
    const encryptionAlgorithmParamsAsn1 = encryptionAlgorithm.parameters;

    if (!password) {
        throw new MissingPasswordError('Please specify the password to decrypt the key');
    }

    const encryptionAlgorithmId = OIDS[encryptionAlgorithm.id];

    let decryptionResult;

    switch (encryptionAlgorithmId) {
    case 'pbes2':
        decryptionResult = decryptWithPBES2(encryptedData, encryptionAlgorithmParamsAsn1, password);
        break;
    default:
        throw new UnsupportedAlgorithmError(`Unsupported encryption algorithm OID '${encryptionAlgorithm.id}'`);
    }

    const { encryptionAlgorithmParams, decryptedData } = decryptionResult;

    return {
        encryptionAlgorithm: {
            id: encryptionAlgorithmId,
            ...encryptionAlgorithmParams,
        },
        privateKeyInfoAsn1: decryptedData,
    };
};

const encryptPrivateKeyInfo = (privateKeyInfoAsn1, encryptionAlgorithm, password) => {
    const { id: encryptionAlgorithmId, ...encryptionAlgorithmParams } = encryptionAlgorithm || { id: 'pbes2' };

    let encryptionResult;

    switch (encryptionAlgorithmId) {
    case 'pbes2':
        encryptionResult = encryptWithPBES2(privateKeyInfoAsn1, encryptionAlgorithmParams, password);
        break;
    default:
        throw new UnsupportedAlgorithmError(`Unsupported encryption algorithm id '${encryptionAlgorithmId}'`);
    }

    const { encryptedData, encryptionAlgorithmParamsAsn1 } = encryptionResult;

    const encryptedPrivateKeyInfoAsn1 = encodeAsn1({
        encryptionAlgorithm: {
            id: FLIPPED_OIDS[encryptionAlgorithmId],
            parameters: encryptionAlgorithmParamsAsn1,
        },
        encryptedData,
    }, EncryptedPrivateKeyInfo);

    return encryptedPrivateKeyInfoAsn1;
};

export const maybeDecryptPrivateKeyInfo = (encryptedPrivateKeyInfoAsn1, password) => {
    try {
        return decryptPrivateKeyInfo(encryptedPrivateKeyInfoAsn1, password);
    } catch (err) {
        if (err instanceof DecodeAsn1FailedError && err.modelName === 'EncryptedPrivateKeyInfo') {
            return {
                encryptionAlgorithm: null,
                privateKeyInfoAsn1: encryptedPrivateKeyInfoAsn1,
            };
        }

        throw err;
    }
};

export const maybeEncryptPrivateKeyInfo = (privateKeyInfoAsn1, encryptionAlgorithm, password) => {
    if (!password && !encryptionAlgorithm) {
        return privateKeyInfoAsn1;
    }

    if (!password && encryptionAlgorithm) {
        throw new MissingPasswordError('An encryption algorithm was specified but no password was set');
    }

    return encryptPrivateKeyInfo(privateKeyInfoAsn1, encryptionAlgorithm, password);
};

