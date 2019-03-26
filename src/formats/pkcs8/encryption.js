import { OIDS, FLIPPED_OIDS } from '../../util/oid';
import { createPbkdf2, createAesDecrypter, createAesEncrypter, createDesDecrypter, createDesEncrypter } from '../../util/encryption';
import { decodeAsn1, encodeAsn1, EncryptedPrivateKeyInfo, PBES2Algorithms, PBKDF2params, PBES2ESParams } from '../../util/asn1';
import { integerFromArrayBuffer, hexStringToArrayBuffer } from '../../util/binary';
import randomBytes from '../../util/random';

export const decryptWithPBES2 = (encryptionAlgorithmParamsAsn1, encryptedData, password) => {
    const { keyDerivationFunc, encryptionScheme } = decodeAsn1(encryptionAlgorithmParamsAsn1, PBES2Algorithms);

    let deriveKeyFn;
    let derivedKeyLength;
    let decryptFn;

    const encryptionSchemeName = OIDS[encryptionScheme.id];
    const keyDerivationFuncName = OIDS[keyDerivationFunc.id];
    let encryptionSchemeParams;
    let keyDerivationParams;

    // Process encryption scheme
    switch (encryptionSchemeName) {
    case 'aes128-CBC':
    case 'aes192-CBC':
    case 'aes256-CBC':
        derivedKeyLength = Number(encryptionSchemeName.match(/^aes(\d+)-/)[1]) / 8;
        encryptionSchemeParams = { iv: decodeAsn1(encryptionScheme.parameters, PBES2ESParams[encryptionSchemeName]) };
        decryptFn = createAesDecrypter({ ...encryptionSchemeParams, mode: 'CBC' });
        break;
    case 'des-EDE3-CBC':
        derivedKeyLength = 24;
        encryptionSchemeParams = { iv: decodeAsn1(encryptionScheme.parameters, PBES2ESParams['des-EDE3-CBC']) };
        decryptFn = createDesDecrypter({ ...encryptionSchemeParams, mode: 'CBC' });
        break;
    case 'desCBC':
        derivedKeyLength = 8;
        encryptionSchemeParams = { iv: decodeAsn1(encryptionScheme.parameters, PBES2ESParams.desCB) };
        decryptFn = createDesDecrypter({ ...encryptionSchemeParams, mode: 'CBC' });
        break;
    default:
        throw Object.assign(
            new Error(`Unsupported encryption scheme OID '${encryptionScheme.id}'`),
            { code: 'UNSUPPORTED_ALGORITHM' }
        );
    }

    // Process key derivation name
    switch (keyDerivationFuncName) {
    case 'PBKDF2': {
        const pbkdf2Params = decodeAsn1(keyDerivationFunc.parameters, PBKDF2params);

        keyDerivationParams = {
            salt: pbkdf2Params.salt,
            iterationCount: integerFromArrayBuffer(pbkdf2Params.iterationCount),
            ...(pbkdf2Params.keyLength ? { keyLength: integerFromArrayBuffer(pbkdf2Params.keyLength) } : {}),
            prf: OIDS[pbkdf2Params.prf.id],
        };

        deriveKeyFn = createPbkdf2({
            keyLength: derivedKeyLength,
            ...keyDerivationParams,
        });
        break;
    }
    default:
        throw Object.assign(
            new Error(`Unsupported key derivation function OID '${keyDerivationFunc.id}'`),
            { code: 'UNSUPPORTED_ALGORITHM' }
        );
    }

    const derivedKey = deriveKeyFn(password);
    const decryptedData = decryptFn(derivedKey, encryptedData);

    return {
        encryptionAlgorithmParams: {
            keyDerivationFunc: { id: keyDerivationFuncName, ...keyDerivationParams },
            encryptionScheme: { id: encryptionSchemeName, ...encryptionSchemeParams },
        },
        decryptedData,
    };
};

export const encryptWithPBES2 = (encryptionAlgorithmParams, data, password) => {
    const { keyDerivationFunc, encryptionScheme } = encryptionAlgorithmParams;

    let deriveKeyFn;
    let derivedKeyLength;
    let encryptFn;

    const encryptionSchemeName = OIDS[encryptionScheme.id] || encryptionScheme.id;
    const keyDerivationFuncName = OIDS[keyDerivationFunc.id] || keyDerivationFunc.id;
    let keyDerivationFuncParamsAsn1;
    let encryptionSchemeParamsAsn1;

    // Process encryption scheme
    switch (encryptionSchemeName) {
    case 'aes128-CBC':
    case 'aes192-CBC':
    case 'aes256-CBC': {
        const iv = encryptionScheme.iv || randomBytes(16);

        derivedKeyLength = Number(encryptionSchemeName.match(/^aes(\d+)-/)[1]) / 8;
        encryptFn = createAesEncrypter({ iv });
        encryptionSchemeParamsAsn1 = encodeAsn1(iv, PBES2ESParams[encryptionSchemeName]);
        break;
    }
    case 'des-EDE3-CBC': {
        const iv = encryptionScheme.iv || randomBytes(8);

        derivedKeyLength = 24;
        encryptFn = createDesEncrypter({ iv });
        encryptionSchemeParamsAsn1 = encodeAsn1(iv, PBES2ESParams['des-EDE3-CBC']);
        break;
    }
    case 'desCBC': {
        const iv = encryptionScheme.iv || randomBytes(8);

        derivedKeyLength = 8;
        encryptFn = createDesEncrypter({ iv });
        encryptionSchemeParamsAsn1 = encodeAsn1(iv, PBES2ESParams.desCBC);
        break;
    }
    default:
        throw Object.assign(
            new Error(`Unsupported encryption scheme OID '${encryptionScheme.id}'`),
            { code: 'UNSUPPORTED_ALGORITHM' }
        );
    }

    // Process key derivation name
    switch (keyDerivationFuncName) {
    case 'PBKDF2': {
        const salt = keyDerivationFunc.salt || randomBytes(8);

        keyDerivationFuncParamsAsn1 = encodeAsn1({
            salt,
            iterationCount: keyDerivationFunc.iterationCount,
            keyLength: keyDerivationFunc.keyLength,
            prf: {
                id: FLIPPED_OIDS[keyDerivationFunc.prf] || keyDerivationFunc.prf,
                parameters: hexStringToArrayBuffer('0500'),
            },
        }, PBKDF2params);

        deriveKeyFn = createPbkdf2({
            salt,
            iterationCount: keyDerivationFunc.iterationCount,
            keyLength: keyDerivationFunc.keyLength || derivedKeyLength,
            prf: OIDS[keyDerivationFunc.prf] || keyDerivationFunc.prf,
        });
        break;
    }
    default:
        throw Object.assign(
            new Error(`Unsupported key derivation function OID '${keyDerivationFunc.id}'`),
            { code: 'UNSUPPORTED_ALGORITHM' }
        );
    }

    const derivedKey = deriveKeyFn(password);
    const encryptedData = encryptFn(derivedKey, data);

    const encryptionAlgorithmParamsAsn1 = encodeAsn1({
        keyDerivationFunc: {
            id: FLIPPED_OIDS[keyDerivationFuncName],
            parameters: keyDerivationFuncParamsAsn1,
        },
        encryptionScheme: {
            id: FLIPPED_OIDS[encryptionSchemeName],
            parameters: encryptionSchemeParamsAsn1,
        },
    }, PBES2Algorithms);

    return {
        encryptionAlgorithmParamsAsn1,
        encryptedData,
    };
};

const ALGORITHMS = {
    PBES2: { decrypt: decryptWithPBES2, encrypt: encryptWithPBES2 },
};

export const maybeDecryptPrivateKeyInfo = (maybeEncryptedPrivateKeyInfoAsn1, password) => {
    try {
        return decryptPrivateKeyInfo(maybeEncryptedPrivateKeyInfoAsn1, password);
    } catch (err) {
        if (err.code === 'DECODE_ASN1_FAILED' && err.model === 'EncryptedPrivateKeyInfo') {
            return {
                encryptionAlgorithm: null,
                privateKeyInfoAsn1: maybeEncryptedPrivateKeyInfoAsn1,
            };
        }

        throw err;
    }
};

export const decryptPrivateKeyInfo = (encryptedPrivateKeyInfoAsn1, password) => {
    const { encryptionAlgorithm, encryptedData } = decodeAsn1(encryptedPrivateKeyInfoAsn1, EncryptedPrivateKeyInfo);

    if (!password) {
        throw Object.assign(
            new Error('Please specify the password to decrypt the key'),
            { code: 'SUPPLY_PASSWORD' }
        );
    }

    const encryptionAlgorithmOid = encryptionAlgorithm.id;
    const encryptionAlgorithmName = OIDS[encryptionAlgorithmOid] || encryptionAlgorithmOid;

    if (!ALGORITHMS[encryptionAlgorithmName]) {
        throw Object.assign(
            new Error(`Unsupported encryption algorithm OID '${encryptionAlgorithmOid}'`),
            { code: 'UNSUPPORTED_ALGORITHM' }
        );
    }

    const { encryptionAlgorithmParams, decryptedData } = ALGORITHMS[encryptionAlgorithmName].decrypt(
        encryptionAlgorithm.parameters,
        encryptedData,
        password
    );

    return {
        encryptionAlgorithm: {
            id: encryptionAlgorithmName,
            ...encryptionAlgorithmParams,
        },
        privateKeyInfoAsn1: decryptedData,
    };
};

export const encryptPrivateKeyInfo = (encryptionAlgorithm, privateKeyInfoAsn1, password) => {
    const { id: encryptionAlgorithmId, ...encryptionAlgorithmParams } = encryptionAlgorithm;

    const encryptionAlgorithmName = OIDS[encryptionAlgorithmId] || encryptionAlgorithmId;

    if (!ALGORITHMS[encryptionAlgorithmName]) {
        throw Object.assign(
            new Error(`Unsupported encryption algorithm ID '${encryptionAlgorithmId}'`),
            { code: 'UNSUPPORTED_ALGORITHM' }
        );
    }

    const { encryptionAlgorithmParamsAsn1, encryptedData } = ALGORITHMS[encryptionAlgorithmName].encrypt(
        encryptionAlgorithmParams,
        privateKeyInfoAsn1,
        password
    );

    const encryptedPrivateKeyInfoAsn1 = encodeAsn1({
        encryptionAlgorithm: {
            id: FLIPPED_OIDS[encryptionAlgorithmName],
            parameters: encryptionAlgorithmParamsAsn1,
        },
        encryptedData,
    }, EncryptedPrivateKeyInfo);

    return encryptedPrivateKeyInfoAsn1;
};
