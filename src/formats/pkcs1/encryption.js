import random from 'node-forge/lib/random';
import util from 'node-forge/lib/util';
import aes from 'node-forge/lib/aes';
import des from 'node-forge/lib/des';
import rc2 from 'node-forge/lib/rc2';
import pbe from 'node-forge/lib/pbe';
import 'node-forge/lib/md5'; // Necessary for pbe.opensslDeriveBytes
import { binaryStringToArrayBuffer, arrayBufferToBinaryString, hexStringToArrayBuffer, arrayBufferToHexString } from '../../util/binary';
import { OIDS } from '../../util/oid';
import { validateAlgorithmIdentifier } from '../../util/validator';

export const decryptPemBody = (pem, password) => {
    const encryptionAlgorithm = {
        id: null,
        iv: hexStringToArrayBuffer(pem.dekInfo.parameters),
    };

    let dkLen;
    let cipherFn;

    switch (pem.dekInfo.algorithm) {
    case 'DES-CBC':
        encryptionAlgorithm.id = 'desCBC';
        dkLen = 8;
        cipherFn = des.createDecryptionCipher;
        break;
    case 'DES-EDE3-CBC':
        encryptionAlgorithm.id = 'des-EDE3-CBC';
        dkLen = 24;
        cipherFn = des.createDecryptionCipher;
        break;
    case 'AES-128-CBC':
        encryptionAlgorithm.id = 'aes128-CBC';
        dkLen = 16;
        cipherFn = aes.createDecryptionCipher;
        break;
    case 'AES-192-CBC':
        encryptionAlgorithm.id = 'aes192-CBC';
        dkLen = 24;
        cipherFn = aes.createDecryptionCipher;
        break;
    case 'AES-256-CBC':
        encryptionAlgorithm.id = 'aes256-CBC';
        dkLen = 32;
        cipherFn = aes.createDecryptionCipher;
        break;
    case 'RC2-40-CBC':
        encryptionAlgorithm.id = 'rc2-cbc';
        encryptionAlgorithm.rc2ParameterVersion = 40;
        dkLen = 5;
        cipherFn = (key) => rc2.createDecryptionCipher(key, 40);
        break;
    case 'RC2-64-CBC':
        encryptionAlgorithm.id = 'rc2-cbc';
        encryptionAlgorithm.rc2ParameterVersion = 64;
        dkLen = 8;
        cipherFn = (key) => rc2.createDecryptionCipher(key, 64);
        break;
    case 'RC2-128-CBC':
        encryptionAlgorithm.id = 'rc2-cbc';
        encryptionAlgorithm.rc2ParameterVersion = 128;
        dkLen = 16;
        cipherFn = (key) => rc2.createDecryptionCipher(key, 128);
        break;
    default:
        throw Object.assign(
            new Error(`Unsupported DEK-INFO algorithm '${pem.dekInfo.algorithm}'`),
            { code: 'UNSUPPORTED_ALGORITHM' }
        );
    }

    // Use OpenSSL legacy key derivation
    const iv = arrayBufferToBinaryString(encryptionAlgorithm.iv);
    const dk = pbe.opensslDeriveBytes(password, iv.substr(0, 8), dkLen);
    const cipher = cipherFn(dk);

    cipher.start(iv);
    cipher.update(util.createBuffer(pem.body));

    if (!cipher.finish()) {
        throw Object.assign(
            new Error('Decryption failed, mostly likely the password is wrong'),
            { code: 'DECRYPTION_FAILED' }
        );
    }

    return {
        encryptionAlgorithm,
        pemBody: binaryStringToArrayBuffer(cipher.output.getBytes()),
    };
};

export const encryptPemBody = (pemBody, encryptionAlgorithm, password) => {
    encryptionAlgorithm = validateAlgorithmIdentifier(encryptionAlgorithm, 'aes256-CBC');

    const algorithmName = OIDS[encryptionAlgorithm.id] || encryptionAlgorithm.id;
    let dekInfoAlgorithm;

    let dkLen;
    let cipherFn;
    let ivBytes;

    switch (algorithmName) {
    case 'desCBC':
        dekInfoAlgorithm = 'DES-CBC';
        dkLen = 8;
        ivBytes = 8;
        cipherFn = des.createEncryptionCipher;
        break;
    case 'des-EDE3-CBC':
        dekInfoAlgorithm = 'DES-EDE3-CBC';
        dkLen = 24;
        ivBytes = 8;
        cipherFn = des.createEncryptionCipher;
        break;
    case 'aes128-CBC':
        dekInfoAlgorithm = 'AES-128-CBC';
        dkLen = 16;
        ivBytes = 16;
        cipherFn = aes.createEncryptionCipher;
        break;
    case 'aes192-CBC':
        dekInfoAlgorithm = 'AES-192-CBC';
        dkLen = 24;
        ivBytes = 16;
        cipherFn = aes.createEncryptionCipher;
        break;
    case 'aes256-CBC':
        dekInfoAlgorithm = 'AES-256-CBC';
        dkLen = 32;
        ivBytes = 16;
        cipherFn = aes.createEncryptionCipher;
        break;
    case 'rc2-cbc': {
        ivBytes = 8;

        const rc2ParameterVersion = encryptionAlgorithm.parameters.rc2ParameterVersion || 128;

        switch (rc2ParameterVersion) {
        case 40:
            dekInfoAlgorithm = 'RC2-40-CBC';
            dkLen = 5;
            cipherFn = (key) => rc2.createEncryptionCipher(key, 40);
            break;
        case 64:
            dekInfoAlgorithm = 'RC2-64-CBC';
            dkLen = 8;
            cipherFn = (key) => rc2.createEncryptionCipher(key, 64);
            break;
        case 128:
            dekInfoAlgorithm = 'RC2-128-CBC';
            dkLen = 16;
            cipherFn = (key) => rc2.createEncryptionCipher(key, 128);
            break;
        default:
            throw Object.assign(
                new Error(`Unsupported rc2ParameterVersion '${rc2ParameterVersion}'`),
                { code: 'UNSUPPORTED_ALGORITHM' }
            );
        }
        break;
    }
    default:
        throw Object.assign(
            new Error(`Unsupported encryption algorithm id '${encryptionAlgorithm.id}'`),
            { code: 'UNSUPPORTED_ALGORITHM' }
        );
    }

    // Re-use iv if passed
    const iv = encryptionAlgorithm.iv ?
        arrayBufferToBinaryString(encryptionAlgorithm.iv) : random.getBytesSync(ivBytes);

    if (iv.length !== ivBytes) {
        throw Object.assign(
            new Error(`Expecting iv to have ${ivBytes} bytes`),
            { code: 'INVALID_ENCRYPTION_PARAMETER' }
        );
    }

    // Encrypt private key using OpenSSL legacy key derivation
    const dk = pbe.opensslDeriveBytes(password, iv.substr(0, 8), dkLen);
    const cipher = cipherFn(dk);

    cipher.start(iv);
    cipher.update(util.createBuffer(arrayBufferToBinaryString(pemBody)));
    cipher.finish();

    return {
        dekInfo: {
            algorithm: dekInfoAlgorithm,
            parameters: arrayBufferToHexString(binaryStringToArrayBuffer(iv)).toUpperCase(),
        },
        pemBody: binaryStringToArrayBuffer(cipher.output.getBytes()),
    };
};
