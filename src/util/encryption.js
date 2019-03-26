import { createBuffer } from 'node-forge/lib/util';
import sha1 from 'node-forge/lib/sha1';
import sha256 from 'node-forge/lib/sha256';
import sha512 from 'node-forge/lib/sha512';
import aes from 'node-forge/lib/aes';
import des from 'node-forge/lib/des';
import pbkdf2 from 'node-forge/lib/pbkdf2';
import { OIDS } from '../util/oid';
import { arrayBufferToBinaryString, binaryStringToArrayBuffer } from '../util/binary';

export const createPbkdf2 = (params) => {
    const { salt, iterationCount, keyLength, prf } = params;

    const saltStr = arrayBufferToBinaryString(salt);
    const prfName = OIDS[params.prf] || prf;
    let prfMd;

    switch (prfName) {
    case 'hmacWithSHA1':
        prfMd = sha1.create();
        break;
    case 'hmacWithSHA224':
    case 'hmacWithSHA256':
        prfMd = sha256.create();
        break;
    case 'hmacWithSHA384':
    case 'hmacWithSHA512':
        prfMd = sha512.create();
        break;
    default:
        throw Object.assign(
            new Error(`Unsupported prf id '${prf}'`),
            { code: 'UNSUPPORTED_ALGORITHM' }
        );
    }

    return (password) => binaryStringToArrayBuffer(pbkdf2(password, saltStr, iterationCount, keyLength, prfMd));
};

export const createAesDecrypter = (params) => {
    const { iv, mode } = params;

    const ivStr = arrayBufferToBinaryString(iv);

    return (key, encryptedData) => {
        const keyStr = arrayBufferToBinaryString(key);
        const cipher = aes.createDecryptionCipher(keyStr, mode);

        cipher.start(ivStr);
        cipher.update(createBuffer(arrayBufferToBinaryString(encryptedData)));

        if (!cipher.finish()) {
            throw Object.assign(
                new Error('Decryption failed, mostly likely the password is wrong'),
                { code: 'DECRYPTION_FAILED' }
            );
        }

        return binaryStringToArrayBuffer(cipher.output.getBytes());
    };
};

export const createAesEncrypter = (params) => {
    const { iv, mode } = params;

    const ivStr = arrayBufferToBinaryString(iv);

    return (key, data) => {
        const keyStr = arrayBufferToBinaryString(key);
        const cipher = aes.createEncryptionCipher(keyStr, mode);

        cipher.start(ivStr);
        cipher.update(createBuffer(arrayBufferToBinaryString(data)));
        cipher.finish();

        return binaryStringToArrayBuffer(cipher.output.getBytes());
    };
};

export const createDesDecrypter = (params) => {
    const { iv, mode } = params;

    const ivStr = arrayBufferToBinaryString(iv);

    return (key, encryptedData) => {
        const cipher = des.createDecryptionCipher(key, mode);

        cipher.start(ivStr);
        cipher.update(createBuffer(arrayBufferToBinaryString(encryptedData)));

        if (!cipher.finish()) {
            throw Object.assign(
                new Error('Decryption failed, mostly likely the password is wrong'),
                { code: 'DECRYPTION_FAILED' }
            );
        }

        return binaryStringToArrayBuffer(cipher.output.getBytes());
    };
};

export const createDesEncrypter = (params) => {
    const { iv, mode } = params;

    const ivStr = arrayBufferToBinaryString(iv);

    return (key, data) => {
        const keyStr = arrayBufferToBinaryString(key);
        const cipher = des.createEncryptionCipher(keyStr, mode);

        cipher.start(ivStr);
        cipher.update(createBuffer(arrayBufferToBinaryString(data)));
        cipher.finish();

        return binaryStringToArrayBuffer(cipher.output.getBytes());
    };
};
