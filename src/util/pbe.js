import { createBuffer } from 'node-forge/lib/util';
import sha1 from 'node-forge/lib/sha1';
import sha256 from 'node-forge/lib/sha256';
import sha512 from 'node-forge/lib/sha512';
import md5 from 'node-forge/lib/md5';
import pbkdf2 from 'node-forge/lib/pbkdf2';
import aes from 'node-forge/lib/aes';
import des from 'node-forge/lib/des';
import rc2 from 'node-forge/lib/rc2';
import { uint8ArrayToBinaryString, binaryStringToUint8Array } from './binary';
import { UnsupportedAlgorithmError, DecryptionFailedError } from './errors';

export const createPbkdf2KeyDeriver = (params) => {
    const { salt, iterationCount, keyLength, prf } = params;

    const saltStr = uint8ArrayToBinaryString(salt);
    let prfMd;

    switch (prf) {
    case 'hmac-with-sha1':
        prfMd = sha1.create();
        break;
    // TODO: node-forge doesn't have sha224 support, see: https://github.com/digitalbazaar/forge/issues/669
    // case 'hmacWithSHA224':
    //     prfMd = sha256.sha224.create();
    //     break;
    case 'hmac-with-sha256':
        prfMd = sha256.create();
        break;
    case 'hmac-with-sha384':
        prfMd = sha512.sha384.create();
        break;
    case 'hmac-with-sha512':
        prfMd = sha512.create();
        break;
    default:
        throw new UnsupportedAlgorithmError(`Unsupported prf algorithm id '${prf}'`);
    }

    return (password) => binaryStringToUint8Array(pbkdf2(password, saltStr, iterationCount, keyLength, prfMd));
};

export const createOpenSslKeyDeriver = (params) => {
    const { salt, keyLength } = params;

    const saltStr = uint8ArrayToBinaryString(salt);
    const md = md5.create();

    const hash = (bytes) =>
        md
        .start()
        .update(bytes)
        .digest()
        .getBytes();

    return (password) => {
        const digests = [hash(password + saltStr)];

        for (let length = 16, i = 1; length < keyLength; i += 1, length += 16) {
            digests.push(hash(digests[i - 1] + password + saltStr));
        }

        const digestStr = digests.join('').substr(0, keyLength);

        return binaryStringToUint8Array(digestStr);
    };
};

export const createAesDecrypter = (params) => {
    const { iv, mode } = params;

    const ivStr = uint8ArrayToBinaryString(iv);

    return (key, encryptedData) => {
        const keyStr = uint8ArrayToBinaryString(key);
        const cipher = aes.createDecryptionCipher(keyStr, mode);

        cipher.start(ivStr);
        cipher.update(createBuffer(uint8ArrayToBinaryString(encryptedData)));

        if (!cipher.finish()) {
            throw new DecryptionFailedError('Decryption failed, mostly likely the password is wrong');
        }

        return binaryStringToUint8Array(cipher.output.getBytes());
    };
};

export const createAesEncrypter = (params) => {
    const { iv, mode } = params;

    const ivStr = uint8ArrayToBinaryString(iv);

    return (key, data) => {
        const keyStr = uint8ArrayToBinaryString(key);
        const cipher = aes.createEncryptionCipher(keyStr, mode);

        cipher.start(ivStr);
        cipher.update(createBuffer(uint8ArrayToBinaryString(data)));
        cipher.finish();

        return binaryStringToUint8Array(cipher.output.getBytes());
    };
};

export const createDesDecrypter = (params) => {
    const { iv, mode } = params;

    const ivStr = uint8ArrayToBinaryString(iv);

    return (key, encryptedData) => {
        const keyStr = uint8ArrayToBinaryString(key);
        const cipher = des.createDecryptionCipher(keyStr, mode);

        cipher.start(ivStr);
        cipher.update(createBuffer(uint8ArrayToBinaryString(encryptedData)));

        if (!cipher.finish()) {
            throw new DecryptionFailedError('Decryption failed, mostly likely the password is wrong');
        }

        return binaryStringToUint8Array(cipher.output.getBytes());
    };
};

export const createDesEncrypter = (params) => {
    const { iv, mode } = params;

    const ivStr = uint8ArrayToBinaryString(iv);

    return (key, data) => {
        const keyStr = uint8ArrayToBinaryString(key);
        const cipher = des.createEncryptionCipher(keyStr, mode);

        cipher.start(ivStr);
        cipher.update(createBuffer(uint8ArrayToBinaryString(data)));
        cipher.finish();

        return binaryStringToUint8Array(cipher.output.getBytes());
    };
};

export const createRc2Decrypter = (params) => {
    const { iv, bits } = params;

    const ivStr = uint8ArrayToBinaryString(iv);

    return (key, encryptedData) => {
        const keyStr = uint8ArrayToBinaryString(key);
        const cipher = rc2.createDecryptionCipher(keyStr, bits);

        cipher.start(ivStr);
        cipher.update(createBuffer(uint8ArrayToBinaryString(encryptedData)));

        if (!cipher.finish()) {
            throw new DecryptionFailedError('Decryption failed, mostly likely the password is wrong');
        }

        return binaryStringToUint8Array(cipher.output.getBytes());
    };
};

export const createRc2Encrypter = (params) => {
    const { iv, bits } = params;

    const ivStr = uint8ArrayToBinaryString(iv);

    return (key, data) => {
        const keyStr = uint8ArrayToBinaryString(key);
        const cipher = rc2.createEncryptionCipher(keyStr, bits);

        cipher.start(ivStr);
        cipher.update(createBuffer(uint8ArrayToBinaryString(data)));
        cipher.finish();

        return binaryStringToUint8Array(cipher.output.getBytes());
    };
};
