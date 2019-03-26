import { encode as encodePem, decode as decodePem } from 'node-forge/lib/pem';
import { binaryStringToArrayBuffer, arrayBufferToBinaryString } from '../../util/binary';
import { decryptPemBody, encryptPemBody } from './encryption';
import { decomposeKey as decomposePkc1Key, composeKey as composePkcs1Key } from './pkcs1';

const isEncrypted = (pem) =>
    pem.procType &&
    pem.procType.type === 'ENCRYPTED' &&
    pem.dekInfo &&
    pem.dekInfo.algorithm;

export const decomposeKey = (pemStr, options) => {
    if (typeof pemStr !== 'string') {
        throw Object.assign(
            new Error('The key for PKCS1-PEM must be a string'),
            { code: 'INVALID_KEY' }
        );
    }

    let pem;

    try {
        pem = decodePem(pemStr)[0];
    } catch (err) {
        throw Object.assign(
            new Error('Failed to decode PKCS1 as PEM'),
            { code: 'INVALID_KEY', originalError: err }
        );
    }

    let decomposedKey;

    // Is it encrypted?
    if (isEncrypted(pem)) {
        const { pemBody: pkcs1Key, encryptionAlgorithm } = decryptPemBody(pem, options.password);

        decomposedKey = decomposePkc1Key(pkcs1Key, options);
        decomposedKey.encryptionAlgorithm = encryptionAlgorithm;
    } else {
        const pkcs1Key = binaryStringToArrayBuffer(pem.body);

        decomposedKey = decomposePkc1Key(pkcs1Key, options);
    }

    decomposedKey.format = 'pkcs1-pem';

    return decomposedKey;
};

export const composeKey = ({ encryptionAlgorithm, ...decomposedKey }, options) => {
    const pkcs1Key = composePkcs1Key(decomposedKey, options);

    const pem = {
        type: 'RSA PRIVATE KEY',
    };

    // Do we need to encrypt?
    if (options.password) {
        const { pemBody, dekInfo } = encryptPemBody(pkcs1Key, encryptionAlgorithm, options.password);

        pem.procType = { version: '4', type: 'ENCRYPTED' };
        pem.dekInfo = dekInfo;
        pem.body = arrayBufferToBinaryString(pemBody);
    } else {
        pem.body = arrayBufferToBinaryString(pkcs1Key);
    }

    return encodePem(pem).replace(/\r/g, '');
};
