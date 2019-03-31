import { OIDS, FLIPPED_OIDS } from './oids';
import { CurvePrivateKey } from './asn1-entities';
import { decomposeRsaPrivateKey, composeRsaPrivateKey } from '../pkcs1/keys';
import { decodeAsn1, encodeAsn1 } from '../../util/asn1';
import { uint8ArrayToHexString, hexStringToUint8Array } from '../../util/binary';
import { UnsupportedAlgorithmError } from '../../util/errors';
import KEY_TYPES from '../../util/key-types';

const decomposeRsaPrivateKeyInfo = (privateKeyInfo) => {
    const { privateKeyAlgorithm, privateKey: privateKeyAsn1 } = privateKeyInfo;

    const { keyData } = decomposeRsaPrivateKey(privateKeyAsn1);

    return {
        keyAlgorithm: {
            id: OIDS[privateKeyAlgorithm.id],
            parameters: uint8ArrayToHexString(privateKeyAlgorithm.parameters) === '0500' ? null : privateKeyAlgorithm.parameters,
        },
        keyData,
    };
};

const composeRsaPrivateKeyInfo = (keyAlgorithm, keyData) => {
    const rsaPrivateKeyAsn1 = composeRsaPrivateKey(keyData);

    return {
        version: 0,
        privateKeyAlgorithm: {
            id: FLIPPED_OIDS[keyAlgorithm.id],
            parameters: keyAlgorithm.parameters || hexStringToUint8Array('0500'),
        },
        privateKey: rsaPrivateKeyAsn1,
    };
};

const decomposeEd25519PrivateKeyInfo = (privateKeyInfo) => {
    const { privateKeyAlgorithm, privateKey } = privateKeyInfo;
    const seed = decodeAsn1(privateKey, CurvePrivateKey);

    return {
        keyAlgorithm: {
            id: OIDS[privateKeyAlgorithm.id],
        },
        keyData: {
            seed,
        },
    };
};

const composeEd25519PrivateKeyInfo = (keyAlgorithm, keyData) => ({
    version: 0,
    privateKeyAlgorithm: {
        id: FLIPPED_OIDS[keyAlgorithm.id],
    },
    privateKey: encodeAsn1(keyData.seed, CurvePrivateKey),
});

export const decomposePrivateKeyInfo = (privateKeyInfo) => {
    const keyType = KEY_TYPES[OIDS[privateKeyInfo.privateKeyAlgorithm.id]];

    switch (keyType) {
    case 'rsa': return decomposeRsaPrivateKeyInfo(privateKeyInfo);
    case 'ed25519': return decomposeEd25519PrivateKeyInfo(privateKeyInfo);
    default:
        throw new UnsupportedAlgorithmError(`Unsupported key algorithm OID '${privateKeyInfo.privateKeyAlgorithm.id}'`);
    }
};

export const composePrivateKeyInfo = (keyAlgorithm, keyData) => {
    const keyType = KEY_TYPES[keyAlgorithm.id];

    switch (keyType) {
    case 'rsa': return composeRsaPrivateKeyInfo(keyAlgorithm, keyData);
    case 'ed25519': return composeEd25519PrivateKeyInfo(keyAlgorithm, keyData);
    default:
        throw new UnsupportedAlgorithmError(`Unsupported key algorithm id '${keyAlgorithm.id}'`);
    }
};
