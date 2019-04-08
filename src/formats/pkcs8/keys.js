import { CurvePrivateKey } from './asn1-entities';
import { decomposeRsaPrivateKey, composeRsaPrivateKey } from '../raw/keys';
import { OIDS, FLIPPED_OIDS } from '../../util/oids';
import { decodeAsn1, encodeAsn1 } from '../../util/asn1';
import { hexStringToUint8Array } from '../../util/binary';
import { UnsupportedAlgorithmError } from '../../util/errors';
import { KEY_TYPES } from '../../util/key-types';

const decomposeRsaPrivateKeyInfo = (privateKeyInfo) => {
    const { privateKeyAlgorithm, privateKey: privateKeyAsn1 } = privateKeyInfo;

    const keyAlgorithm = { id: OIDS[privateKeyAlgorithm.id] };

    switch (keyAlgorithm.id) {
    case 'rsa-encryption':
    case 'md2-with-rsa-encryption':
    case 'md4-with-rsa-encryption':
    case 'md5-with-rsa-encryption':
    case 'sha1-with-rsa-encryption':
    case 'sha224-with-rsa-encryption':
    case 'sha256-with-rsa-encryption':
    case 'sha384-with-rsa-encryption':
    case 'sha512-with-rsa-encryption':
    case 'sha512-224-with-rsa-encryption':
    case 'sha512-256-with-rsa-encryption':
        break;
    case 'rsaes-oaep':
        throw new UnsupportedAlgorithmError('RSA-OAEP keys are not yet supported');
    case 'rsassa-pss':
        throw new UnsupportedAlgorithmError('RSA-PSS keys are not yet supported');
    default:
        throw new UnsupportedAlgorithmError(`Unsupported key algorithm OID '${privateKeyAlgorithm.id}'`);
    }

    const { keyData } = decomposeRsaPrivateKey(privateKeyAsn1);

    return {
        keyAlgorithm: {
            id: OIDS[privateKeyAlgorithm.id],
        },
        keyData,
    };
};

const composeRsaPrivateKeyInfo = (keyAlgorithm, keyData) => {
    const rsaPrivateKeyAsn1 = composeRsaPrivateKey(keyAlgorithm, keyData);

    return {
        version: 0,
        privateKeyAlgorithm: {
            id: FLIPPED_OIDS[keyAlgorithm.id],
            parameters: hexStringToUint8Array('0500'),
        },
        privateKey: rsaPrivateKeyAsn1,
    };
};

const decomposeEd25519PrivateKeyInfo = (privateKeyInfo) => {
    // See: https://tools.ietf.org/html/rfc8032#section-5.1.5
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
