import { RsaPublicKey } from './asn1-entities';
import { OIDS, FLIPPED_OIDS } from '../../util/oids';
import { decodeAsn1, encodeAsn1 } from '../../util/asn1';
import { hexStringToUint8Array, uint8ArrayToInteger } from '../../util/binary';
import { UnsupportedAlgorithmError } from '../../util/errors';
import KEY_TYPES from '../../util/key-types';

const decomposeRsaSubjectPublicKeyInfo = (subjectPublicKeyInfo) => {
    const { algorithm, publicKey: publicKeyAsn1 } = subjectPublicKeyInfo;

    const keyAlgorithm = { id: OIDS[algorithm.id] };

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
        throw new UnsupportedAlgorithmError(`Unsupported key algorithm OID '${algorithm.id}'`);
    }

    const keyData = decodeAsn1(publicKeyAsn1.data, RsaPublicKey);

    return {
        keyAlgorithm: {
            id: OIDS[algorithm.id],
        },
        keyData: {
            ...keyData,
            // The publicExponent is small, so just transform it to a number
            publicExponent: uint8ArrayToInteger(keyData.publicExponent),
        },
    };
};

const composeRsaSubjectPublicKeyInfo = (keyAlgorithm, keyData) => {
    const rsaPrivateKeyAsn1 = encodeAsn1(keyData, RsaPublicKey);

    return {
        algorithm: {
            id: FLIPPED_OIDS[keyAlgorithm.id],
            parameters: hexStringToUint8Array('0500'),
        },
        publicKey: {
            unused: 0,
            data: rsaPrivateKeyAsn1,
        },
    };
};

const decomposeEd25519SubjectPublicKeyInfo = (subjectPublicKeyInfo) => {
    const { algorithm, publicKey } = subjectPublicKeyInfo;

    return {
        keyAlgorithm: {
            id: OIDS[algorithm.id],
        },
        keyData: {
            bytes: publicKey.data,
        },
    };
};

const composeEd25519SubjectPublicKeyInfo = (keyAlgorithm, keyData) => ({
    algorithm: {
        id: FLIPPED_OIDS[keyAlgorithm.id],
    },
    publicKey: {
        unused: 0,
        data: keyData.bytes,
    },
});

export const decomposeSubjectPublicKeyInfo = (subjectPublicKeyInfo) => {
    const keyType = KEY_TYPES[OIDS[subjectPublicKeyInfo.algorithm.id]];

    switch (keyType) {
    case 'rsa': return decomposeRsaSubjectPublicKeyInfo(subjectPublicKeyInfo);
    case 'ed25519': return decomposeEd25519SubjectPublicKeyInfo(subjectPublicKeyInfo);
    default:
        throw new UnsupportedAlgorithmError(`Unsupported key algorithm OID '${subjectPublicKeyInfo.algorithm.id}'`);
    }
};

export const composeSubjectPublicKeyInfo = (keyAlgorithm, keyData) => {
    const keyType = KEY_TYPES[keyAlgorithm.id];

    switch (keyType) {
    case 'rsa': return composeRsaSubjectPublicKeyInfo(keyAlgorithm, keyData);
    case 'ed25519': return composeEd25519SubjectPublicKeyInfo(keyAlgorithm, keyData);
    default:
        throw new UnsupportedAlgorithmError(`Unsupported key algorithm id '${keyAlgorithm.id}'`);
    }
};
