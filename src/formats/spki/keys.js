import { EcParameters } from './asn1-entities';
import { decomposeRsaPublicKey, composeRsaPublicKey } from '../raw/keys';
import { decodeAsn1, encodeAsn1 } from '../../util/asn1';
import { OIDS, FLIPPED_OIDS } from '../../util/oids';
import { hexStringToUint8Array } from '../../util/binary';
import { UnsupportedAlgorithmError } from '../../util/errors';
import { KEY_TYPES } from '../../util/key-types';

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

    const { keyData } = decomposeRsaPublicKey(publicKeyAsn1.data);

    return {
        keyAlgorithm: {
            id: OIDS[algorithm.id],
        },
        keyData,
    };
};

const composeRsaSubjectPublicKeyInfo = (keyAlgorithm, keyData) => {
    const rsaPublicKeyAsn1 = composeRsaPublicKey(keyAlgorithm, keyData);

    return {
        algorithm: {
            id: FLIPPED_OIDS[keyAlgorithm.id],
            parameters: hexStringToUint8Array('0500'),
        },
        publicKey: {
            unused: 0,
            data: rsaPublicKeyAsn1,
        },
    };
};

const decomposeEcSubjectPublicKeyInfo = (subjectPublicKeyInfo) => {
    const { algorithm, publicKey } = subjectPublicKeyInfo;

    const namedCurveOid = decodeAsn1(algorithm.parameters, EcParameters);
    const namedCurve = OIDS[namedCurveOid];

    const encodedPoint = publicKey.data;

    if (encodedPoint[0] !== 4) {
        throw new UnsupportedAlgorithmError('Uncompressed key points are not supported');
    }

    // Get the byte length based on the curve name, by extract the number of bits from it
    // and converting it to bytes
    // Note that the number of bits may not be multiples of 8
    const byteLength = Math.floor((Number(namedCurve.match(/\d+/)[0]) + 7) / 8);

    if (encodedPoint.length !== (byteLength * 2) + 1) {
        throw new UnsupportedAlgorithmError(`Expecting public key to have length ${(byteLength * 2) - 1}, got ${encodedPoint.length} instead`);
    }

    return {
        keyAlgorithm: {
            id: 'ec-public-key',
            namedCurve,
        },
        keyData: {
            x: encodedPoint.slice(1, byteLength + 1),
            y: encodedPoint.slice(byteLength + 1),
        },
    };
};

const composeEcSubjectPublicKeyInfo = (keyAlgorithm, keyData) => {
    const namedCurveOid = FLIPPED_OIDS[keyAlgorithm.namedCurve];

    if (!namedCurveOid) {
        throw new UnsupportedAlgorithmError(`Unsupported named curve '${keyAlgorithm.namedCurve}'`);
    }

    return {
        algorithm: {
            id: FLIPPED_OIDS[keyAlgorithm.id],
            parameters: encodeAsn1(namedCurveOid, EcParameters),
        },
        publicKey: {
            unused: 0,
            data: new Uint8Array([
                4,
                ...keyData.x,
                ...keyData.y,
            ]),
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
    case 'ec': return decomposeEcSubjectPublicKeyInfo(subjectPublicKeyInfo);
    case 'ed25519': return decomposeEd25519SubjectPublicKeyInfo(subjectPublicKeyInfo);
    default:
        throw new UnsupportedAlgorithmError(`Unsupported key algorithm OID '${subjectPublicKeyInfo.algorithm.id}'`);
    }
};

export const composeSubjectPublicKeyInfo = (keyAlgorithm, keyData) => {
    const keyType = KEY_TYPES[keyAlgorithm.id];

    switch (keyType) {
    case 'rsa': return composeRsaSubjectPublicKeyInfo(keyAlgorithm, keyData);
    case 'ec': return composeEcSubjectPublicKeyInfo(keyAlgorithm, keyData);
    case 'ed25519': return composeEd25519SubjectPublicKeyInfo(keyAlgorithm, keyData);
    default:
        throw new UnsupportedAlgorithmError(`Unsupported key algorithm id '${keyAlgorithm.id}'`);
    }
};
