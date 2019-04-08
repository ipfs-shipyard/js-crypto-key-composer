import { RsaPrivateKey, RsaPublicKey, EcPrivateKey } from './asn1-entities';
import { decodeAsn1, encodeAsn1 } from '../../util/asn1';
import { UnsupportedAlgorithmError } from '../../util/errors';
import { OIDS, FLIPPED_OIDS } from '../../util/oids';
import { KEY_TYPES } from '../../util/key-types';

export const decomposeRsaPrivateKey = (rsaPrivateKeyAsn1) => {
    const { version, ...keyData } = decodeAsn1(rsaPrivateKeyAsn1, RsaPrivateKey);

    return {
        keyAlgorithm: {
            id: 'rsa-encryption',
        },
        keyData,
    };
};

export const composeRsaPrivateKey = (keyAlgorithm, keyData) => {
    const otherPrimeInfos = keyData.otherPrimeInfos;
    const hasMultiplePrimes = otherPrimeInfos && otherPrimeInfos.length > 0;

    const rsaPrivateKey = {
        ...keyData,
        version: hasMultiplePrimes ? 1 : 0,
        otherPrimeInfos: hasMultiplePrimes ? otherPrimeInfos : undefined,
    };

    return encodeAsn1(rsaPrivateKey, RsaPrivateKey);
};

export const decomposeRsaPublicKey = (rsaPublicKeyAsn1) => {
    const { version, ...keyData } = decodeAsn1(rsaPublicKeyAsn1, RsaPublicKey);

    return {
        keyAlgorithm: {
            id: 'rsa-encryption',
        },
        keyData,
    };
};

export const composeRsaPublicKey = (keyAlgorithm, keyData) =>
    encodeAsn1(keyData, RsaPublicKey);

export const decomposeEcPrivateKey = (ecPrivateKeyAsn1) => {
    const ecPrivateKey = decodeAsn1(ecPrivateKeyAsn1, EcPrivateKey);
    const namedCurve = OIDS[ecPrivateKey.parameters];

    if (!namedCurve) {
        throw new UnsupportedAlgorithmError(`Unsupported named curve OID '${ecPrivateKey.parameters}'`);
    }

    if (!ecPrivateKey.publicKey) {
        throw new UnsupportedAlgorithmError('Public key must be defined');
    }

    const encodedPoint = ecPrivateKey.publicKey.data;

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
            d: ecPrivateKey.privateKey,
        },
    };
};

export const composeEcPrivateKey = (keyAlgorithm, keyData) => {
    const namedCurveOid = FLIPPED_OIDS[keyAlgorithm.namedCurve];

    if (!namedCurveOid) {
        throw new UnsupportedAlgorithmError(`Unsupported named curve '${keyAlgorithm.namedCurve}'`);
    }

    if (!keyData.y) {
        throw new UnsupportedAlgorithmError('Uncompressed key points are not supported (y must be specified)');
    }

    const ecPrivateKey = {
        version: 1,
        privateKey: keyData.d,
        parameters: namedCurveOid,
        publicKey: {
            unused: 0,
            data: new Uint8Array([
                4,
                ...keyData.x,
                ...keyData.y,
            ]),
        },
    };

    return encodeAsn1(ecPrivateKey, EcPrivateKey);
};

export const SUPPORTED_KEY_TYPES = {
    private: ['rsa', 'ec'],
    public: ['rsa'],
};

export const decomposeRawPrivateKey = (keyType, privateKeyAsn1) => {
    switch (keyType) {
    case 'rsa': return decomposeRsaPrivateKey(privateKeyAsn1);
    case 'ec': return decomposeEcPrivateKey(privateKeyAsn1);
    default:
        throw new UnsupportedAlgorithmError(`Unsupported key type '${keyType}'`);
    }
};

export const composeRawPrivateKey = (keyAlgorithm, keyData) => {
    const keyType = KEY_TYPES[keyAlgorithm.id];

    switch (keyType) {
    case 'rsa': return composeRsaPrivateKey(keyAlgorithm, keyData);
    case 'ec': return composeEcPrivateKey(keyAlgorithm, keyData);
    default:
        throw new UnsupportedAlgorithmError(`Unsupported key algorithm id '${keyAlgorithm.id}'`);
    }
};

export const decomposeRawPublicKey = (keyType, publicKeyAsn1) => {
    switch (keyType) {
    case 'rsa': return decomposeRsaPublicKey(publicKeyAsn1);
    default:
        throw new UnsupportedAlgorithmError(`Unsupported key type '${keyType}'`);
    }
};

export const composeRawPublicKey = (keyAlgorithm, keyData) => {
    const keyType = KEY_TYPES[keyAlgorithm.id];

    switch (keyType) {
    case 'rsa': return composeRsaPublicKey(keyAlgorithm, keyData);
    default:
        throw new UnsupportedAlgorithmError(`Unsupported key algorithm id '${keyAlgorithm.id}'`);
    }
};
