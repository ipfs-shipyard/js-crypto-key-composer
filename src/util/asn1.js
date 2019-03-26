import asn1 from '@lordvlad/asn1.js';
import deepForEach from 'deep-for-each';
import cloneDeep from 'clone-deep';
import { nodeBufferToArrayBuffer, arrayBufferToNodeBuffer, bnToArrayBuffer, binaryStringToArrayBuffer } from './binary';

// Ensure that all asn1 objid are returned as strings separated with '.'
// See https://github.com/indutny/asn1.js/blob/b99ce086320e0123331e6272f6de75548c6855fa/lib/asn1/decoders/der.js#L198
// See https://github.com/indutny/asn1.js/blob/b99ce086320e0123331e6272f6de75548c6855fa/lib/asn1/encoders/der.js#L103
const objIdValues = new Proxy({}, {
    get: (obj, key) => {
        if (key === 'hasOwnProperty') {
            return (key) => key.indexOf('.') > 0;
        }

        return key.indexOf('.') > 0 ? key : undefined;
    },
});

export const decodeAsn1 = (encodedEntity, Model) => {
    let decodedEntity;

    try {
        decodedEntity = Model.decode(arrayBufferToNodeBuffer(encodedEntity), 'der');
    } catch (err) {
        throw Object.assign(
            new Error(`Unable to decode ${Model.name}`),
            { code: 'DECODE_ASN1_FAILED', model: Model.name, originalError: err },
        );
    }

    const mapValue = (value) => {
        // Node buffer to array buffer
        if (value && value.buffer) {
            return nodeBufferToArrayBuffer(value);
        }
        // Big number to array buffer
        if (value && value.toArrayLike) {
            return bnToArrayBuffer(value);
        }

        return value;
    };

    // Apply conversion to all properties deep within the entity
    deepForEach(decodedEntity, (value, key, subject) => {
        subject[key] = mapValue(value);
    });

    return mapValue(decodedEntity);
};

export const encodeAsn1 = (decodedEntity, Model) => {
    const mapValue = (value) => {
        // Array buffer to node buffer
        if (value instanceof ArrayBuffer) {
            return arrayBufferToNodeBuffer(value);
        }

        return value;
    };

    // Clone argument because we are going to mutate it
    decodedEntity = cloneDeep(decodedEntity);

    // Apply conversion to all properties deep within the entity
    decodedEntity = mapValue(decodedEntity);
    deepForEach(decodedEntity, (value, key, subject) => {
        subject[key] = mapValue(value);
    });

    let encodedEntity;

    try {
        encodedEntity = Model.encode(decodedEntity, 'der');
    } catch (err) {
        throw Object.assign(
            new Error(`Unable to encode ${Model.name}`),
            { code: 'ENCODE_ASN1_FAILED', model: Model.name, originalError: err },
        );
    }

    return nodeBufferToArrayBuffer(encodedEntity);
};

/* eslint-disable babel/no-invalid-this, newline-per-chained-call */
export const OtherPrimeInfo = asn1.define('OtherPrimeInfo', function () {
    this.seq().obj(
        this.key('prime').int(),
        this.key('exponent').int(),
        this.key('coefficient').int(),
    );
});

export const RSAPrivateKey = asn1.define('RSAPrivateKey', function () {
    this.seq().obj(
        this.key('version').int(),
        this.key('modulus').int(),
        this.key('publicExponent').int(),
        this.key('privateExponent').int(),
        this.key('prime1').int(),
        this.key('prime2').int(),
        this.key('exponent1').int(),
        this.key('exponent2').int(),
        this.key('coefficient').int(),
        this.key('otherPrimeInfos').seqof(OtherPrimeInfo).optional(),
    );
});

export const AlgorithmIdentifier = asn1.define('AlgorithmIdentifier', function () {
    this.seq().obj(
        this.key('id').objid(objIdValues),
        this.key('parameters').optional().any()
    );
});

export const PublicKeyInfo = asn1.define('PublicKeyInfo', function () {
    this.seq().obj(
        this.key('algorithm').use(AlgorithmIdentifier),
        this.key('publicKey').octstr()
    );
});

export const PrivateKeyInfo = asn1.define('PrivateKeyInfo', function () {
    this.seq().obj(
        this.key('version').int(),
        this.key('algorithm').use(AlgorithmIdentifier),
        this.key('privateKey').octstr(),
        this.key('attributes').implicit(0).optional().any(),
        this.key('publicKey').implicit(1).optional().bitstr()
    );
});

export const EncryptedPrivateKeyInfo = asn1.define('EncryptedPrivateKeyInfo', function () {
    this.seq().obj(
        this.key('encryptionAlgorithm').use(AlgorithmIdentifier),
        this.key('encryptedData').octstr(),
    );
});

export const PBES2Algorithms = asn1.define('PBES2Algorithms', function () {
    this.seq().obj(
        this.key('keyDerivationFunc').use(AlgorithmIdentifier),
        this.key('encryptionScheme').use(AlgorithmIdentifier).def({
            id: '1.2.840.113549.2.7', // hmacWithSHA1
            parameters: arrayBufferToNodeBuffer(binaryStringToArrayBuffer('0500')),
        })
    );
});

export const PBES2ESParams = {
    desCB: asn1.define('desCB', function () { this.octstr(); }),
    'des-EDE3-CBC': asn1.define('des-EDE3-CBC', function () { this.octstr(); }),
    'aes128-CBC': asn1.define('aes128-CBC', function () { this.octstr(); }),
    'aes192-CBC': asn1.define('aes192-CBC', function () { this.octstr(); }),
    'aes256-CBC': asn1.define('aes256-CBC', function () { this.octstr(); }),
};

export const PBKDF2params = asn1.define('PBKDF2-params', function () {
    this.seq().obj(
        this.key('salt').octstr(),
        this.key('iterationCount').int(),
        this.key('keyLength').int().optional(),
        this.key('prf').use(AlgorithmIdentifier)
    );
});

export const CurvePrivateKey = asn1.define('CurvePrivateKey', function () { this.octstr(); });
/* eslint-enable babel/no-invalid-this, newline-per-chained-call */
