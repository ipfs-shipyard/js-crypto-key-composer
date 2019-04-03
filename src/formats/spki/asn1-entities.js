/* eslint-disable babel/no-invalid-this, newline-per-chained-call */
import asn1 from '@lordvlad/asn1.js';

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

export const AlgorithmIdentifier = asn1.define('AlgorithmIdentifier', function () {
    this.seq().obj(
        this.key('id').objid(objIdValues),
        this.key('parameters').optional().any()
    );
});

export const SubjectPublicKeyInfo = asn1.define('SubjectPublicKeyInfo', function () {
    this.seq().obj(
        this.key('algorithm').use(AlgorithmIdentifier),
        this.key('publicKey').bitstr()
    );
});

export const RsaPublicKey = asn1.define('RsaPublicKey', function () {
    this.seq().obj(
        this.key('modulus').int(),
        this.key('publicExponent').int()
    );
});
/* eslint-enable babel/no-invalid-this, newline-per-chained-call */
