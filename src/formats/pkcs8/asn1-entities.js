/* eslint-disable babel/no-invalid-this, newline-per-chained-call */
import { Buffer } from 'buffer';
import asn1 from '@lordvlad/asn1.js';
import { FLIPPED_OIDS } from '../../util/oids';

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

// This is actually a OneAsymmetricKey, defined in https://tools.ietf.org/html/rfc8410
export const PrivateKeyInfo = asn1.define('PrivateKeyInfo', function () {
    this.seq().obj(
        this.key('version').int(),
        this.key('privateKeyAlgorithm').use(AlgorithmIdentifier),
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

export const Pbes2Algorithms = asn1.define('PBES2Algorithms', function () {
    this.seq().obj(
        this.key('keyDerivationFunc').use(AlgorithmIdentifier),
        this.key('encryptionScheme').use(AlgorithmIdentifier),
    );
});

export const Pbes2EsParams = {
    'des-cbc': asn1.define('desCBC', function () { this.octstr(); }),
    'des-ede3-cbc': asn1.define('des-EDE3-CBC', function () { this.octstr(); }),
    'aes128-cbc': asn1.define('aes128-CBC', function () { this.octstr(); }),
    'aes192-cbc': asn1.define('aes192-CBC', function () { this.octstr(); }),
    'aes256-cbc': asn1.define('aes256-CBC', function () { this.octstr(); }),
};

export const Pbkdf2Params = asn1.define('PBKDF2-params', function () {
    this.seq().obj(
        this.key('salt').choice({
            specified: this.octstr(),
            otherSource: this.use(AlgorithmIdentifier),
        }),
        this.key('iterationCount').int(),
        this.key('keyLength').int().optional(),
        this.key('prf').use(AlgorithmIdentifier).def({
            id: FLIPPED_OIDS['hmac-with-sha1'],
            parameters: Buffer.from([0x05, 0x00]),
        })
    );
});

export const Rc2CbcParameter = asn1.define('RC2-CBC-Parameter', function () {
    this.seq().obj(
        this.key('rc2ParameterVersion').int().optional(),
        this.key('iv').octstr()
    );
});

export const CurvePrivateKey = asn1.define('CurvePrivateKey', function () { this.octstr(); });
/* eslint-enable babel/no-invalid-this, newline-per-chained-call */
