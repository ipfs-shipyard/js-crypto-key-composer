import { decodeAsn1, encodeAsn1, RSAPrivateKey, CurvePrivateKey } from '../../util/asn1';
import { integerFromArrayBuffer } from '../../util/binary';

const toRsaKeyData = (rsaPrivateKeyAsn1) => {
    const rsaPrivateKey = decodeAsn1(rsaPrivateKeyAsn1, RSAPrivateKey);

    return {
        ...rsaPrivateKey,
        // Versions and publicExponent small, so just transform them to numbers
        version: integerFromArrayBuffer(rsaPrivateKey.version),
        publicExponent: integerFromArrayBuffer(rsaPrivateKey.publicExponent),
    };
};

const toRsaPrivateKey = (keyData) => encodeAsn1(keyData, RSAPrivateKey);

const toEd25519KeyData = (rsaPrivateKeyAsn1) => decodeAsn1(rsaPrivateKeyAsn1, CurvePrivateKey);

const toEd25519PrivateKey = (rsaPrivateKeyAsn1) => encodeAsn1(rsaPrivateKeyAsn1, CurvePrivateKey);

export default {
    rsa: { toKeyData: toRsaKeyData, toPrivateKey: toRsaPrivateKey },
    ed25519: { toKeyData: toEd25519KeyData, toPrivateKey: toEd25519PrivateKey },
};
