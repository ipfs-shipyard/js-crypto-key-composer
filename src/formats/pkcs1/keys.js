import { RSAPrivateKey } from './asn1-entities';
import { decodeAsn1, encodeAsn1 } from '../../util/asn1';
import { uint8ArrayToInteger } from '../../util/binary';
import { InvalidKeyDataError } from '../../util/errors';

export const decomposeRsaPrivateKey = (rsaPrivateKeyAsn1) => {
    const rsaPrivateKey = decodeAsn1(rsaPrivateKeyAsn1, RSAPrivateKey);

    return {
        keyAlgorithm: {
            id: 'rsa-encryption',
        },
        keyData: {
            ...rsaPrivateKey,
            // Versions and publicExponent small, so just transform them to numbers
            version: uint8ArrayToInteger(rsaPrivateKey.version),
            publicExponent: uint8ArrayToInteger(rsaPrivateKey.publicExponent),
        },
    };
};

export const composeRsaPrivateKey = (rsaKeyData) => {
    if (rsaKeyData.version < 0 || rsaKeyData.version > 2) {
        throw new InvalidKeyDataError('Version must be 0 or 1');
    }

    if (rsaKeyData.otherPrimeInfos && rsaKeyData.version < 1) {
        throw new InvalidKeyDataError('Version must be set to 1 when defining \'otherPrimeInfos\'');
    }

    return encodeAsn1(rsaKeyData, RSAPrivateKey);
};
