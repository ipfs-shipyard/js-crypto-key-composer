import { decomposePrivateKeyInfo, composePrivateKeyInfo } from './keys';
import { maybeDecryptPrivateKeyInfo, maybeEncryptPrivateKeyInfo } from './encryption';
import { PrivateKeyInfo } from './asn1-entities';
import { decodeAsn1, encodeAsn1 } from '../../util/asn1';
import { InvalidInputKeyError, DecodeAsn1FailedError } from '../../util/errors';

export const decomposeKey = (encryptedPrivateKeyInfoAsn1, options) => {
    // Attempt to decrypt privateKeyInfoAsn1 as it might actually be a EncryptedPrivateKeyInfo
    const { privateKeyInfoAsn1, encryptionAlgorithm } = maybeDecryptPrivateKeyInfo(encryptedPrivateKeyInfoAsn1, options.password);

    // Attempt to decode as PrivateKeyInfo
    let privateKeyInfo;

    try {
        privateKeyInfo = decodeAsn1(privateKeyInfoAsn1, PrivateKeyInfo);
    } catch (err) {
        if (!encryptionAlgorithm && err instanceof DecodeAsn1FailedError) {
            throw new InvalidInputKeyError(err.message, { originalError: err });
        }

        throw err;
    }

    // Decompose the PrivateKeyInfo
    const { keyAlgorithm, keyData } = decomposePrivateKeyInfo(privateKeyInfo);

    return {
        format: 'pkcs8-der',
        keyAlgorithm,
        keyData,
        encryptionAlgorithm,
    };
};

export const composeKey = ({ keyAlgorithm, keyData, encryptionAlgorithm }, options) => {
    // Generate the PrivateKeyInfo based on the key algorithm & key data
    const privateKeyInfo = composePrivateKeyInfo(keyAlgorithm, keyData);

    // Encode PrivateKeyInfo into ASN1
    const privateKeyInfoAsn1 = encodeAsn1(privateKeyInfo, PrivateKeyInfo);

    // Do we need to encrypt as EncryptedPrivateKeyInfo?
    const encryptedPrivateKeyInfoAsn1 = maybeEncryptPrivateKeyInfo(privateKeyInfoAsn1, encryptionAlgorithm, options.password);

    return encryptedPrivateKeyInfoAsn1;
};
