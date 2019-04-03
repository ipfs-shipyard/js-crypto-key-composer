import { decomposeSubjectPublicKeyInfo, composeSubjectPublicKeyInfo } from './keys';
import { SubjectPublicKeyInfo } from './asn1-entities';
import { decodeAsn1, encodeAsn1 } from '../../util/asn1';
import { InvalidInputKeyError, DecodeAsn1FailedError } from '../../util/errors';

export const decomposeKey = (subjectPublicKeyAsn1) => {
    // Attempt to decode as SubjectPublicKeyInfo
    let subjectPublicKey;

    try {
        subjectPublicKey = decodeAsn1(subjectPublicKeyAsn1, SubjectPublicKeyInfo);
    } catch (err) {
        if (err instanceof DecodeAsn1FailedError) {
            throw new InvalidInputKeyError(err.message, { originalError: err });
        }

        throw err;
    }

    // Decompose the SubjectPublicKeyInfo
    const { keyAlgorithm, keyData } = decomposeSubjectPublicKeyInfo(subjectPublicKey);

    return {
        format: 'spki-der',
        keyAlgorithm,
        keyData,
    };
};

export const composeKey = ({ keyAlgorithm, keyData }) => {
    // Generate the SubjectPublicKeyInfo based on the key algorithm & key data
    const subjectPublicKeyInfo = composeSubjectPublicKeyInfo(keyAlgorithm, keyData);

    // Encode SubjectPublicKeyInfo into ASN1
    const subjectPublicKeyInfoAsn1 = encodeAsn1(subjectPublicKeyInfo, SubjectPublicKeyInfo);

    return subjectPublicKeyInfoAsn1;
};
