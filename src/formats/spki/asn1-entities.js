/* eslint-disable newline-per-chained-call */
import { define, objidValues } from '../../util/asn1';

export const AlgorithmIdentifier = define('AlgorithmIdentifier', (asn1) => {
    asn1.seq().obj(
        asn1.key('id').objid(objidValues),
        asn1.key('parameters').optional().any()
    );
});

export const SubjectPublicKeyInfo = define('SubjectPublicKeyInfo', (asn1) => {
    asn1.seq().obj(
        asn1.key('algorithm').use(AlgorithmIdentifier),
        asn1.key('publicKey').bitstr()
    );
});

export const EcParameters = define('ECParameters', (asn1) => {
    asn1.objid(objidValues);
});
