/* eslint-disable babel/no-invalid-asn1, newline-per-chained-call */
import { define, objidValues } from '../../util/asn1';

const OtherPrimeInfo = define('OtherPrimeInfo', (asn1) => {
    asn1.seq().obj(
        asn1.key('prime').int(),
        asn1.key('exponent').int(),
        asn1.key('coefficient').int(),
    );
});

export const RsaPrivateKey = define('RSAPrivateKey', (asn1) => {
    asn1.seq().obj(
        asn1.key('version').int(),
        asn1.key('modulus').int(),
        asn1.key('publicExponent').int(),
        asn1.key('privateExponent').int(),
        asn1.key('prime1').int(),
        asn1.key('prime2').int(),
        asn1.key('exponent1').int(),
        asn1.key('exponent2').int(),
        asn1.key('coefficient').int(),
        asn1.key('otherPrimeInfos').seqof(OtherPrimeInfo).optional(),
    );
});

export const RsaPublicKey = define('RSAPublicKey', (asn1) => {
    asn1.seq().obj(
        asn1.key('modulus').int(),
        asn1.key('publicExponent').int()
    );
});

export const EcPrivateKey = define('ECPrivateKey', (asn1) => {
    asn1.seq().obj(
        asn1.key('version').int(),
        asn1.key('privateKey').octstr(),
        asn1.key('parameters').explicit(0).objid(objidValues),
        asn1.key('publicKey').explicit(1).bitstr().optional(),
    );
});
