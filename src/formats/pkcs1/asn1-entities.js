/* eslint-disable babel/no-invalid-this, newline-per-chained-call */
import asn1 from '@lordvlad/asn1.js';

export const OtherPrimeInfo = asn1.define('OtherPrimeInfo', function () {
    this.seq().obj(
        this.key('prime').int(),
        this.key('exponent').int(),
        this.key('coefficient').int(),
    );
});

export const RsaPrivateKey = asn1.define('RSAPrivateKey', function () {
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
