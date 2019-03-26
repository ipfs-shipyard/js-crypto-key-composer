import oids from 'node-forge/lib/oids';
import { pickBy, invert } from 'lodash';

const onlyOids = pickBy(oids, (value, key) => key.indexOf('.') > 0);

export const OIDS = {
    ...onlyOids,

    // These OIDs are are commented in node-forge out and are associated to RSA keys
    '1.2.840.113549.1.1.2': 'md2WithRSAEncryption',
    '1.2.840.113549.1.1.3': 'md4WithRSAEncryption',

    // Override PKCS5 algorithm oids because they have wrong names
    '1.2.840.113549.1.5.12': 'PBKDF2',
    '1.2.840.113549.1.5.13': 'PBES2',

    // RC2
    '1.2.840.113549.3.2': 'rc2-cbc',

    // Ed25519
    '1.3.101.112': 'EdDSA25519',
};

export const FLIPPED_OIDS = invert(OIDS);

const KEY_TYPES = {
    // RSA key types
    rsaEncryption: 'rsa',
    md2WithRSAEncryption: 'rsa',
    md4WithRSAEncryption: 'rsa',
    md5WithRSAEncryption: 'rsa',
    sha1WithRSAEncryption: 'rsa',
    'RSAES-OAEP': 'rsa',
    mgf1: 'rsa',
    pSpecified: 'rsa',
    'RSASSA-PSS': 'rsa',
    sha256WithRSAEncryption: 'rsa',
    sha384WithRSAEncryption: 'rsa',
    sha512WithRSAEncryption: 'rsa',

    // Ed25519 key types
    EdDSA25519: 'ed25519',
};

export const keyTypeFromAlgorithm = (algorithm) => KEY_TYPES[algorithm] || KEY_TYPES[OIDS[algorithm]];
