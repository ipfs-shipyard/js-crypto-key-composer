import { invert } from 'lodash';

export const OIDS = {
    // RSA
    '1.2.840.113549.1.1.1': 'rsa-encryption',
    '1.2.840.113549.1.1.2': 'md2-with-rsa-encryption',
    '1.2.840.113549.1.1.3': 'md4-with-rsa-encryption',
    '1.2.840.113549.1.1.4': 'md5-with-rsa-encryption',
    '1.2.840.113549.1.1.5': 'sha1-with-rsa-encryption',
    '1.2.840.113549.1.1.14': 'sha224-with-rsa-encryption',
    '1.2.840.113549.1.1.11': 'sha256-with-rsa-encryption',
    '1.2.840.113549.1.1.12': 'sha384-with-rsa-encryption',
    '1.2.840.113549.1.1.13': 'sha512-with-rsa-encryption',
    '1.2.840.113549.1.1.15': 'sha512-224-with-rsa-encryption',
    '1.2.840.113549.1.1.16': 'sha512-256-with-rsa-encryption',
    '1.2.840.113549.1.1.7': 'rsaes-oaep',
    '1.2.840.113549.1.1.10': 'rsassa-pss',

    // Ed25519
    '1.3.101.112': 'ed25519',

    // PBE related
    '2.16.840.1.101.3.4.1.2': 'aes128-cbc',
    '2.16.840.1.101.3.4.1.22': 'aes192-cbc',
    '2.16.840.1.101.3.4.1.42': 'aes256-cbc',
    '1.2.840.113549.3.2': 'rc2-cbc',
    '1.3.14.3.2.7': 'des-cbc',
    '1.2.840.113549.3.7': 'des-ede3-cbc',
    '1.2.840.113549.1.5.13': 'pbes2',
    '1.2.840.113549.1.5.12': 'pbkdf2',
    '1.2.840.113549.2.7': 'hmac-with-sha1',
    '1.2.840.113549.2.8': 'hmac-with-sha224',
    '1.2.840.113549.2.9': 'hmac-with-sha256',
    '1.2.840.113549.2.10': 'hmac-with-sha384',
    '1.2.840.113549.2.11': 'hmac-with-sha512',
};

export const FLIPPED_OIDS = invert(OIDS);
