const KEY_TYPES = {
    // RSA key types
    'rsa-encryption': 'rsa',
    'md2-with-rsa-encryption': 'rsa',
    'md4-with-rsa-encryption': 'rsa',
    'md5-with-rsa-encryption': 'rsa',
    'sha1-with-rsa-encryption': 'rsa',
    'rsaes-oaep': 'rsa',
    mgf1: 'rsa',
    'p-specified': 'rsa',
    'rsassa-pss': 'rsa',
    'sha256-with-rsa-encryption': 'rsa',
    'sha384-with-rsa-encryption': 'rsa',
    'sha512-with-rsa-encryption': 'rsa',

    // ED25519 key types
    ed25519: 'ed25519',
};

export const KEY_ALIASES = {
    rsa: { id: 'rsa-encryption' },
};

export default KEY_TYPES;
