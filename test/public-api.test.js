import fs from 'fs';
import { decomposePrivateKey, composePrivateKey, decomposePublicKey, composePublicKey, getKeyTypeFromAlgorithm } from '../src';

const PRIVATE_KEYS = {
    'pkcs1-pem-rsa-1': fs.readFileSync('test/fixtures/pkcs1-pem/rsa-1'),
    'pkcs8-der-invalid-1': fs.readFileSync('test/fixtures/pkcs8-der/invalid-1'),
};

const PUBLIC_KEYS = {
    'spki-pem-rsa-1': fs.readFileSync('test/fixtures/spki-pem/rsa-1.pub'),
    'spki-der-invalid-1': fs.readFileSync('test/fixtures/spki-der/invalid-1.pub'),
};

describe('decomposePrivateKey', () => {
    it('should decompose with a single format', () => {
        expect(decomposePrivateKey(PRIVATE_KEYS['pkcs1-pem-rsa-1'], { format: 'pkcs1-pem' })).toMatchSnapshot();
    });

    it('should decompose with multiple formats', () => {
        expect(decomposePrivateKey(PRIVATE_KEYS['pkcs1-pem-rsa-1'], { format: ['pkcs1-der', 'pkcs1-pem'] })).toMatchSnapshot();
    });

    it('should fail if input key is invalid', () => {
        expect.assertions(2);

        try {
            decomposePrivateKey(2);
        } catch (err) {
            expect(err.message).toBe('Expecting input key to be one of: Uint8Array, ArrayBuffer, string');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }
    });

    it('should fail if format is invalid', () => {
        expect.assertions(2);

        try {
            decomposePrivateKey('', { format: 2 });
        } catch (err) {
            expect(err.message).toBe('Expecting format to be a string');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }
    });

    it('should fail if one of the formats is invalid', () => {
        expect.assertions(2);

        try {
            decomposePrivateKey('', { format: [2] });
        } catch (err) {
            expect(err.message).toBe('Expecting format to be a string');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }
    });

    it('should fail if format is not supported', () => {
        expect.assertions(2);

        try {
            decomposePrivateKey('', { format: 'foo' });
        } catch (err) {
            expect(err.message).toBe('Unsupported format \'foo\'');
            expect(err.code).toBe('UNSUPPORTED_FORMAT');
        }
    });

    it('should fail if key does not match a single format', () => {
        expect.assertions(2);

        try {
            decomposePrivateKey('', { format: 'pkcs1-pem' });
        } catch (err) {
            expect(err.message).toBe('Failed to decode PEM');
            expect(err.code).toBe('DECODE_PEM_FAILED');
        }
    });

    it('should fail if key does not match any formats', () => {
        expect.assertions(4);

        try {
            decomposePrivateKey('', { format: ['pkcs1-der', 'pkcs1-pem'] });
        } catch (err) {
            expect(err.message).toBe('No format was able to recognize the input key');
            expect(err.code).toBe('AGGREGATED_ERROR');
            expect(err.errors['pkcs1-der'].code).toBe('DECODE_ASN1_FAILED');
            expect(err.errors['pkcs1-pem'].code).toBe('DECODE_PEM_FAILED');
        }
    });

    it('should fail with the internal error when trying a single format', () => {
        expect.assertions(2);

        try {
            decomposePrivateKey(PRIVATE_KEYS['pkcs8-der-invalid-1'], { format: 'pkcs8-der' });
        } catch (err) {
            expect(err.message).toBe('Unsupported key algorithm OID \'0.20.999\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });

    it('should fail with the internal error when trying multiple formats', () => {
        expect.assertions(2);

        try {
            decomposePrivateKey(PRIVATE_KEYS['pkcs8-der-invalid-1'], { format: ['pkcs8-der'] });
        } catch (err) {
            expect(err.message).toBe('Unsupported key algorithm OID \'0.20.999\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });
});

describe('composePrivateKey', () => {
    it('should fail if the decomposed key is invalid', () => {
        expect.assertions(2);

        try {
            composePrivateKey([]);
        } catch (err) {
            expect(err.message).toBe('Expecting decomposed key to be an object');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }
    });

    it('should fail if format is invalid', () => {
        expect.assertions(2);

        try {
            composePrivateKey({ format: 2 });
        } catch (err) {
            expect(err.message).toBe('Expecting format to be a string');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }
    });

    it('should fail if key algorithm is invalid', () => {
        expect.assertions(4);

        try {
            composePrivateKey({ format: 'pkcs8-der', keyAlgorithm: [] });
        } catch (err) {
            expect(err.message).toBe('Expecting key algorithm to be an object');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }

        try {
            composePrivateKey({ format: 'pkcs8-der', keyAlgorithm: { id: 2 } });
        } catch (err) {
            expect(err.message).toBe('Expecting key algorithm id to be a string');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }
    });

    it('should fail if key data is invalid', () => {
        expect.assertions(2);

        try {
            composePrivateKey({
                format: 'pkcs8-der',
                keyAlgorithm: { id: 'rsa-encryption' },
                keyData: [],
            });
        } catch (err) {
            expect(err.message).toBe('Expecting key data to be an object');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }
    });

    it('should fail if encryption algorithm is invalid', () => {
        const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['pkcs1-pem-rsa-1'], { format: 'pkcs1-pem' });

        expect.assertions(6);

        try {
            composePrivateKey({
                ...decomposedKey,
                encryptionAlgorithm: [],
            }, { password: 'password' });
        } catch (err) {
            expect(err.message).toBe('Expecting encryption algorithm to be an object');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }

        try {
            composePrivateKey({
                ...decomposedKey,
                encryptionAlgorithm: {
                    keyDerivationFunc: 2,
                },
            }, { password: 'password' });
        } catch (err) {
            expect(err.message).toBe('Expecting key derivation func to be an object');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }

        try {
            composePrivateKey({
                ...decomposedKey,
                encryptionAlgorithm: {
                    encryptionScheme: 2,
                },
            }, { password: 'password' });
        } catch (err) {
            expect(err.message).toBe('Expecting encryption scheme to be an object');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }
    });
});

describe('decomposePublicKey', () => {
    it('should decompose with a single format', () => {
        expect(decomposePublicKey(PUBLIC_KEYS['spki-pem-rsa-1'], { format: 'spki-pem' })).toMatchSnapshot();
    });

    it('should decompose with multiple formats', () => {
        expect(decomposePublicKey(PUBLIC_KEYS['spki-pem-rsa-1'], { format: ['spki-der', 'spki-pem'] })).toMatchSnapshot();
    });

    it('should fail if input key is invalid', () => {
        expect.assertions(2);

        try {
            decomposePublicKey(2);
        } catch (err) {
            expect(err.message).toBe('Expecting input key to be one of: Uint8Array, ArrayBuffer, string');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }
    });

    it('should fail if format is invalid', () => {
        expect.assertions(2);

        try {
            decomposePublicKey('', { format: 2 });
        } catch (err) {
            expect(err.message).toBe('Expecting format to be a string');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }
    });

    it('should fail if one of the formats is invalid', () => {
        expect.assertions(2);

        try {
            decomposePublicKey('', { format: [2] });
        } catch (err) {
            expect(err.message).toBe('Expecting format to be a string');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }
    });

    it('should fail if format is not supported', () => {
        expect.assertions(2);

        try {
            decomposePublicKey('', { format: 'foo' });
        } catch (err) {
            expect(err.message).toBe('Unsupported format \'foo\'');
            expect(err.code).toBe('UNSUPPORTED_FORMAT');
        }
    });

    it('should fail if key does not match a single format', () => {
        expect.assertions(2);

        try {
            decomposePublicKey('', { format: 'spki-pem' });
        } catch (err) {
            expect(err.message).toBe('Failed to decode PEM');
            expect(err.code).toBe('DECODE_PEM_FAILED');
        }
    });

    it('should fail if key does not match any formats', () => {
        expect.assertions(4);

        try {
            decomposePublicKey('', { format: ['spki-der', 'spki-pem'] });
        } catch (err) {
            expect(err.message).toBe('No format was able to recognize the input key');
            expect(err.code).toBe('AGGREGATED_ERROR');
            expect(err.errors['spki-der'].code).toBe('DECODE_ASN1_FAILED');
            expect(err.errors['spki-pem'].code).toBe('DECODE_PEM_FAILED');
        }
    });

    it('should fail with the internal error when trying a single format', () => {
        expect.assertions(2);

        try {
            decomposePublicKey(PUBLIC_KEYS['spki-der-invalid-1'], { format: 'spki-der' });
        } catch (err) {
            expect(err.message).toBe('Unsupported key algorithm OID \'0.20.999\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });

    it('should fail with the internal error when trying multiple formats', () => {
        expect.assertions(2);

        try {
            decomposePublicKey(PUBLIC_KEYS['spki-der-invalid-1'], { format: ['spki-der'] });
        } catch (err) {
            expect(err.message).toBe('Unsupported key algorithm OID \'0.20.999\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });
});

describe('composePublicKey', () => {
    it('should fail if the decomposed key is invalid', () => {
        expect.assertions(2);

        try {
            composePublicKey([]);
        } catch (err) {
            expect(err.message).toBe('Expecting decomposed key to be an object');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }
    });

    it('should fail if format is invalid', () => {
        expect.assertions(2);

        try {
            composePublicKey({ format: 2 });
        } catch (err) {
            expect(err.message).toBe('Expecting format to be a string');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }
    });

    it('should fail if key algorithm is invalid', () => {
        expect.assertions(4);

        try {
            composePublicKey({ format: 'spki-der', keyAlgorithm: [] });
        } catch (err) {
            expect(err.message).toBe('Expecting key algorithm to be an object');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }

        try {
            composePublicKey({ format: 'spki-der', keyAlgorithm: { id: 2 } });
        } catch (err) {
            expect(err.message).toBe('Expecting key algorithm id to be a string');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }
    });

    it('should fail if key data is invalid', () => {
        expect.assertions(2);

        try {
            composePublicKey({
                format: 'spki-der',
                keyAlgorithm: { id: 'rsa-encryption' },
                keyData: [],
            });
        } catch (err) {
            expect(err.message).toBe('Expecting key data to be an object');
            expect(err.code).toBe('UNEXPECTED_TYPE');
        }
    });
});

describe('getKeyTypeFromAlgorithm', () => {
    it('should return undefined if unknown', () => {
        expect(getKeyTypeFromAlgorithm('foo')).toBe(undefined);
    });

    it('should return \'rsa\' for all RSA variants', () => {
        expect(getKeyTypeFromAlgorithm('rsa-encryption')).toBe('rsa');
        expect(getKeyTypeFromAlgorithm('md2-with-rsa-encryption')).toBe('rsa');
        expect(getKeyTypeFromAlgorithm('md5-with-rsa-encryption')).toBe('rsa');
        expect(getKeyTypeFromAlgorithm('sha1-with-rsa-encryption')).toBe('rsa');
        expect(getKeyTypeFromAlgorithm('sha224-with-rsa-encryption')).toBe('rsa');
        expect(getKeyTypeFromAlgorithm('sha256-with-rsa-encryption')).toBe('rsa');
        expect(getKeyTypeFromAlgorithm('sha384-with-rsa-encryption')).toBe('rsa');
        expect(getKeyTypeFromAlgorithm('sha512-224-with-rsa-encryption')).toBe('rsa');
        expect(getKeyTypeFromAlgorithm('sha512-256-with-rsa-encryption')).toBe('rsa');
    });

    it('should return \'ed25519\' for all ED25519 variants', () => {
        expect(getKeyTypeFromAlgorithm('ed25519')).toBe('ed25519');
    });

    it('should return \'ec\' for all EC variants', () => {
        expect(getKeyTypeFromAlgorithm('ec-public-key')).toBe('ec');
        expect(getKeyTypeFromAlgorithm('ec-dh')).toBe('ec');
        expect(getKeyTypeFromAlgorithm('ec-mqv')).toBe('ec');
    });

    it('should allow passing the key algoritm object', () => {
        expect(getKeyTypeFromAlgorithm({ id: 'rsa-encryption' })).toBe('rsa');
    });

    it('should return undefined on nulish input', () => {
        expect(getKeyTypeFromAlgorithm(null)).toBe(undefined);
        expect(getKeyTypeFromAlgorithm(undefined)).toBe(undefined);
    });
});
