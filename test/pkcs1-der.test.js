import fs from 'fs';
import { decomposePrivateKey, composePrivateKey } from '../src';
import { typedArrayToUint8Array } from '../src/util/binary';

const KEYS = {
    'rsa-1': fs.readFileSync('test/fixtures/pkcs1-der/rsa-1'),
    'rsa-2': fs.readFileSync('test/fixtures/pkcs1-der/rsa-2'),
    'rsa-3': fs.readFileSync('test/fixtures/pkcs1-der/rsa-3'),
};

describe('decomposePrivateKey', () => {
    it('should decompose a RSA key', () => {
        expect(decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs1-der' })).toMatchSnapshot();
    });

    it('should decompose a RSA key with 3 primes', () => {
        expect(decomposePrivateKey(KEYS['rsa-2'], { format: 'pkcs1-der' })).toMatchSnapshot();
    });

    it('should decompose a RSA key with 4 primes', () => {
        expect(decomposePrivateKey(KEYS['rsa-3'], { format: 'pkcs1-der' })).toMatchSnapshot();
    });

    it('should also support Uint8Array, ArrayBuffer and string besides Node\'s Buffer', () => {
        const nodeBuffer = fs.readFileSync('test/fixtures/pkcs1-der/rsa-1');

        expect(decomposePrivateKey(typedArrayToUint8Array(nodeBuffer), { format: 'pkcs1-der' })).toMatchSnapshot();
        expect(decomposePrivateKey(typedArrayToUint8Array(nodeBuffer).buffer, { format: 'pkcs1-der' })).toMatchSnapshot();
        expect(decomposePrivateKey(nodeBuffer.toString('binary'), { format: 'pkcs1-der' })).toMatchSnapshot();
    });

    it('should fail if the input key is invalid', () => {
        expect.assertions(2);

        try {
            decomposePrivateKey('', { format: 'pkcs1-der' });
        } catch (err) {
            expect(err.message).toBe('Failed to decode RSAPrivateKey');
            expect(err.code).toBe('DECODE_ASN1_FAILED');
        }
    });
});

describe('composePrivateKey', () => {
    it('should compose a RSA key (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs1-der' });
        const composedKey = composePrivateKey(decomposedKey);

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-1']));
    });

    it('should compose a RSA key with 3 primes (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(KEYS['rsa-2'], { format: 'pkcs1-der' });
        const composedKey = composePrivateKey(decomposedKey);

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-2']));
    });

    it('should compose a RSA key with 4 primes (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(KEYS['rsa-3'], { format: 'pkcs1-der' });
        const composedKey = composePrivateKey(decomposedKey);

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-3']));
    });

    it('should fail if the key is not a RSA key', () => {
        expect.assertions(2);

        try {
            composePrivateKey({
                format: 'pkcs1-der',
                keyAlgorithm: { id: 'foo' },
                keyData: {},
            });
        } catch (err) {
            expect(err.message).toBe('The key algorithm id for PKCS1 must be one of RSA\'s');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });

    it('should fail if an encryption algorithm was specified', () => {
        expect.assertions(2);

        try {
            composePrivateKey({
                format: 'pkcs1-der',
                encryptionAlgorithm: {},
                keyAlgorithm: { id: 'rsa-encryption' },
                keyData: {},
            });
        } catch (err) {
            expect(err.message).toBe('The PKCS1 DER format does not support encryption');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });

    it('should support a string in the key algorithm', () => {
        const decomposedKey = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs1-der' });
        const composedKey = composePrivateKey({ ...decomposedKey, keyAlgorithm: 'rsa-encryption' });

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-1']));
    });

    it('should support the \'rsa\' alias as the key algorithm', () => {
        const decomposedKey1 = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs1-der' });
        const composedKey1 = composePrivateKey({ ...decomposedKey1, keyAlgorithm: 'rsa' });

        expect(composedKey1).toEqual(typedArrayToUint8Array(KEYS['rsa-1']));

        const decomposedKey2 = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs1-der' });
        const composedKey2 = composePrivateKey({ ...decomposedKey2, keyAlgorithm: { id: 'rsa' } });

        expect(composedKey2).toEqual(typedArrayToUint8Array(KEYS['rsa-1']));
    });
});
