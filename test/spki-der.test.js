import fs from 'fs';
import { decomposePublicKey, composePublicKey } from '../src';
import { typedArrayToUint8Array } from '../src/util/binary';

const KEYS = {
    'rsa-1': fs.readFileSync('test/fixtures/spki-der/rsa-1.pub'),
    'ed25519-1': fs.readFileSync('test/fixtures/spki-der/ed25519-1.pub'),
    'ec-1': fs.readFileSync('test/fixtures/spki-der/ec-1.pub'),
    'ec-invalid-1': fs.readFileSync('test/fixtures/spki-der/ec-invalid-1.pub'),
    'invalid-1': fs.readFileSync('test/fixtures/spki-der/invalid-1.pub'),
};

describe('decomposePublicKey', () => {
    it('should decompose a RSA key', () => {
        expect(decomposePublicKey(KEYS['rsa-1'], { format: 'spki-der' })).toMatchSnapshot();
    });

    it('should decompose a EC key, secp256k1', () => {
        expect(decomposePublicKey(KEYS['ec-1'], { format: 'spki-der' })).toMatchSnapshot();
    });

    it('should fail to decompose a EC key with an invalid curve', () => {
        expect.assertions(2);

        try {
            decomposePublicKey(KEYS['ec-invalid-1'], { format: 'spki-der' });
        } catch (err) {
            expect(err.message).toBe('Unsupported named curve OID \'0.20.999\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });

    it('should decompose a ED25519 key', () => {
        expect(decomposePublicKey(KEYS['ed25519-1'], { format: 'spki-der' })).toMatchSnapshot();
    });

    it('should also support Uint8Array, ArrayBuffer and string besides Node\'s Buffer', () => {
        const nodeBuffer = fs.readFileSync('test/fixtures/spki-der/rsa-1.pub');

        expect(decomposePublicKey(typedArrayToUint8Array(nodeBuffer), { format: 'spki-der' })).toMatchSnapshot();
        expect(decomposePublicKey(typedArrayToUint8Array(nodeBuffer).buffer, { format: 'spki-der' })).toMatchSnapshot();
        expect(decomposePublicKey(nodeBuffer.toString('binary'), { format: 'spki-der' })).toMatchSnapshot();
    });

    it('should fail if the key algorithm is not supported', () => {
        expect.assertions(2);

        try {
            decomposePublicKey(KEYS['invalid-1'], { format: 'spki-der' });
        } catch (err) {
            expect(err.message).toBe('Unsupported key algorithm OID \'0.20.999\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });

    it('should fail if the input key is invalid', () => {
        expect.assertions(2);

        try {
            decomposePublicKey('', { format: 'spki-der' });
        } catch (err) {
            expect(err.message).toBe('Failed to decode SubjectPublicKeyInfo');
            expect(err.code).toBe('DECODE_ASN1_FAILED');
        }
    });
});

describe('composePublicKey', () => {
    it('should compose a RSA key (mirroring)', () => {
        const decomposedKey = decomposePublicKey(KEYS['rsa-1'], { format: 'spki-der' });
        const composedKey = composePublicKey(decomposedKey);

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-1']));
    });

    it('should compose a EC key (mirroring)', () => {
        const decomposedKey = decomposePublicKey(KEYS['ec-1'], { format: 'spki-der' });
        const composedKey = composePublicKey(decomposedKey);

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['ec-1']));
    });

    it('should fail to compose a EC key with an invalid curve', () => {
        const decomposedKey = decomposePublicKey(KEYS['ec-1'], { format: 'spki-der' });

        expect.assertions(2);

        try {
            composePublicKey({
                ...decomposedKey,
                keyAlgorithm: {
                    ...decomposedKey.keyAlgorithm,
                    namedCurve: 'foo',
                },
            }, { format: 'spki-der' });
        } catch (err) {
            expect(err.message).toBe('Unsupported named curve \'foo\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });

    it('should compose a ED25519 key (mirroring)', () => {
        const decomposedKey = decomposePublicKey(KEYS['ed25519-1'], { format: 'spki-der' });
        const composedKey = composePublicKey(decomposedKey);

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['ed25519-1']));
    });

    it('should fail if the key algorithm is not supported', () => {
        expect.assertions(2);

        try {
            composePublicKey({
                format: 'spki-der',
                keyAlgorithm: { id: 'foo' },
                keyData: {},
            });
        } catch (err) {
            expect(err.message).toBe('Unsupported key algorithm id \'foo\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });

    it('should support a string in the key algorithm', () => {
        const decomposedKey = decomposePublicKey(KEYS['rsa-1'], { format: 'spki-der' });
        const composedKey = composePublicKey({ ...decomposedKey, keyAlgorithm: 'rsa-encryption' });

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-1']));
    });

    it('should support the \'rsa\' alias as the key algorithm', () => {
        const decomposedKey1 = decomposePublicKey(KEYS['rsa-1'], { format: 'spki-der' });
        const composedKey1 = composePublicKey({ ...decomposedKey1, keyAlgorithm: 'rsa' });

        expect(composedKey1).toEqual(typedArrayToUint8Array(KEYS['rsa-1']));

        const decomposedKey2 = decomposePublicKey(KEYS['rsa-1'], { format: 'spki-der' });
        const composedKey2 = composePublicKey({ ...decomposedKey2, keyAlgorithm: { id: 'rsa' } });

        expect(composedKey2).toEqual(typedArrayToUint8Array(KEYS['rsa-1']));
    });
});
