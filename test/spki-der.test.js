import fs from 'fs';
import { decomposePublicKey, composePublicKey } from '../src';
import { typedArrayToUint8Array } from '../src/util/binary';

const KEYS = {
    'rsa-1': fs.readFileSync('test/fixtures/spki-der/rsa-1'),
    'ed25519-1': fs.readFileSync('test/fixtures/spki-der/ed25519-1'),
    'invalid-1': fs.readFileSync('test/fixtures/spki-der/invalid-1'),
};

describe('decomposePublicKey', () => {
    it('should decompose a standard RSA key', () => {
        expect(decomposePublicKey(KEYS['rsa-1'], { format: 'spki-der' })).toMatchSnapshot();
    });

    it('should decompose a ed25519 key', () => {
        expect(decomposePublicKey(KEYS['ed25519-1'], { format: 'spki-der' })).toMatchSnapshot();
    });

    it('should also support Uint8Array, ArrayBuffer and string besides Node\'s Buffer', () => {
        const nodeBuffer = fs.readFileSync('test/fixtures/spki-der/rsa-1');

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
            expect(err.code).toBe('INVALID_INPUT_KEY');
        }
    });
});

describe('composePublicKey', () => {
    it('should compose a standard RSA key (mirroring)', () => {
        const decomposedKey = decomposePublicKey(KEYS['rsa-1'], { format: 'spki-der' });
        const composedKey = composePublicKey(decomposedKey);

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-1']));
    });

    it('should compose a ed25519 key (mirroring)', () => {
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
        const decomposedKey = decomposePublicKey(KEYS['rsa-1'], { format: 'spki-der' });
        const composedKey = composePublicKey({ ...decomposedKey, keyAlgorithm: 'rsa' });

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-1']));
    });
});
