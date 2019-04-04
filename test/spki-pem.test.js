import fs from 'fs';
import { decomposePublicKey, composePublicKey } from '../src';
import { typedArrayToUint8Array } from '../src/util/binary';

const KEYS = {
    'rsa-1': fs.readFileSync('test/fixtures/spki-pem/rsa-1'),
    'ed25519-1': fs.readFileSync('test/fixtures/spki-pem/ed25519-1'),
};

describe('decomposePublicKey', () => {
    it('should decompose a standard RSA key', () => {
        expect(decomposePublicKey(KEYS['rsa-1'], { format: 'spki-pem' })).toMatchSnapshot();
    });

    it('should decompose a ed25519 key', () => {
        expect(decomposePublicKey(KEYS['ed25519-1'], { format: 'spki-pem' })).toMatchSnapshot();
    });

    it('should also support Uint8Array, ArrayBuffer and string besides Node\'s Buffer', () => {
        const nodeBuffer = fs.readFileSync('test/fixtures/spki-pem/rsa-1');

        expect(decomposePublicKey(typedArrayToUint8Array(nodeBuffer), { format: 'spki-pem' })).toMatchSnapshot();
        expect(decomposePublicKey(typedArrayToUint8Array(nodeBuffer).buffer, { format: 'spki-pem' })).toMatchSnapshot();
        expect(decomposePublicKey(nodeBuffer.toString('binary'), { format: 'spki-pem' })).toMatchSnapshot();
    });

    it('should fail if the input key is invalid', () => {
        expect.assertions(2);

        try {
            decomposePublicKey('', { format: 'spki-pem' });
        } catch (err) {
            expect(err.message).toBe('Failed to decode SPKI as PEM');
            expect(err.code).toBe('INVALID_INPUT_KEY');
        }
    });
});

describe('composePublicKey', () => {
    it('should compose a standard RSA key (mirroring)', () => {
        const decomposedKey = decomposePublicKey(KEYS['rsa-1'], { format: 'spki-pem' });
        const composedKey = composePublicKey(decomposedKey);

        expect(composedKey).toEqual(KEYS['rsa-1'].toString());
    });

    it('should compose a ed25519 key (mirroring)', () => {
        const decomposedKey = decomposePublicKey(KEYS['ed25519-1'], { format: 'spki-pem' });
        const composedKey = composePublicKey(decomposedKey);

        expect(composedKey).toEqual(KEYS['ed25519-1'].toString());
    });

    it('should fail if the key algorithm is not supported', () => {
        expect.assertions(2);

        try {
            composePublicKey({
                format: 'spki-pem',
                keyAlgorithm: { id: 'foo' },
                keyData: {},
            });
        } catch (err) {
            expect(err.message).toBe('Unsupported key algorithm id \'foo\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });

    it('should support a string in the key algorithm', () => {
        const decomposedKey = decomposePublicKey(KEYS['rsa-1'], { format: 'spki-pem' });
        const composedKey = composePublicKey({ ...decomposedKey, keyAlgorithm: 'rsa-encryption' });

        expect(composedKey).toEqual(KEYS['rsa-1'].toString());
    });

    it('should support the \'rsa\' alias as the key algorithm', () => {
        const decomposedKey1 = decomposePublicKey(KEYS['rsa-1'], { format: 'spki-pem' });
        const composedKey1 = composePublicKey({ ...decomposedKey1, keyAlgorithm: 'rsa' });

        expect(composedKey1).toEqual(KEYS['rsa-1'].toString());

        const decomposedKey2 = decomposePublicKey(KEYS['rsa-1'], { format: 'spki-pem' });
        const composedKey2 = composePublicKey({ ...decomposedKey2, keyAlgorithm: { id: 'rsa' } });

        expect(composedKey2).toEqual(KEYS['rsa-1'].toString());
    });
});
