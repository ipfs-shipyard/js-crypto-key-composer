import fs from 'fs';
import { decomposePublicKey, composePublicKey } from '../src';
import { typedArrayToUint8Array } from '../src/util/binary';

const KEYS = {
    'rsa-1': fs.readFileSync('test/fixtures/spki-pem/rsa-1.pub'),
    'ed25519-1': fs.readFileSync('test/fixtures/spki-pem/ed25519-1.pub'),
};

describe('decomposePublicKey', () => {
    it('should decompose a RSA key', () => {
        expect(decomposePublicKey(KEYS['rsa-1'], { format: 'spki-pem' })).toMatchSnapshot();
    });

    it('should decompose a ED25519 key', () => {
        expect(decomposePublicKey(KEYS['ed25519-1'], { format: 'spki-pem' })).toMatchSnapshot();
    });

    it('should also support Uint8Array, ArrayBuffer and string besides Node\'s Buffer', () => {
        const nodeBuffer = fs.readFileSync('test/fixtures/spki-pem/rsa-1.pub');

        expect(decomposePublicKey(typedArrayToUint8Array(nodeBuffer), { format: 'spki-pem' })).toMatchSnapshot();
        expect(decomposePublicKey(typedArrayToUint8Array(nodeBuffer).buffer, { format: 'spki-pem' })).toMatchSnapshot();
        expect(decomposePublicKey(nodeBuffer.toString('binary'), { format: 'spki-pem' })).toMatchSnapshot();
    });

    it('should fail if the input key is invalid', () => {
        expect.assertions(2);

        try {
            decomposePublicKey('', { format: 'spki-pem' });
        } catch (err) {
            expect(err.message).toBe('Failed to decode PEM');
            expect(err.code).toBe('DECODE_PEM_FAILED');
        }
    });
});

describe('composePublicKey', () => {
    it('should compose a RSA key (mirroring)', () => {
        const decomposedKey = decomposePublicKey(KEYS['rsa-1'], { format: 'spki-pem' });
        const composedKey = composePublicKey(decomposedKey);

        expect(composedKey).toEqual(KEYS['rsa-1'].toString());
    });

    it('should compose a ED25519 key (mirroring)', () => {
        const decomposedKey = decomposePublicKey(KEYS['ed25519-1'], { format: 'spki-pem' });
        const composedKey = composePublicKey(decomposedKey);

        expect(composedKey).toEqual(KEYS['ed25519-1'].toString());
    });
});
