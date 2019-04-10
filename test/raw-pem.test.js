import fs from 'fs';
import { decomposePrivateKey, composePrivateKey, decomposePublicKey, composePublicKey } from '../src';
import { typedArrayToUint8Array } from '../src/util/binary';

const PRIVATE_KEYS = {
    'rsa-1': fs.readFileSync('test/fixtures/raw-pem/rsa-1'),
    'rsa-2': fs.readFileSync('test/fixtures/raw-pem/rsa-2'),
    'ec-1': fs.readFileSync('test/fixtures/raw-pem/ec-1'),
    'ec-2': fs.readFileSync('test/fixtures/raw-pem/ec-2'),
    'ec-3': fs.readFileSync('test/fixtures/raw-pem/ec-3'),

    'enc-1': fs.readFileSync('test/fixtures/raw-pem/enc-1'),
    'enc-2': fs.readFileSync('test/fixtures/raw-pem/enc-2'),
    'enc-3': fs.readFileSync('test/fixtures/raw-pem/enc-3'),
    'enc-4': fs.readFileSync('test/fixtures/raw-pem/enc-4'),
    'enc-5': fs.readFileSync('test/fixtures/raw-pem/enc-5'),
    'enc-6': fs.readFileSync('test/fixtures/raw-pem/enc-6'),
    'enc-7': fs.readFileSync('test/fixtures/raw-pem/enc-7'),
    'enc-8': fs.readFileSync('test/fixtures/raw-pem/enc-8'),
    'enc-9': fs.readFileSync('test/fixtures/raw-pem/enc-9'),
};

const PUBLIC_KEYS = {
    'rsa-1': fs.readFileSync('test/fixtures/raw-pem/rsa-1.pub'),
};

const password = 'password';

describe('decomposePrivateKey', () => {
    it('should decompose a RSA key', () => {
        expect(decomposePrivateKey(PRIVATE_KEYS['rsa-1'], { format: 'raw-pem' })).toMatchSnapshot();
    });

    it('should decompose an encrypted RSA key', () => {
        expect(decomposePrivateKey(PRIVATE_KEYS['rsa-2'], { format: 'raw-pem', password })).toMatchSnapshot();
    });

    it('should decompose a EC key', () => {
        expect(decomposePrivateKey(PRIVATE_KEYS['ec-1'], { format: 'raw-pem' })).toMatchSnapshot();
    });

    it('should decompose an encrypted EC key', () => {
        expect(decomposePrivateKey(PRIVATE_KEYS['ec-2'], { format: 'raw-pem', password })).toMatchSnapshot();
    });

    it('should decompose a EC key with parameters', () => {
        expect(decomposePrivateKey(PRIVATE_KEYS['ec-3'], { format: 'raw-pem', password })).toMatchSnapshot();
    });

    it('should support also Uint8Array, ArrayBuffer and string besides node.js Buffer', () => {
        const nodeBuffer = fs.readFileSync('test/fixtures/raw-pem/rsa-1');

        expect(decomposePrivateKey(typedArrayToUint8Array(nodeBuffer), { format: 'raw-pem' })).toMatchSnapshot();
        expect(decomposePrivateKey(typedArrayToUint8Array(nodeBuffer).buffer, { format: 'raw-pem' })).toMatchSnapshot();
        expect(decomposePrivateKey(nodeBuffer.toString(), { format: 'raw-pem' })).toMatchSnapshot();
    });

    it('should fail if the input key is invalid', () => {
        expect.assertions(2);

        try {
            decomposePrivateKey('', { format: 'raw-pem' });
        } catch (err) {
            expect(err.message).toBe('Failed to decode PEM');
            expect(err.code).toBe('DECODE_PEM_FAILED');
        }
    });

    it('should fail if the there\'s no key type', () => {
        expect.assertions(2);

        const pem = `
-----BEGIN PRIVATE KEY-----
Zm9v
-----END PRIVATE KEY-----
        `;

        try {
            decomposePrivateKey(pem, { format: 'raw-pem' });
        } catch (err) {
            expect(err.message).toMatch('Could not find pem message matching patterns:');
            expect(err.code).toBe('DECODE_PEM_FAILED');
        }
    });

    it('should fail if the key type is unsupported', () => {
        expect.assertions(2);

        const pem = `
-----BEGIN FOO PRIVATE KEY-----
Zm9v
-----END FOO PRIVATE KEY-----
        `;

        try {
            decomposePrivateKey(pem, { format: 'raw-pem' });
        } catch (err) {
            expect(err.message).toBe('Unsupported key type \'foo\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });

    describe('decryption algorithms', () => {
        it('should decompose an encrypted key with aes128', () => {
            expect(decomposePrivateKey(PRIVATE_KEYS['enc-1'], { format: 'raw-pem', password })).toMatchSnapshot();
        });

        it('should decompose an encrypted key with aes192', () => {
            expect(decomposePrivateKey(PRIVATE_KEYS['enc-2'], { format: 'raw-pem', password })).toMatchSnapshot();
        });

        it('should decompose an encrypted key with aes256', () => {
            expect(decomposePrivateKey(PRIVATE_KEYS['enc-3'], { format: 'raw-pem', password })).toMatchSnapshot();
        });

        it('should decompose an encrypted key with rc2 40 bits', () => {
            expect(decomposePrivateKey(PRIVATE_KEYS['enc-4'], { format: 'raw-pem', password })).toMatchSnapshot();
        });

        it('should decompose an encrypted key with rc2 64 bits', () => {
            expect(decomposePrivateKey(PRIVATE_KEYS['enc-5'], { format: 'raw-pem', password })).toMatchSnapshot();
        });

        it('should decompose an encrypted key with rc2 128 bits (implicit)', () => {
            expect(decomposePrivateKey(PRIVATE_KEYS['enc-6'], { format: 'raw-pem', password })).toMatchSnapshot();
        });

        it('should decompose an encrypted key with rc2 128 bits', () => {
            expect(decomposePrivateKey(PRIVATE_KEYS['enc-7'], { format: 'raw-pem', password })).toMatchSnapshot();
        });

        it('should decompose an encrypted key with desCBC', () => {
            expect(decomposePrivateKey(PRIVATE_KEYS['enc-8'], { format: 'raw-pem', password })).toMatchSnapshot();
        });

        it('should decompose an encrypted key with DES-EDE3-CBC', () => {
            expect(decomposePrivateKey(PRIVATE_KEYS['enc-9'], { format: 'raw-pem', password })).toMatchSnapshot();
        });

        it('should fail to decompose an encrypted key without suplying a password', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(PRIVATE_KEYS['enc-1'], { format: 'raw-pem' });
            } catch (err) {
                expect(err.message).toBe('Please specify the password to decrypt the key');
                expect(err.code).toBe('MISSING_PASSWORD');
            }
        });

        it('should fail if the encryption algorithm is not supported', () => {
            const pem = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: FOO,3FF39C97F9E81CAF

THISISAFAKEKEY
-----END RSA PRIVATE KEY-----
`;

            expect.assertions(2);

            try {
                decomposePrivateKey(pem, {
                    format: 'raw-pem',
                    password,
                });
            } catch (err) {
                expect(err.message).toBe('Unsupported DEK-INFO algorithm \'FOO\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should fail to decompose an encrypted key with the wrong password', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(PRIVATE_KEYS['enc-1'], {
                    format: 'raw-pem',
                    password: 'foo',
                });
            } catch (err) {
                expect(err.message).toBe('Decryption failed, mostly likely the password is wrong');
                expect(err.code).toBe('DECRYPTION_FAILED');
            }
        });
    });
});

describe('composePrivateKey', () => {
    it('should compose RSA key (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['rsa-1'], { format: 'raw-pem' });
        const composedKey = composePrivateKey(decomposedKey);

        expect(composedKey).toBe(PRIVATE_KEYS['rsa-1'].toString());
    });

    it('should compose an encrypted RSA key (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['rsa-2'], { format: 'raw-pem', password });
        const composedKey = composePrivateKey(decomposedKey, { password });

        expect(composedKey).toBe(PRIVATE_KEYS['rsa-2'].toString());
    });

    it('should compose EC key (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['ec-1'], { format: 'raw-pem' });
        const composedKey = composePrivateKey(decomposedKey);

        expect(composedKey).toBe(PRIVATE_KEYS['ec-1'].toString());
    });

    it('should compose an encrypted EC key (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['ec-2'], { format: 'raw-pem', password });
        const composedKey = composePrivateKey(decomposedKey, { password });

        expect(composedKey).toBe(PRIVATE_KEYS['ec-2'].toString());
    });

    describe('encryption algorithms', () => {
        it('should compose an encrypted key with aes128 (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['enc-1'], { format: 'raw-pem', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toBe(PRIVATE_KEYS['enc-1'].toString());
        });

        it('should compose an encrypted key with aes192 (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['enc-2'], { format: 'raw-pem', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toBe(PRIVATE_KEYS['enc-2'].toString());
        });

        it('should compose an encrypted key with aes256 (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['enc-3'], { format: 'raw-pem', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toBe(PRIVATE_KEYS['enc-3'].toString());
        });

        it('should compose an encrypted key with rc2 40 bits (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['enc-4'], { format: 'raw-pem', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toBe(PRIVATE_KEYS['enc-4'].toString());
        });

        it('should compose an encrypted key with rc2 64 bits (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['enc-5'], { format: 'raw-pem', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toBe(PRIVATE_KEYS['enc-5'].toString());
        });

        it('should compose an encrypted key with rc2 128 bits (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['enc-6'], { format: 'raw-pem', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toBe(PRIVATE_KEYS['enc-6'].toString());
        });

        it('should fail if the RC2 parameter version (bits) specified in the encryption algorithm is not supported', () => {
            const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['rsa-1'], { format: 'raw-pem' });

            expect.assertions(2);

            try {
                composePrivateKey({
                    ...decomposedKey,
                    encryptionAlgorithm: {
                        encryptionScheme: { id: 'rc2-cbc', bits: 1 },
                    },
                }, {
                    password,
                });
            } catch (err) {
                expect(err.message).toBe('Unsupported RC2 bits parameter with value \'1\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should default to 128 bits for the rc2 encryption algorithm', () => {
            const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['rsa-1'], { format: 'raw-pem' });
            const composedKey = composePrivateKey({
                ...decomposedKey,
                encryptionAlgorithm: {
                    encryptionScheme: 'rc2-cbc',
                },
            }, { password });
            const recomposedKey = decomposePrivateKey(composedKey, { format: 'raw-pem', password });

            expect(recomposedKey.encryptionAlgorithm.encryptionScheme.id).toBe('rc2-cbc');
            expect(recomposedKey.encryptionAlgorithm.encryptionScheme.bits).toBe(128);
        });

        it('should compose an encrypted key with des-cbc (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['enc-8'], { format: 'raw-pem', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toBe(PRIVATE_KEYS['enc-8'].toString());
        });

        it('should compose an encrypted key with des-ede3-cbc (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['enc-9'], { format: 'raw-pem', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toBe(PRIVATE_KEYS['enc-9'].toString());
        });

        it('should default to using aes256-cbc if no encryption algorithm was passed', () => {
            const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['rsa-1'], { format: 'raw-pem' });
            const composedKey = composePrivateKey(decomposedKey, { password });
            const recomposedKey = decomposePrivateKey(composedKey, { format: 'raw-pem', password });

            expect(recomposedKey.encryptionAlgorithm.encryptionScheme.id).toBe('aes256-cbc');
        });

        it('should fail if encryption algorithm was specified without a password', () => {
            const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['enc-2'], { format: 'raw-pem', password });

            expect.assertions(2);

            try {
                composePrivateKey(decomposedKey);
            } catch (err) {
                expect(err.message).toBe('An encryption algorithm was specified but no password was set');
                expect(err.code).toBe('MISSING_PASSWORD');
            }
        });

        it('should fail if the key derivation func is not supported', () => {
            const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['rsa-1'], { format: 'raw-pem' });

            expect.assertions(2);

            try {
                composePrivateKey({
                    ...decomposedKey,
                    encryptionAlgorithm: {
                        keyDerivationFunc: 'foo',
                    },
                }, {
                    password,
                });
            } catch (err) {
                expect(err.message).toBe('PKCS1 PEM keys only support \'openssl-derive-bytes\' as the key derivation func');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should fail if the encryption scheme is not supported', () => {
            const decomposedKey = decomposePrivateKey(PRIVATE_KEYS['rsa-1'], { format: 'raw-pem' });

            expect.assertions(2);

            try {
                composePrivateKey({
                    ...decomposedKey,
                    encryptionAlgorithm: {
                        encryptionScheme: 'foo',
                    },
                }, {
                    password,
                });
            } catch (err) {
                expect(err.message).toBe('Unsupported encryption scheme id \'foo\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });
    });
});

describe('decomposePublicKey', () => {
    it('should decompose a RSA key', () => {
        expect(decomposePublicKey(PUBLIC_KEYS['rsa-1'], { format: 'raw-pem' })).toMatchSnapshot();
    });

    it('should support also Uint8Array, ArrayBuffer and string besides node.js Buffer', () => {
        const nodeBuffer = fs.readFileSync('test/fixtures/raw-pem/rsa-1');

        expect(decomposePublicKey(typedArrayToUint8Array(nodeBuffer), { format: 'raw-pem' })).toMatchSnapshot();
        expect(decomposePublicKey(typedArrayToUint8Array(nodeBuffer).buffer, { format: 'raw-pem' })).toMatchSnapshot();
        expect(decomposePublicKey(nodeBuffer.toString(), { format: 'raw-pem' })).toMatchSnapshot();
    });

    it('should fail if the input key is invalid', () => {
        expect.assertions(2);

        try {
            decomposePublicKey('', { format: 'raw-pem' });
        } catch (err) {
            expect(err.message).toBe('Failed to decode PEM');
            expect(err.code).toBe('DECODE_PEM_FAILED');
        }
    });

    it('should fail if the there\'s no key type', () => {
        expect.assertions(2);

        const pem = `
-----BEGIN PRIVATE KEY-----
Zm9v
-----END PRIVATE KEY-----
        `;

        try {
            decomposePublicKey(pem, { format: 'raw-pem' });
        } catch (err) {
            expect(err.message).toBe('Unable to extract key type from PEM');
            expect(err.code).toBe('DECODE_PEM_FAILED');
        }
    });

    it('should fail if the key type is unsupported', () => {
        expect.assertions(2);

        const pem = `
-----BEGIN FOO PRIVATE KEY-----
Zm9v
-----END FOO PRIVATE KEY-----
        `;

        try {
            decomposePublicKey(pem, { format: 'raw-pem' });
        } catch (err) {
            expect(err.message).toBe('Unsupported key type \'foo\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });
});

describe('composePublicKey', () => {
    it('should compose RSA key (mirroring)', () => {
        const decomposedKey = decomposePublicKey(PUBLIC_KEYS['rsa-1'], { format: 'raw-pem' });
        const composedKey = composePublicKey(decomposedKey);

        expect(composedKey).toBe(PUBLIC_KEYS['rsa-1'].toString());
    });
});
