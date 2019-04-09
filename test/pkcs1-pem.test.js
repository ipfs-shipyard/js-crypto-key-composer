import fs from 'fs';
import { decomposePrivateKey, composePrivateKey } from '../src';
import { typedArrayToUint8Array } from '../src/util/binary';

const KEYS = {
    'rsa-1': fs.readFileSync('test/fixtures/pkcs1-pem/rsa-1'),
    'rsa-2': fs.readFileSync('test/fixtures/pkcs1-pem/rsa-2'),
    'enc-1': fs.readFileSync('test/fixtures/pkcs1-pem/enc-1'),
    'enc-2': fs.readFileSync('test/fixtures/pkcs1-pem/enc-2'),
    'enc-3': fs.readFileSync('test/fixtures/pkcs1-pem/enc-3'),
    'enc-4': fs.readFileSync('test/fixtures/pkcs1-pem/enc-4'),
    'enc-5': fs.readFileSync('test/fixtures/pkcs1-pem/enc-5'),
    'enc-6': fs.readFileSync('test/fixtures/pkcs1-pem/enc-6'),
    'enc-7': fs.readFileSync('test/fixtures/pkcs1-pem/enc-7'),
    'enc-8': fs.readFileSync('test/fixtures/pkcs1-pem/enc-8'),
    'enc-9': fs.readFileSync('test/fixtures/pkcs1-pem/enc-9'),
};

const password = 'password';

describe('decomposePrivateKey', () => {
    it('should decompose a RSA key', () => {
        expect(decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs1-pem' })).toMatchSnapshot();
    });

    it('should decompose an encrypted RSA key', () => {
        expect(decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs1-pem', password })).toMatchSnapshot();
    });

    it('should support also Uint8Array, ArrayBuffer and string besides node.js Buffer', () => {
        const nodeBuffer = fs.readFileSync('test/fixtures/pkcs1-pem/rsa-1');

        expect(decomposePrivateKey(typedArrayToUint8Array(nodeBuffer), { format: 'pkcs1-pem' })).toMatchSnapshot();
        expect(decomposePrivateKey(typedArrayToUint8Array(nodeBuffer).buffer, { format: 'pkcs1-pem' })).toMatchSnapshot();
        expect(decomposePrivateKey(nodeBuffer.toString(), { format: 'pkcs1-pem' })).toMatchSnapshot();
    });

    it('should fail if the input key is invalid', () => {
        expect.assertions(2);

        try {
            decomposePrivateKey('', { format: 'pkcs1-pem' });
        } catch (err) {
            expect(err.message).toBe('Failed to decode PEM');
            expect(err.code).toBe('DECODE_PEM_FAILED');
        }
    });

    describe('decryption algorithms', () => {
        it('should decompose an encrypted key with aes128', () => {
            expect(decomposePrivateKey(KEYS['enc-1'], { format: 'pkcs1-pem', password })).toMatchSnapshot();
        });

        it('should decompose an encrypted key with aes192', () => {
            expect(decomposePrivateKey(KEYS['enc-2'], { format: 'pkcs1-pem', password })).toMatchSnapshot();
        });

        it('should decompose an encrypted key with aes256', () => {
            expect(decomposePrivateKey(KEYS['enc-3'], { format: 'pkcs1-pem', password })).toMatchSnapshot();
        });

        it('should decompose an encrypted key with rc2 40 bits', () => {
            expect(decomposePrivateKey(KEYS['enc-4'], { format: 'pkcs1-pem', password })).toMatchSnapshot();
        });

        it('should decompose an encrypted key with rc2 64 bits', () => {
            expect(decomposePrivateKey(KEYS['enc-5'], { format: 'pkcs1-pem', password })).toMatchSnapshot();
        });

        it('should decompose an encrypted key with rc2 128 bits (implicit)', () => {
            expect(decomposePrivateKey(KEYS['enc-6'], { format: 'pkcs1-pem', password })).toMatchSnapshot();
        });

        it('should decompose an encrypted key with rc2 128 bits', () => {
            expect(decomposePrivateKey(KEYS['enc-7'], { format: 'pkcs1-pem', password })).toMatchSnapshot();
        });

        it('should decompose an encrypted key with desCBC', () => {
            expect(decomposePrivateKey(KEYS['enc-8'], { format: 'pkcs1-pem', password })).toMatchSnapshot();
        });

        it('should decompose an encrypted key with DES-EDE3-CBC', () => {
            expect(decomposePrivateKey(KEYS['enc-9'], { format: 'pkcs1-pem', password })).toMatchSnapshot();
        });

        it('should fail to decompose an encrypted key without suplying a password', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['enc-1'], { format: 'pkcs1-pem' });
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
                    format: 'pkcs1-pem',
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
                decomposePrivateKey(KEYS['enc-1'], {
                    format: 'pkcs1-pem',
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
    it('should compose a RSA key (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs1-pem' });
        const composedKey = composePrivateKey(decomposedKey);

        expect(composedKey).toBe(KEYS['rsa-1'].toString());
    });

    it('should compose an encrypted RSA key (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(KEYS['rsa-2'], { format: 'pkcs1-pem', password });
        const composedKey = composePrivateKey(decomposedKey, { password });

        expect(composedKey).toBe(KEYS['rsa-2'].toString());
    });

    describe('encryption algorithms', () => {
        it('should compose an encrypted key with aes128 (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-1'], { format: 'pkcs1-pem', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toBe(KEYS['enc-1'].toString());
        });

        it('should compose an encrypted key with aes192 (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-2'], { format: 'pkcs1-pem', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toBe(KEYS['enc-2'].toString());
        });

        it('should compose an encrypted key with aes256 (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-3'], { format: 'pkcs1-pem', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toBe(KEYS['enc-3'].toString());
        });

        it('should compose an encrypted key with rc2 40 bits (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-4'], { format: 'pkcs1-pem', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toBe(KEYS['enc-4'].toString());
        });

        it('should compose an encrypted key with rc2 64 bits (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-5'], { format: 'pkcs1-pem', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toBe(KEYS['enc-5'].toString());
        });

        it('should compose an encrypted key with rc2 128 bits (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-6'], { format: 'pkcs1-pem', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toBe(KEYS['enc-6'].toString());
        });

        it('should fail if the RC2 parameter version (bits) specified in the encryption algorithm is not supported', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs1-pem' });

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
            const decomposedKey = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs1-pem' });
            const composedKey = composePrivateKey({
                ...decomposedKey,
                encryptionAlgorithm: {
                    encryptionScheme: 'rc2-cbc',
                },
            }, { password });
            const recomposedKey = decomposePrivateKey(composedKey, { format: 'pkcs1-pem', password });

            expect(recomposedKey.encryptionAlgorithm.encryptionScheme.id).toBe('rc2-cbc');
            expect(recomposedKey.encryptionAlgorithm.encryptionScheme.bits).toBe(128);
        });

        it('should compose an encrypted key with des-cbc (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-8'], { format: 'pkcs1-pem', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toBe(KEYS['enc-8'].toString());
        });

        it('should compose an encrypted key with des-ede3-cbc (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-9'], { format: 'pkcs1-pem', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toBe(KEYS['enc-9'].toString());
        });

        it('should default to using aes256-cbc if no encryption algorithm was passed', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs1-pem' });
            const composedKey = composePrivateKey(decomposedKey, { password });
            const recomposedKey = decomposePrivateKey(composedKey, { format: 'pkcs1-pem', password });

            expect(recomposedKey.encryptionAlgorithm.encryptionScheme.id).toBe('aes256-cbc');
        });

        it('should fail if encryption algorithm was specified without a password', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-2'], { format: 'pkcs1-pem', password });

            expect.assertions(2);

            try {
                composePrivateKey(decomposedKey);
            } catch (err) {
                expect(err.message).toBe('An encryption algorithm was specified but no password was set');
                expect(err.code).toBe('MISSING_PASSWORD');
            }
        });

        it('should fail if the key derivation func is not supported', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs1-pem' });

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
            const decomposedKey = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs1-pem' });

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
