import fs from 'fs';
import { decomposePrivateKey, composePrivateKey } from '../src';
import { typedArrayToUint8Array } from '../src/util/binary';

const KEYS = {
    'rsa-1': fs.readFileSync('test/fixtures/pkcs8-der/rsa-1'),
    'rsa-2': fs.readFileSync('test/fixtures/pkcs8-der/rsa-2'),
    'rsa-3': fs.readFileSync('test/fixtures/pkcs8-der/rsa-3'),
    'rsa-4': fs.readFileSync('test/fixtures/pkcs8-der/rsa-4'),
    'ec-1': fs.readFileSync('test/fixtures/pkcs8-der/ec-1'),
    'ec-invalid-1': fs.readFileSync('test/fixtures/pkcs8-der/ec-invalid-1'),
    'ed25519-1': fs.readFileSync('test/fixtures/pkcs8-der/ed25519-1'),
    'ed25519-2': fs.readFileSync('test/fixtures/pkcs8-der/ed25519-2'),
    'invalid-1': fs.readFileSync('test/fixtures/pkcs8-der/invalid-1'),
    'enc-1': fs.readFileSync('test/fixtures/pkcs8-der/enc-1'),
    'enc-2': fs.readFileSync('test/fixtures/pkcs8-der/enc-2'),
    'enc-3': fs.readFileSync('test/fixtures/pkcs8-der/enc-3'),
    'enc-4': fs.readFileSync('test/fixtures/pkcs8-der/enc-4'),
    'enc-5': fs.readFileSync('test/fixtures/pkcs8-der/enc-5'),
    'enc-6': fs.readFileSync('test/fixtures/pkcs8-der/enc-6'),
    'enc-7': fs.readFileSync('test/fixtures/pkcs8-der/enc-7'),
    'enc-8': fs.readFileSync('test/fixtures/pkcs8-der/enc-8'),
    'enc-9': fs.readFileSync('test/fixtures/pkcs8-der/enc-9'),
    'enc-10': fs.readFileSync('test/fixtures/pkcs8-der/enc-10'),
    'enc-11': fs.readFileSync('test/fixtures/pkcs8-der/enc-11'),
    'enc-12': fs.readFileSync('test/fixtures/pkcs8-der/enc-12'),
    'enc-13': fs.readFileSync('test/fixtures/pkcs8-der/enc-13'),
    'enc-invalid-1': fs.readFileSync('test/fixtures/pkcs8-der/enc-invalid-1'),
    'enc-invalid-2': fs.readFileSync('test/fixtures/pkcs8-der/enc-invalid-2'),
    'enc-invalid-3': fs.readFileSync('test/fixtures/pkcs8-der/enc-invalid-3'),
    'enc-invalid-4': fs.readFileSync('test/fixtures/pkcs8-der/enc-invalid-4'),
    'enc-invalid-5': fs.readFileSync('test/fixtures/pkcs8-der/enc-invalid-5'),
    'enc-invalid-6': fs.readFileSync('test/fixtures/pkcs8-der/enc-invalid-6'),
};

const password = 'password';

describe('decomposePrivateKey', () => {
    it('should decompose a RSA key', () => {
        expect(decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs8-der' })).toMatchSnapshot();
    });

    it('should decompose a RSA key with 3 primes', () => {
        expect(decomposePrivateKey(KEYS['rsa-2'], { format: 'pkcs8-der' })).toMatchSnapshot();
    });

    it('should decompose a RSA key with 4 primes', () => {
        expect(decomposePrivateKey(KEYS['rsa-3'], { format: 'pkcs8-der' })).toMatchSnapshot();
    });

    it('should decompose an encrypted RSA key', () => {
        expect(decomposePrivateKey(KEYS['rsa-4'], { format: 'pkcs8-der', password })).toMatchSnapshot();
    });

    it('should decompose a EC key, secp256k1', () => {
        expect(decomposePrivateKey(KEYS['ec-1'], { format: 'pkcs8-der' })).toMatchSnapshot();
    });

    it('should fail to decompose a EC key with an invalid curve', () => {
        expect.assertions(2);

        try {
            decomposePrivateKey(KEYS['ec-invalid-1'], { format: 'pkcs8-der' });
        } catch (err) {
            expect(err.message).toBe('Unsupported named curve OID \'0.20.999\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });

    it('should decompose a ED25519 key', () => {
        expect(decomposePrivateKey(KEYS['ed25519-1'], { format: 'pkcs8-der' })).toMatchSnapshot();
    });

    it('should decompose an encrypted ED25519 key', () => {
        expect(decomposePrivateKey(KEYS['ed25519-2'], { format: 'pkcs8-der', password })).toMatchSnapshot();
    });

    it('should also support Uint8Array, ArrayBuffer and string besides Node\'s Buffer', () => {
        const nodeBuffer = fs.readFileSync('test/fixtures/pkcs8-der/rsa-1');

        expect(decomposePrivateKey(typedArrayToUint8Array(nodeBuffer), { format: 'pkcs8-der' })).toMatchSnapshot();
        expect(decomposePrivateKey(typedArrayToUint8Array(nodeBuffer).buffer, { format: 'pkcs8-der' })).toMatchSnapshot();
        expect(decomposePrivateKey(nodeBuffer.toString('binary'), { format: 'pkcs8-der' })).toMatchSnapshot();
    });

    it('should fail if the key algorithm is not supported', () => {
        expect.assertions(2);

        try {
            decomposePrivateKey(KEYS['invalid-1'], { format: 'pkcs8-der' });
        } catch (err) {
            expect(err.message).toBe('Unsupported key algorithm OID \'0.20.999\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });

    it('should fail if the input key is invalid', () => {
        expect.assertions(2);

        try {
            decomposePrivateKey('', { format: 'pkcs8-der' });
        } catch (err) {
            expect(err.message).toBe('Failed to decode PrivateKeyInfo');
            expect(err.code).toBe('DECODE_ASN1_FAILED');
        }
    });

    describe('decryption algorithms', () => {
        it('should decompose key encrypted with pbes2+pbkdf2+aes128-cbc', () => {
            expect(decomposePrivateKey(KEYS['enc-1'], { format: 'pkcs8-der', password })).toMatchSnapshot();
        });

        it('should decompose key encrypted with pbes2+pbkdf2+aes192-cbc', () => {
            expect(decomposePrivateKey(KEYS['enc-2'], { format: 'pkcs8-der', password })).toMatchSnapshot();
        });

        it('should decompose key encrypted with pbes2+pbkdf2+aes256-cbc', () => {
            expect(decomposePrivateKey(KEYS['enc-3'], { format: 'pkcs8-der', password })).toMatchSnapshot();
        });

        it('should decompose key encrypted with pbes2+pbkdf2+rc2 40 bits', () => {
            expect(decomposePrivateKey(KEYS['enc-4'], { format: 'pkcs8-der', password })).toMatchSnapshot();
        });

        it('should decompose key encrypted with pbes2+pbkdf2+rc2 64 bits', () => {
            expect(decomposePrivateKey(KEYS['enc-5'], { format: 'pkcs8-der', password })).toMatchSnapshot();
        });

        it('should decompose key encrypted with pbes2+pbkdf2+rc2 128 bits', () => {
            expect(decomposePrivateKey(KEYS['enc-6'], { format: 'pkcs8-der', password })).toMatchSnapshot();
        });

        it('should fail if the rc2 parameter version in pbes2+pbkdf2+rc2 is not supported', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['enc-invalid-4'], { format: 'pkcs8-der', password });
            } catch (err) {
                expect(err.message).toBe('Unsupported RC2 version parameter with value \'1\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should decompose key encrypted with pbes2+pbkdf2+des-cbc', () => {
            expect(decomposePrivateKey(KEYS['enc-7'], { format: 'pkcs8-der', password })).toMatchSnapshot();
        });

        it('should decompose key encrypted with pbes2+pbkdf2+des-ede3-cbc', () => {
            expect(decomposePrivateKey(KEYS['enc-8'], { format: 'pkcs8-der', password })).toMatchSnapshot();
        });

        it('should decompose key encrypted with PBKDF2 prf SHA1 variant', () => {
            expect(decomposePrivateKey(KEYS['enc-9'], { format: 'pkcs8-der', password })).toMatchSnapshot('sha1');
        });

        it.skip('should decompose key encrypted with PBKDF2 prf SHA224 variant', () => {
            // See: https://github.com/digitalbazaar/forge/issues/669
            expect(decomposePrivateKey(KEYS['enc-10'], { format: 'pkcs8-der', password })).toMatchSnapshot('sha224');
        });

        it('should decompose key encrypted with PBKDF2 prf SHA256 variant', () => {
            expect(decomposePrivateKey(KEYS['enc-11'], { format: 'pkcs8-der', password })).toMatchSnapshot('sha256');
        });

        it('should decompose key encrypted with PBKDF2 prf SHA384 variant', () => {
            expect(decomposePrivateKey(KEYS['enc-12'], { format: 'pkcs8-der', password })).toMatchSnapshot('sha384');
        });

        it('should decompose key encrypted with PBKDF2 prf SHA512 variant', () => {
            expect(decomposePrivateKey(KEYS['enc-13'], { format: 'pkcs8-der', password })).toMatchSnapshot('sha512');
        });

        it('should fail if the key derivation func prf in the PBES2 encryption algorithm is not supported', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['enc-invalid-5'], { format: 'pkcs8-der', password });
            } catch (err) {
                expect(err.message).toBe('Unsupported prf algorithm OID \'0.20.999\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should fail if the key derivation func in the PBES2 encryption algorithm is not supported', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['enc-invalid-1'], { format: 'pkcs8-der', password });
            } catch (err) {
                expect(err.message).toBe('Unsupported key derivation function algorithm OID \'0.20.999\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should fail if the encryption scheme in the PBES2 encryption algorithm is not supported', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['enc-invalid-2'], { format: 'pkcs8-der', password });
            } catch (err) {
                expect(err.message).toBe('Unsupported encryption scheme algorithm OID \'0.20.999\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should fail if the encryption algorithm is not supported', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['enc-invalid-3'], { format: 'pkcs8-der', password });
            } catch (err) {
                expect(err.message).toBe('Unsupported encryption algorithm OID \'0.20.999\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should fail to decompose an encrypted key without suplying a password', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['enc-1'], { format: 'pkcs8-der' });
            } catch (err) {
                expect(err.message).toBe('Please specify the password to decrypt the key');
                expect(err.code).toBe('MISSING_PASSWORD');
            }
        });

        it('should fail if the decrypted data is not a valid PrivateKeyInfo', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['enc-invalid-6'], { format: 'pkcs8-der', password });
            } catch (err) {
                expect(err.message).toBe('Failed to decode PrivateKeyInfo');
                expect(err.code).toBe('DECODE_ASN1_FAILED');
            }
        });

        it('should fail to decompose an encrypted key with the wrong password', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['enc-1'], {
                    format: 'pkcs8-der',
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
        const decomposedKey = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs8-der' });
        const composedKey = composePrivateKey(decomposedKey);

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-1']));
    });

    it('should compose a RSA key with 3 primes (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(KEYS['rsa-2'], { format: 'pkcs8-der' });
        const composedKey = composePrivateKey(decomposedKey);

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-2']));
    });

    it('should compose a RSA key with 4 primes (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(KEYS['rsa-3'], { format: 'pkcs8-der' });
        const composedKey = composePrivateKey(decomposedKey);

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-3']));
    });

    it('should compose an encrypted RSA key (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(KEYS['rsa-4'], { format: 'pkcs8-der', password });
        const composedKey = composePrivateKey(decomposedKey, { password });

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-4']));
    });

    it('should compose a EC key, secp256k1 (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(KEYS['ec-1'], { format: 'pkcs8-der' });
        const composedKey = composePrivateKey(decomposedKey);

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['ec-1']));
    });

    it('should fail to compose a EC key with an invalid curve', () => {
        const decomposedKey = decomposePrivateKey(KEYS['ec-1'], { format: 'pkcs8-der' });

        expect.assertions(2);

        try {
            composePrivateKey({
                ...decomposedKey,
                keyAlgorithm: {
                    ...decomposedKey.keyAlgorithm,
                    namedCurve: 'foo',
                },
            }, { format: 'pkcs8-der' });
        } catch (err) {
            expect(err.message).toBe('Unsupported named curve \'foo\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });

    it('should compose a ED25519 key (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(KEYS['ed25519-1'], { format: 'pkcs8-der' });
        const composedKey = composePrivateKey(decomposedKey);

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['ed25519-1']));
    });

    it('should compose an encrypted ED25519 key (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(KEYS['ed25519-2'], { format: 'pkcs8-der', password });

        const composedKey = composePrivateKey(decomposedKey, { password });

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['ed25519-2']));
    });

    it('should fail if the key algorithm is not supported', () => {
        expect.assertions(2);

        try {
            composePrivateKey({
                format: 'pkcs8-der',
                keyAlgorithm: { id: 'foo' },
                keyData: {},
            });
        } catch (err) {
            expect(err.message).toBe('Unsupported key algorithm id \'foo\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });

    it('should support a string in the key algorithm', () => {
        const decomposedKey = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs8-der' });
        const composedKey = composePrivateKey({ ...decomposedKey, keyAlgorithm: 'rsa-encryption' });

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-1']));
    });

    it('should support the \'rsa\' alias as the key algorithm', () => {
        const decomposedKey1 = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs8-der' });
        const composedKey1 = composePrivateKey({ ...decomposedKey1, keyAlgorithm: 'rsa' });

        expect(composedKey1).toEqual(typedArrayToUint8Array(KEYS['rsa-1']));

        const decomposedKey2 = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs8-der' });
        const composedKey2 = composePrivateKey({ ...decomposedKey2, keyAlgorithm: { id: 'rsa' } });

        expect(composedKey2).toEqual(typedArrayToUint8Array(KEYS['rsa-1']));
    });

    describe('encryption algorithms', () => {
        it('should compose an encrypted key with pbes2+pbkdf2+aes128-cbc (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-1'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['enc-1']));
        });

        it('should compose an encrypted key with pbes2+pbkdf2+aes192-cbc (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-2'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['enc-2']));
        });

        it('should compose an encrypted key with pbes2+pbkdf2+aes256-cbc (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-3'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['enc-3']));
        });

        it('should compose an encrypted key with pbes2+pbkdf2+rc2 40 bits (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-4'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['enc-4']));
        });

        it('should compose an encrypted key with pbes2+pbkdf2+rc2 64 bits (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-5'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['enc-5']));
        });

        it('should compose an encrypted key with pbes2+pbkdf2+rc2 128 bits (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-6'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['enc-6']));
        });

        it('should fail if the bits specified in pbes2+pbkdf2+rc2 is not supported', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-6'], { format: 'pkcs8-der', password });

            expect.assertions(2);

            try {
                composePrivateKey({
                    ...decomposedKey,
                    encryptionAlgorithm: {
                        ...decomposedKey.encryptionAlgorithm,
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

        it('should default to 128 bits for pbes2+pbkdf2+rc2', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-6'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey({
                ...decomposedKey,
                encryptionAlgorithm: {
                    ...decomposedKey.encryptionAlgorithm,
                    encryptionScheme: 'rc2-cbc',
                },
            }, {
                password,
            });
            const recomposedKey = decomposePrivateKey(composedKey, { format: 'pkcs8-der', password });

            expect(recomposedKey.encryptionAlgorithm.encryptionScheme.id).toBe('rc2-cbc');
            expect(recomposedKey.encryptionAlgorithm.encryptionScheme.bits).toBe(128);
        });

        it('should compose an encrypted key with pbes2+pbkdf2+des-cbc (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-7'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['enc-7']));
        });

        it('should compose an encrypted key with pbes2+pbkdf2+des-ede3-cbc (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-8'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['enc-8']));
        });

        it('should default to using pbes2+pbkdf2+aes256-cbc if no encryption algorithm was passed', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs8-der' });
            const composedKey = composePrivateKey(decomposedKey, { password });
            const recomposedKey = decomposePrivateKey(composedKey, { format: 'pkcs8-der', password });

            expect(recomposedKey.encryptionAlgorithm.keyDerivationFunc.id).toBe('pbkdf2');
            expect(recomposedKey.encryptionAlgorithm.encryptionScheme.id).toBe('aes256-cbc');
        });

        it('should compose an encrypted key with PBKDF2 prf SHA1 variant (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-9'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['enc-9']));
        });

        it.skip('should compose an encrypted key with PBKDF2 prf SHA224 variant (mirroring)', () => {
            // See: https://github.com/digitalbazaar/forge/issues/669
            const decomposedKey = decomposePrivateKey(KEYS['enc-10'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['enc-10']));
        });

        it('should compose an encrypted key with PBKDF2 prf SHA256 variant (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-11'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['enc-11']));
        });

        it('should compose an encrypted key with PBKDF2 prf SHA384 variant (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-12'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['enc-12']));
        });

        it('should compose an encrypted key with PBKDF2 prf SHA512 variant (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-13'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['enc-13']));
        });

        it('should fail if the keyLength is smaller than the expected length of the encryption scheme', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-1'], { format: 'pkcs8-der', password });

            expect.assertions(2);

            try {
                composePrivateKey({
                    ...decomposedKey,
                    encryptionAlgorithm: {
                        ...decomposedKey.encryptionAlgorithm,
                        keyDerivationFunc: {
                            ...decomposedKey.encryptionAlgorithm.keyDerivationFunc,
                            keyLength: 1,
                        },
                    },
                }, {
                    password,
                });
            } catch (err) {
                expect(err.message).toBe('The specified key length must be equal to 16 (or omitted)');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should fail if the key derivation func prf in the PBES2 encryption algorithm is not supported', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-1'], { format: 'pkcs8-der', password });

            expect.assertions(2);

            try {
                composePrivateKey({
                    ...decomposedKey,
                    encryptionAlgorithm: {
                        ...decomposedKey.encryptionAlgorithm,
                        keyDerivationFunc: {
                            ...decomposedKey.encryptionAlgorithm.keyDerivationFunc,
                            prf: 'foo',
                        },
                    },
                }, {
                    password,
                });
            } catch (err) {
                expect(err.message).toBe('Unsupported PBKDF2 prf id \'foo\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should fail if the encryption scheme for PBES2 is not supported', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-1'], { format: 'pkcs8-der', password });

            expect.assertions(2);

            try {
                composePrivateKey({
                    ...decomposedKey,
                    encryptionAlgorithm: {
                        ...decomposedKey.encryptionAlgorithm,
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

        it('should fail if the key derivation func for PBES2 is not supported', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-1'], { format: 'pkcs8-der', password });

            expect.assertions(2);

            try {
                composePrivateKey({
                    ...decomposedKey,
                    encryptionAlgorithm: {
                        ...decomposedKey.encryptionAlgorithm,
                        keyDerivationFunc: { id: 'foo' },
                    },
                }, {
                    password,
                });
            } catch (err) {
                expect(err.message).toBe('Unsupported key derivation function id \'foo\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should fail if encryption algorithm was specified without a password', () => {
            const decomposedKey = decomposePrivateKey(KEYS['enc-1'], { format: 'pkcs8-der', password });

            expect.assertions(2);

            try {
                composePrivateKey(decomposedKey);
            } catch (err) {
                expect(err.message).toBe('An encryption algorithm was specified but no password was set');
                expect(err.code).toBe('MISSING_PASSWORD');
            }
        });
    });
});
