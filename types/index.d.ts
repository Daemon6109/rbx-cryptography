/**
 * Lightweight roblox-ts typings for the Luau cryptography library.
 * These mirror the public surface of `src/init.luau` and submodules so you can
 * consume the package from TypeScript. Many algorithm-specific details are
 * typed loosely; refine as needed per function behavior.
 */

// Convenience aliases for Roblox buffer primitives commonly used throughout.
type BufferLike = buffer;
type HashResult = LuaTuple<[hex: string, raw: BufferLike]>;
type HashFunction = (message: BufferLike, salt?: BufferLike, outputLength?: number, keyData?: BufferLike) => HashResult;

declare namespace Cryptography {
    namespace Hashing {
        namespace SHA2 {
            function SHA224(message: BufferLike, salt?: BufferLike): HashResult;
            function SHA256(message: BufferLike, salt?: BufferLike): HashResult;
            function SHA384(message: BufferLike, salt?: BufferLike): HashResult;
            function SHA512(message: BufferLike, salt?: BufferLike): HashResult;
        }

        namespace SHA3 {
            function SHA3_224(message: BufferLike): HashResult;
            function SHA3_256(message: BufferLike): HashResult;
            function SHA3_384(message: BufferLike): HashResult;
            function SHA3_512(message: BufferLike): HashResult;
            function SHAKE128(message: BufferLike, outputBytes: number): HashResult;
            function SHAKE256(message: BufferLike, outputBytes: number): HashResult;
        }

        namespace Blake3 {
            function Digest(message: BufferLike, length?: number): HashResult;
            function DigestKeyed(key: BufferLike, message: BufferLike, length?: number): HashResult;
            function DeriveKey(context: BufferLike): (input: BufferLike, length?: number) => HashResult;
        }

        function Blake2b(inputData: BufferLike, outputLength?: number, keyData?: BufferLike): HashResult;

        function HMAC(message: BufferLike, key: BufferLike, hashFunction: HashFunction, blockSizeBytes: number, bigEndian?: boolean): HashResult;

        namespace KMAC {
            function KMAC128(data: BufferLike, key: BufferLike, output: BufferLike, customBuffer?: BufferLike): HashResult;
            function KMAC256(data: BufferLike, key: BufferLike, output: BufferLike, customBuffer?: BufferLike): HashResult;
        }
        function MD5(message: BufferLike): HashResult;
        function SHA1(message: BufferLike): HashResult;
        function XXH32(message: BufferLike): number;
        function MurMur(message: BufferLike): number | string | BufferLike;
    }

    namespace Checksums {
        function CRC32(buffer: BufferLike, mode?: "Jam" | "Iso", hex?: boolean): number | string;
        function Adler(buffer: BufferLike): number;
    }

    namespace Utilities {
        namespace Conversions {
            function ToHex(buffer: BufferLike): string;
            function FromHex(hex: string | BufferLike): BufferLike;
        }

        namespace Base64 {
            function Encode(buffer: BufferLike): BufferLike;
            function Decode(input: string | BufferLike): BufferLike;
        }

        function RandomString(length: number, asBuffer?: boolean): string | BufferLike;

        namespace CSPRNG {
            let BlockExpansion: boolean;
            let SizeTarget: number;
            let RekeyAfter: number;

            let Key: BufferLike;
            let Nonce: BufferLike;
            let Buffer: BufferLike;

            let Counter: number;
            let BufferPosition: number;
            let BufferSize: number;
            let BytesLeft: number;

            const EntropyProviders: Array<(bytesLeft: number) => BufferLike | undefined>;

            function Reseed(customEntropy?: BufferLike): void;
            function AddEntropyProvider(provider: (bytesLeft: number) => BufferLike | undefined): void;
            function RemoveEntropyProvider(provider: (bytesLeft: number) => BufferLike | undefined): void;

            function Random(): number;
            function RandomInt(min: number, max?: number): number;
            function RandomNumber(min: number, max?: number): number;
            function RandomBytes(count: number): BufferLike;
            function RandomString(length: number, asBuffer?: boolean): string | BufferLike;
            function RandomHex(length: number): string;
            function Ed25519ClampedBytes(input: BufferLike): BufferLike;
            function Ed25519Random(): BufferLike;
        }
    }

    namespace Encryption {
        namespace AES {
            function Encrypt(key: BufferLike, iv: BufferLike, plaintext: BufferLike, aad?: BufferLike): LuaTuple<[ciphertext: BufferLike, tag: BufferLike]>;
            function Decrypt(key: BufferLike, iv: BufferLike, ciphertext: BufferLike, tag: BufferLike, aad?: BufferLike): LuaTuple<[ok: boolean, plaintext: BufferLike]> | false;
        }

        namespace AEAD {
            function ChaCha20(data: BufferLike, key: BufferLike, nonce: BufferLike, counter?: number, rounds?: number): BufferLike;
            function XChaCha20(data: BufferLike, key: BufferLike, nonce: BufferLike, counter?: number, rounds?: number): BufferLike;
            function Poly1305(message: BufferLike, key: BufferLike): BufferLike;
            function Encrypt(message: BufferLike, key: BufferLike, nonce: BufferLike, aad?: BufferLike, rounds?: number, useXChaCha20?: boolean): LuaTuple<[ciphertext: BufferLike, tag: BufferLike]>;
            function Decrypt(ciphertext: BufferLike, key: BufferLike, nonce: BufferLike, tag: BufferLike, aad?: BufferLike, rounds?: number, useXChaCha20?: boolean): BufferLike | undefined;
        }

        namespace Simon {
            function Encrypt(plaintext: BufferLike, key: BufferLike): BufferLike;
            function Decrypt(ciphertext: BufferLike, key: BufferLike): BufferLike;
        }

        namespace Speck {
            function Encrypt(plaintext: BufferLike, key: BufferLike): BufferLike;
            function Decrypt(ciphertext: BufferLike, key: BufferLike): BufferLike;
        }

        function XOR(data: BufferLike, key: BufferLike): BufferLike;
    }

    namespace Verification {
        namespace EdDSA {
            function PublicKey(secretKey: BufferLike): BufferLike;
            function Sign(secretKey: BufferLike, publicKey: BufferLike, message: BufferLike): BufferLike;
            function Verify(publicKey: BufferLike, message: BufferLike, signature: BufferLike): boolean;

            namespace CSPRNG {
                let BlockExpansion: boolean;
                let SizeTarget: number;
                let RekeyAfter: number;

                let Key: BufferLike;
                let Nonce: BufferLike;
                let Buffer: BufferLike;

                let Counter: number;
                let BufferPosition: number;
                let BufferSize: number;
                let BytesLeft: number;

                const EntropyProviders: Array<(bytesLeft: number) => BufferLike | undefined>;

                function Reseed(customEntropy?: BufferLike): void;
                function AddEntropyProvider(provider: (bytesLeft: number) => BufferLike | undefined): void;
                function RemoveEntropyProvider(provider: (bytesLeft: number) => BufferLike | undefined): void;

                function Random(): number;
                function RandomInt(min: number, max?: number): number;
                function RandomNumber(min: number, max?: number): number;
                function RandomBytes(count: number): BufferLike;
                function RandomString(length: number, asBuffer?: boolean): string | BufferLike;
                function RandomHex(length: number): string;
                function Ed25519ClampedBytes(input: BufferLike): BufferLike;
                function Ed25519Random(): BufferLike;
            }

            namespace X25519 {
                function Mask(secretKey: BufferLike): BufferLike;
                function MaskSignature(secretKey: BufferLike): BufferLike;
                function Remask(maskedKey: BufferLike): BufferLike;
                function MaskComponent(maskedKey: BufferLike): BufferLike;
                function PublicKey(maskedKey: BufferLike): BufferLike;
                function Exchange(maskedSecretKey: BufferLike, theirPublicKey: BufferLike): LuaTuple<[shared: BufferLike, maskComponent: BufferLike]>;
            }
        }

        namespace MlDSA {
            namespace CSPRNG {
                let BlockExpansion: boolean;
                let SizeTarget: number;
                let RekeyAfter: number;

                let Key: BufferLike;
                let Nonce: BufferLike;
                let Buffer: BufferLike;

                let Counter: number;
                let BufferPosition: number;
                let BufferSize: number;
                let BytesLeft: number;

                const EntropyProviders: Array<(bytesLeft: number) => BufferLike | undefined>;

                function Reseed(customEntropy?: BufferLike): void;
                function AddEntropyProvider(provider: (bytesLeft: number) => BufferLike | undefined): void;
                function RemoveEntropyProvider(provider: (bytesLeft: number) => BufferLike | undefined): void;

                function Random(): number;
                function RandomInt(min: number, max?: number): number;
                function RandomNumber(min: number, max?: number): number;
                function RandomBytes(count: number): BufferLike;
                function RandomString(length: number, asBuffer?: boolean): string | BufferLike;
                function RandomHex(length: number): string;
                function Ed25519ClampedBytes(input: BufferLike): BufferLike;
                function Ed25519Random(): BufferLike;
            }

            function PubKeyLen(): number;
            function SecKeyLen(): number;
            function SigLen(): number;

            namespace ML_DSA_44 {
                const Beta: number;
                const D: number;
                const Eta: number;
                const Gamma1: number;
                const Gamma2: number;
                const K: number;
                const L: number;
                const Lambda: number;
                const Omega: number;
                const PubKeyByteLen: number;
                const SecKeyByteLen: number;
                const SigByteLen: number;
                const KeygenSeedByteLen: number;
                const SigningSeedByteLen: number;
                const Tau: number;
                function GenerateKeys(): LuaTuple<[pub: BufferLike, sec: BufferLike]>;
                function KeyGen(seed?: BufferLike): LuaTuple<[pub: BufferLike, sec: BufferLike]>;
                function Sign(secretKey: BufferLike, message: BufferLike, randomness?: BufferLike): BufferLike;
                function Verify(publicKey: BufferLike, message: BufferLike, signature: BufferLike): boolean;
            }

            namespace ML_DSA_65 {
                const Beta: number;
                const D: number;
                const Eta: number;
                const Gamma1: number;
                const Gamma2: number;
                const K: number;
                const L: number;
                const Lambda: number;
                const Omega: number;
                const PubKeyByteLen: number;
                const SecKeyByteLen: number;
                const SigByteLen: number;
                const KeygenSeedByteLen: number;
                const SigningSeedByteLen: number;
                const Tau: number;
                function GenerateKeys(): LuaTuple<[pub: BufferLike, sec: BufferLike]>;
                function KeyGen(seed?: BufferLike): LuaTuple<[pub: BufferLike, sec: BufferLike]>;
                function Sign(secretKey: BufferLike, message: BufferLike, randomness?: BufferLike): BufferLike;
                function Verify(publicKey: BufferLike, message: BufferLike, signature: BufferLike): boolean;
            }

            namespace ML_DSA_87 {
                const Beta: number;
                const D: number;
                const Eta: number;
                const Gamma1: number;
                const Gamma2: number;
                const K: number;
                const L: number;
                const Lambda: number;
                const Omega: number;
                const PubKeyByteLen: number;
                const SecKeyByteLen: number;
                const SigByteLen: number;
                const KeygenSeedByteLen: number;
                const SigningSeedByteLen: number;
                const Tau: number;
                function GenerateKeys(): LuaTuple<[pub: BufferLike, sec: BufferLike]>;
                function KeyGen(seed?: BufferLike): LuaTuple<[pub: BufferLike, sec: BufferLike]>;
                function Sign(secretKey: BufferLike, message: BufferLike, randomness?: BufferLike): BufferLike;
                function Verify(publicKey: BufferLike, message: BufferLike, signature: BufferLike): boolean;
            }
        }

        namespace MlKEM {
            namespace CSPRNG {
                let BlockExpansion: boolean;
                let SizeTarget: number;
                let RekeyAfter: number;

                let Key: BufferLike;
                let Nonce: BufferLike;
                let Buffer: BufferLike;

                let Counter: number;
                let BufferPosition: number;
                let BufferSize: number;
                let BytesLeft: number;

                const EntropyProviders: Array<(bytesLeft: number) => BufferLike | undefined>;

                function Reseed(customEntropy?: BufferLike): void;
                function AddEntropyProvider(provider: (bytesLeft: number) => BufferLike | undefined): void;
                function RemoveEntropyProvider(provider: (bytesLeft: number) => BufferLike | undefined): void;

                function Random(): number;
                function RandomInt(min: number, max?: number): number;
                function RandomNumber(min: number, max?: number): number;
                function RandomBytes(count: number): BufferLike;
                function RandomString(length: number, asBuffer?: boolean): string | BufferLike;
                function RandomHex(length: number): string;
                function Ed25519ClampedBytes(input: BufferLike): BufferLike;
                function Ed25519Random(): BufferLike;
            }

            function KeyGen(seed?: BufferLike): LuaTuple<[publicKey: BufferLike, secretKey: BufferLike]>;
            function Encapsulate(publicKey: BufferLike, seed?: BufferLike): LuaTuple<[ciphertext: BufferLike, sharedSecret: BufferLike]>;
            function Decapsulate(secretKey: BufferLike, ciphertext: BufferLike): BufferLike;
            function ValidateDecapsulationKey(secretKey: BufferLike): boolean;
            function SecretsEqual(secretA: BufferLike, secretB: BufferLike): boolean;

            namespace MLKEM_512 {
                function KeyGen(seed?: BufferLike): LuaTuple<[publicKey: BufferLike, secretKey: BufferLike]>;
                function Encapsulate(publicKey: BufferLike, seed?: BufferLike): LuaTuple<[ciphertext: BufferLike, sharedSecret: BufferLike]>;
                function Decapsulate(secretKey: BufferLike, ciphertext: BufferLike): BufferLike;
                function GenerateKeys(seed?: BufferLike): LuaTuple<[publicKey: BufferLike, secretKey: BufferLike]>;
                function ValidateDecapsulationKey(secretKey: BufferLike): boolean;
            }

            namespace MLKEM_768 {
                function KeyGen(seed?: BufferLike): LuaTuple<[publicKey: BufferLike, secretKey: BufferLike]>;
                function Encapsulate(publicKey: BufferLike, seed?: BufferLike): LuaTuple<[ciphertext: BufferLike, sharedSecret: BufferLike]>;
                function Decapsulate(secretKey: BufferLike, ciphertext: BufferLike): BufferLike;
                function GenerateKeys(seed?: BufferLike): LuaTuple<[publicKey: BufferLike, secretKey: BufferLike]>;
                function ValidateDecapsulationKey(secretKey: BufferLike): boolean;
            }

            namespace MLKEM_1024 {
                function KeyGen(seed?: BufferLike): LuaTuple<[publicKey: BufferLike, secretKey: BufferLike]>;
                function Encapsulate(publicKey: BufferLike, seed?: BufferLike): LuaTuple<[ciphertext: BufferLike, sharedSecret: BufferLike]>;
                function Decapsulate(secretKey: BufferLike, ciphertext: BufferLike): BufferLike;
                function GenerateKeys(seed?: BufferLike): LuaTuple<[publicKey: BufferLike, secretKey: BufferLike]>;
                function ValidateDecapsulationKey(secretKey: BufferLike): boolean;
            }
        }
    }
}

export = Cryptography;
