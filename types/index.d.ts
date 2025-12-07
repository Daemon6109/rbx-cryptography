/**
 * Lightweight roblox-ts typings for the Luau cryptography library.
 * These mirror the public surface of `src/init.luau` and submodules so you can
 * consume the package from TypeScript. Many algorithm-specific details are
 * typed loosely; refine as needed per function behavior.
 */

// Convenience aliases for Roblox buffer primitives commonly used throughout.
type BufferLike = buffer;

type HashResult = [hex: string, raw: BufferLike];

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
            function SHAKE_128(message: BufferLike): HashResult;
            function SHAKE_256(message: BufferLike): HashResult;
        }

        namespace Blake3 {
            function Digest(message: BufferLike, length?: number): HashResult;
            function DigestKeyed(key: BufferLike, message: BufferLike, length?: number): HashResult;
            function DeriveKey(context: BufferLike): (input: BufferLike, length?: number) => HashResult;
        }

        namespace Blake2b {
            function Blake2b(inputData: BufferLike, outputLength?: number, keyData?: BufferLike): HashResult;
        }

        // Typed loosely; refine with concrete signatures as desired.
        const HMAC: (...args: unknown[]) => unknown;
        const KMAC: (...args: unknown[]) => unknown;
        const MD5: (message: BufferLike) => HashResult;
        const SHA1: (message: BufferLike) => HashResult;
        const XXH32: (message: BufferLike) => number;
        const MurMur: (message: BufferLike) => number | string | BufferLike;
    }

    namespace Checksums {
        function CRC32(buffer: BufferLike, mode?: "Jam" | "Iso", pad?: boolean): number;
        function Adler(buffer: BufferLike): number;
    }

    namespace Utilities {
        namespace Conversions {
            function ToHex(buffer: BufferLike): string;
            function FromHex(hex: string | BufferLike): BufferLike;
        }

        namespace Base64 {
            function Encode(buffer: BufferLike): string;
            function Decode(input: string | BufferLike): BufferLike;
        }

        namespace RandomString {
            function Generate(length: number): string;
        }

        namespace CSPRNG {
            const Blake3: (...args: unknown[]) => unknown;
            const ChaCha20: (...args: unknown[]) => unknown;
            const Conversions: typeof Conversions;
            function RandomBytes(length: number): BufferLike;
        }
    }

    namespace Encryption {
        namespace AES {
            function Encrypt(key: BufferLike, iv: BufferLike, plaintext: BufferLike, aad?: BufferLike): [ciphertext: BufferLike, tag: BufferLike];
            function Decrypt(key: BufferLike, iv: BufferLike, ciphertext: BufferLike, tag: BufferLike, aad?: BufferLike): [ok: true, plaintext: BufferLike] | [ok: false];
        }

        namespace AEAD {
            const ChaCha: (...args: unknown[]) => unknown;
            const Poly1305: (...args: unknown[]) => unknown;
        }

        namespace Simon {
            const Encrypt: (...args: unknown[]) => unknown;
            const Decrypt: (...args: unknown[]) => unknown;
        }

        namespace Speck {
            const Encrypt: (...args: unknown[]) => unknown;
            const Decrypt: (...args: unknown[]) => unknown;
        }

        namespace XOR {
            function Encrypt(data: BufferLike, key: BufferLike): BufferLike;
            function Decrypt(data: BufferLike, key: BufferLike): BufferLike;
        }
    }

    namespace Verification {
        namespace EdDSA {
            // X25519 and Ed25519 typed loosely; refine as needed.
            namespace X25519 {
                function GenerateKeyPair(): [publicKey: BufferLike, privateKey: BufferLike];
                function Derive(publicKey: BufferLike, privateKey: BufferLike): BufferLike;
            }

            function Sign(privateKey: BufferLike, message: BufferLike): BufferLike;
            function Verify(publicKey: BufferLike, message: BufferLike, signature: BufferLike): boolean;
        }

        // PQ algorithms left broad; add concrete shapes per need.
        const MlDSA: Record<string, unknown>;
        const MlKEM: Record<string, unknown>;
    }
}

export = Cryptography;
