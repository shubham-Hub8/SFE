# Simple File Encryptor — Version 3.0

Simple File Encryptor (SFE) is a self-contained browser application for local file encryption and decryption. Version 3.0 keeps the existing visual structure while replacing the new-file container design with a privacy-oriented SFE3 format.

## What SFE 3.0 does

- New encryption uses the SFE3 container format.
- AES-256-GCM is used for authenticated encryption through the browser Web Crypto API.
- Argon2id is the recommended password KDF.
- PBKDF2-HMAC-SHA-256 is available as an alternate SFE3 KDF at 600,000 iterations by default.
- Every SFE3 container gets a fresh 32-byte random salt and a fresh 12-byte random nonce base.
- Argon2id defaults to 64 MiB, 3 passes and 4 lanes, with a custom 12–256 MiB memory control exposed by the application.
- SFE3 processes data in fixed 1 MiB records rather than wrapping independently encrypted files in a plaintext ZIP.
- The manifest is encrypted. New SFE3 containers do not expose original filenames, relative paths, file counts, exact individual sizes, MIME types, or filesystem timestamps in the clear.
- New encrypted downloads use a cryptographically random outer filename and the `.sfe3` extension instead of reusing the original filename.
- Final data records are zero-padded to a fixed 1 MiB payload size, reducing exact-size leakage at the record level.
- A secure 32-character password generator uses `crypto.getRandomValues()` with rejection sampling so character selection is unbiased.
- The password strength tracker is a predictability-aware local heuristic that considers length, character diversity, repeated chunks, repeated characters, sequential runs, keyboard patterns, and common weak passwords; it does not claim to measure exact entropy.
- Passwords for new SFE3 encryption are normalized using Unicode NFC, require 12–128 Unicode code points, and obvious weak patterns are rejected.
- Individual files are limited to 1 GiB and total plaintext input is limited to just under 4 GiB.
- Existing SFE1 and SFE2 files remain decryptable for migration.

## SFE3 container overview

The public header is fixed at 64 bytes:

`magic | version | KDF | cipher | flags | KDF parameters | 32-byte salt | 12-byte nonce base`

After the header:

`encrypted fixed-size manifest record | encrypted fixed-size data records`

The manifest record has a fixed 1 MiB plaintext payload. Each data record has a fixed 1 MiB plaintext payload plus a 4-byte actual-length field. AES-GCM adds a 128-bit authentication tag to every record.

Each record also authenticates the full SFE3 header, its record type and its record index as AES-GCM additional authenticated data (AAD). This binds the record to the exact container parameters and position.

## KDFs

### Argon2id (recommended)

SFE3 uses the RFC 9106 Argon2id algorithm with a 32-byte derived key. The default profile is:

- Memory: 64 MiB
- Passes: 3
- Lanes: 4
- Salt: 32 random bytes

The application exposes a custom whole-MiB memory value from 12 through 256 MiB. The implementation is fully local and does not load an external cryptography library or CDN asset.

### PBKDF2-HMAC-SHA-256

SFE3 supports PBKDF2-HMAC-SHA-256 with a visible custom iteration control from 600,000 through 2,000,000 iterations, defaulting to 600,000. The exact selected count is stored in the SFE3 header so decryption uses the same work factor.

It derives the same 256-bit AES key length used by the Argon2id path. Argon2id is the preferred choice for new files because it is memory-hard; PBKDF2 is available when a conventional, widely supported KDF is specifically desired.

### Argon2id memory control

SFE3 exposes a custom Argon2id memory setting from 12 MiB through 256 MiB. The default is 64 MiB, with 3 passes and 4 lanes. Higher memory settings increase the resources required for password guessing and increase RAM usage on the local device.

## Metadata protection

New SFE3 encryption does not put the original filename in the outer encrypted filename. It uses 32 random hexadecimal characters followed by `.sfe3`.

For multi-file encryption, SFE3 does not create a plaintext ZIP containing encrypted entries. Instead, the filenames and relative paths are stored in an authenticated encrypted manifest. The manifest also stores the data sizes required for reconstruction after decryption.

MIME types and source filesystem timestamps are not stored in the SFE3 manifest.

SFE3 deliberately does not claim that every observable side channel disappears. The encrypted container's total byte length remains observable and therefore reveals the total plaintext size rounded up to the 1 MiB record boundary. This is a normal limitation of a practical fixed-size container. The format substantially reduces unnecessary filename, path and per-file metadata leakage without requiring unbounded padding.

## Authentication and tamper detection

AES-256-GCM authenticates:

- the public SFE3 header,
- the record type,
- the record index,
- and the encrypted record contents.

SFE3 also derives each record nonce by adding the record index to a fresh random 96-bit nonce base. The expected nonce is checked before decryption. Reordering, replacing, truncating or modifying records therefore causes authentication or structural validation to fail.

## Compatibility

SFE3 is the format used for new encryption.

SFE1 and SFE2 remain read-only compatibility formats so existing encrypted files can be migrated by decrypting them and encrypting them again as SFE3. Legacy formats retain their original cryptographic constructions for compatibility; they are not silently rewritten in place.

## Running the application

Extract the release ZIP and open `index.html` in a modern browser. The release is designed to remain portable and offline-capable after loading. There is no Node.js requirement, no account, no server component, no upload step and no CDN dependency.

## Security scope

This project is an open-source client-side encryption utility. It has not undergone an independent cryptographic security audit. The security documentation in `SFE3-SECURITY-IMPLEMENTATION-AND-AUDIT.txt` explains the file format, threat model, implementation details and verification performed for this release.

A forgotten password cannot be recovered by the application. Choose a strong password and keep an independent backup of important encrypted files.
