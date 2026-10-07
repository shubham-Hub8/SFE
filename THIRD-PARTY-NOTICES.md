# Third-party notices

## Runtime cryptography

Simple File Encryptor 3.0 does not load cryptographic libraries, modules, or CDN assets at runtime. The application is self-contained and can be opened directly from `index.html`.

- **Argon2id:** RFC 9106 Argon2id implementation included in `js/argon2id.js`.
- **AES-256-GCM:** provided by the browser's Web Crypto API.
- **PBKDF2-HMAC-SHA-256:** provided by the browser's Web Crypto API for the SFE3 alternate KDF.
- **Randomness:** provided by the browser's cryptographically secure `crypto.getRandomValues()` API.

The Argon2id implementation is intentionally dependency-free so the release remains portable and offline-capable.
