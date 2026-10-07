/*
 * Simple File Encryptor 3.0
 * SFE3: Argon2id or PBKDF2 + AES-256-GCM
 *
 * New encryption uses the SFE3 container format.
 * SFE1 and SFE2 decryption remain available for legacy migration.
 *
 * SFE3 is deliberately record-oriented so large files can be processed in
 * 1 MiB chunks instead of constructing one giant plaintext ArrayBuffer.
 */

"use strict";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

/* ---------- Common constants ---------- */

const KEY_LENGTH = 32;
const GCM_TAG_BITS = 128;
const GCM_TAG_BYTES = GCM_TAG_BITS / 8;
const GCM_NONCE_LENGTH = 12;
const SFE3_SALT_LENGTH = 32;
const SFE3_HEADER_LENGTH = 64;
const SFE3_CHUNK_SIZE = 1024 * 1024; // 1 MiB
const SFE3_MANIFEST_PLAIN_LENGTH = 1024 * 1024; // fixed-size to hide manifest length
const SFE3_MAX_MANIFEST_FILES = 50000;
const SFE3_MAX_PATH_LENGTH = 4096;
const SFE3_MAX_PASSWORD_CODE_POINTS = 128;
const SFE3_MAX_TOTAL_SIZE = (4 * 1024 * 1024 * 1024) - 1;

/* ---------- SFE3 format ---------- */

const SFE3_MAGIC = new Uint8Array([0x53, 0x46, 0x45, 0x33]); // SFE3
const SFE3_VERSION = 1;
const SFE3_CIPHER_AES_256_GCM = 1;
const SFE3_KDF_ARGON2ID = 1;
const SFE3_KDF_PBKDF2_SHA256 = 2;
const SFE3_FLAG_NONE = 0;
const SFE3_RECORD_MANIFEST = 1;
const SFE3_RECORD_DATA = 2;
const SFE3_DEFAULT_PBKDF2_ITERATIONS = 600000;
const SFE3_MIN_PBKDF2_ITERATIONS = 600000;
const SFE3_MAX_PBKDF2_ITERATIONS = 2000000;

/* RFC 9106 second recommended Argon2id profile for memory-constrained use. */
const ARGON2_DEFAULT_MEMORY_KIB = 64 * 1024;
const ARGON2_PASSES = 3;
const ARGON2_PARALLELISM = 4;
const ARGON2_MIN_MEMORY_KIB = 12 * 1024;
const ARGON2_MAX_MEMORY_KIB = 256 * 1024;

/* ---------- Legacy formats ---------- */

const SFE1_HEADER = 'SFE1';
const SFE2_HEADER = new Uint8Array([0x53, 0x46, 0x45, 0x32]); // SFE2
const SFE2_VERSION = 1;
const SFE2_KDF_ARGON2ID = 1;
const SFE2_SALT_LENGTH = 16;
const SFE2_IV_LENGTH = 12;
const SFE2_HEADER_LENGTH = 46;

/* ---------- Byte helpers ---------- */

function randomBytes(length) {
    const out = new Uint8Array(length);
    crypto.getRandomValues(out);
    return out;
}

function writeU32LE(value) {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value >>> 0, true);
    return out;
}

function readU32LE(bytes, offset = 0) {
    if (offset < 0 || offset + 4 > bytes.byteLength) {
        throw new Error('Invalid 32-bit field offset.');
    }

    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
        .getUint32(offset, true);
}

function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;

    let diff = 0;
    for (let i = 0; i < a.length; i += 1) {
        diff |= a[i] ^ b[i];
    }

    return diff === 0;
}

function concatBytes(...chunks) {
    const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;

    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
    }

    return out;
}

function asciiBytes(value) {
    return encoder.encode(value);
}

function addU96(base, value) {
    if (!(base instanceof Uint8Array) || base.length !== GCM_NONCE_LENGTH) {
        throw new Error('Invalid SFE3 nonce base.');
    }

    if (!Number.isSafeInteger(value) || value < 0 || value > 0xFFFFFFFF) {
        throw new Error('Invalid SFE3 record index.');
    }

    const out = base.slice();
    let carry = value >>> 0;

    for (let word = 0; word < 3; word += 1) {
        const offset = word * 4;
        const current = readU32LE(out, offset);
        const sum = current + carry;
        new DataView(out.buffer, out.byteOffset, out.byteLength)
            .setUint32(offset, sum >>> 0, true);
        carry = sum > 0xFFFFFFFF ? 1 : 0;
    }

    if (carry !== 0) {
        throw new Error('SFE3 nonce space exhausted.');
    }

    return out;
}

function normalizePassword(password) {
    if (typeof password !== 'string') {
        throw new Error('Password must be a string.');
    }

    return typeof password.normalize === 'function'
        ? password.normalize('NFC')
        : password;
}

function passwordCodePointLength(password) {
    return Array.from(normalizePassword(password)).length;
}

function setKdfProgressSafe(progress) {
    if (typeof window.setKdfProgress === 'function') {
        window.setKdfProgress(progress);
    }
}

/* ---------- SFE3 header ---------- */

function buildSfe3Header({ kdf, cost1, cost2, cost3, salt, nonceBase }) {
    if (salt.length !== SFE3_SALT_LENGTH || nonceBase.length !== GCM_NONCE_LENGTH) {
        throw new Error('Invalid SFE3 salt or nonce size.');
    }

    return concatBytes(
        SFE3_MAGIC,
        new Uint8Array([
            SFE3_VERSION,
            kdf,
            SFE3_CIPHER_AES_256_GCM,
            SFE3_FLAG_NONE
        ]),
        writeU32LE(cost1),
        writeU32LE(cost2),
        writeU32LE(cost3),
        salt,
        nonceBase
    );
}

function validateArgon2Parameters(memorySize, passes, parallelism) {
    if (
        !Number.isInteger(memorySize) ||
        !Number.isInteger(passes) ||
        !Number.isInteger(parallelism) ||
        memorySize < ARGON2_MIN_MEMORY_KIB ||
        memorySize > ARGON2_MAX_MEMORY_KIB ||
        memorySize < (8 * parallelism) ||
        passes < 1 ||
        passes > 32 ||
        parallelism < 1 ||
        parallelism > 16
    ) {
        throw new Error('Invalid Argon2id parameters.');
    }
}

function validatePbkdf2Iterations(iterations) {
    if (
        !Number.isInteger(iterations) ||
        iterations < SFE3_MIN_PBKDF2_ITERATIONS ||
        iterations > SFE3_MAX_PBKDF2_ITERATIONS
    ) {
        throw new Error('Invalid PBKDF2 iteration count.');
    }
}

function parseSfe3Header(bytes) {
    if (bytes.length !== SFE3_HEADER_LENGTH) {
        throw new Error('Invalid SFE3 header length.');
    }

    if (!constantTimeEqual(bytes.slice(0, 4), SFE3_MAGIC)) {
        throw new Error('Invalid SFE3 file.');
    }

    const version = bytes[4];
    const kdf = bytes[5];
    const cipher = bytes[6];
    const flags = bytes[7];
    const cost1 = readU32LE(bytes, 8);
    const cost2 = readU32LE(bytes, 12);
    const cost3 = readU32LE(bytes, 16);
    const salt = bytes.slice(20, 52);
    const nonceBase = bytes.slice(52, 64);

    if (version !== SFE3_VERSION) {
        throw new Error('Unsupported SFE3 version.');
    }

    if (cipher !== SFE3_CIPHER_AES_256_GCM || flags !== SFE3_FLAG_NONE) {
        throw new Error('Unsupported SFE3 cipher or flags.');
    }

    if (kdf === SFE3_KDF_ARGON2ID) {
        validateArgon2Parameters(cost1, cost2, cost3);
    } else if (kdf === SFE3_KDF_PBKDF2_SHA256) {
        validatePbkdf2Iterations(cost1);
        if (cost2 !== 0 || cost3 !== 0) {
            throw new Error('Invalid PBKDF2 parameters.');
        }
    } else {
        throw new Error('Unsupported SFE3 KDF.');
    }

    return {
        header: bytes.slice(),
        version,
        kdf,
        cipher,
        flags,
        cost1,
        cost2,
        cost3,
        salt,
        nonceBase
    };
}

function describeSfe3Kdf(header) {
    if (header.kdf === SFE3_KDF_ARGON2ID) {
        return `Argon2id (${formatArgon2Memory(header.cost1)}, ${header.cost2} passes, ${header.cost3} lanes)`;
    }

    return `PBKDF2-HMAC-SHA-256 (${header.cost1.toLocaleString()} iterations)`;
}

/* ---------- SFE3 key derivation ---------- */

async function deriveSfe3Key(password, header) {
    const normalizedPassword = normalizePassword(password);
    const passwordBytes = encoder.encode(normalizedPassword);
    let keyMaterial;

    try {
        if (header.kdf === SFE3_KDF_ARGON2ID) {
            keyMaterial = window.SFEArgon2id.derive(
                passwordBytes,
                header.salt,
                {
                    m: header.cost1,
                    t: header.cost2,
                    p: header.cost3
                },
                progress => setKdfProgressSafe(progress)
            );
        } else {
            const passwordKey = await crypto.subtle.importKey(
                'raw',
                passwordBytes,
                'PBKDF2',
                false,
                ['deriveBits']
            );

            const bits = await crypto.subtle.deriveBits(
                {
                    name: 'PBKDF2',
                    hash: 'SHA-256',
                    salt: header.salt,
                    iterations: header.cost1
                },
                passwordKey,
                256
            );

            keyMaterial = new Uint8Array(bits);
            setKdfProgressSafe(1);
        }
    } finally {
        passwordBytes.fill(0);
    }

    if (!(keyMaterial instanceof Uint8Array) || keyMaterial.length !== KEY_LENGTH) {
        if (keyMaterial instanceof Uint8Array) keyMaterial.fill(0);
        throw new Error('Key derivation returned invalid key material.');
    }

    try {
        return await crypto.subtle.importKey(
            'raw',
            keyMaterial,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );
    } finally {
        keyMaterial.fill(0);
    }
}

/* ---------- SFE3 record cryptography ---------- */

function getSfe3RecordNonce(header, recordIndex) {
    return addU96(header.nonceBase, recordIndex);
}

function buildSfe3RecordAAD(header, recordType, recordIndex) {
    return concatBytes(
        header.header,
        new Uint8Array([recordType]),
        writeU32LE(recordIndex)
    );
}

async function encryptSfe3Record(key, header, recordType, recordIndex, plaintext) {
    const nonce = getSfe3RecordNonce(header, recordIndex);
    const aad = buildSfe3RecordAAD(header, recordType, recordIndex);

    const ciphertext = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: nonce,
            additionalData: aad,
            tagLength: GCM_TAG_BITS
        },
        key,
        plaintext
    );

    return concatBytes(
        new Uint8Array([recordType]),
        nonce,
        new Uint8Array(ciphertext)
    );
}

async function decryptSfe3Record(key, header, recordType, recordIndex, recordBytes, expectedCipherLength) {
    const expectedLength = 1 + GCM_NONCE_LENGTH + expectedCipherLength;

    if (recordBytes.length !== expectedLength) {
        throw new Error('Invalid SFE3 record length.');
    }

    if (recordBytes[0] !== recordType) {
        throw new Error('Invalid SFE3 record type.');
    }

    const nonce = recordBytes.slice(1, 1 + GCM_NONCE_LENGTH);
    const expectedNonce = getSfe3RecordNonce(header, recordIndex);

    if (!constantTimeEqual(nonce, expectedNonce)) {
        throw new Error('Invalid SFE3 record nonce.');
    }

    const ciphertext = recordBytes.slice(1 + GCM_NONCE_LENGTH);
    const aad = buildSfe3RecordAAD(header, recordType, recordIndex);

    return new Uint8Array(await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: nonce,
            additionalData: aad,
            tagLength: GCM_TAG_BITS
        },
        key,
        ciphertext
    ));
}

/* ---------- SFE3 manifest ---------- */

function validateRelativePathForManifest(path) {
    if (typeof path !== 'string' || path.length === 0 || path.length > SFE3_MAX_PATH_LENGTH) {
        throw new Error('A selected filename/path is invalid or too long.');
    }

    if (path.includes('\0')) {
        throw new Error('A selected filename contains an invalid null character.');
    }

    const normalized = path.replace(/\\/g, '/');

    if (normalized.startsWith('/') || /^[A-Za-z]:\//.test(normalized)) {
        throw new Error('Absolute paths are not allowed in SFE3 containers.');
    }

    const parts = normalized.split('/');
    if (parts.some(part => part === '..')) {
        throw new Error('Parent-directory paths are not allowed.');
    }

    return parts.filter(part => part !== '' && part !== '.').join('/');
}

function buildSfe3Manifest(files) {
    if (!Array.isArray(files) || files.length === 0) {
        throw new Error('No files were selected.');
    }

    if (files.length > SFE3_MAX_MANIFEST_FILES) {
        throw new Error(`Too many files selected. The maximum is ${SFE3_MAX_MANIFEST_FILES.toLocaleString()}.`);
    }

    const entries = [];
    const seen = new Set();
    let totalSize = 0;

    for (const file of files) {
        if (!(file instanceof Blob)) {
            throw new Error('Invalid file selection.');
        }

        const path = validateRelativePathForManifest(getRelativePath(file));

        if (seen.has(path)) {
            throw new Error(`Duplicate file path detected: ${path}`);
        }

        if (!Number.isSafeInteger(file.size) || file.size <= 0 || file.size > MAX_FILE_SIZE) {
            throw new Error('One or more selected files are invalid or exceed the 1 GB file limit.');
        }

        seen.add(path);
        entries.push({
            path,
            size: file.size
        });

        totalSize += file.size;

        if (totalSize > SFE3_MAX_TOTAL_SIZE) {
            throw new Error('The selected files exceed the safe total container size limit.');
        }
    }

    const manifestObject = {
        format: 'SFE3',
        manifestVersion: 1,
        chunkSize: SFE3_CHUNK_SIZE,
        files: entries
    };

    const jsonBytes = encoder.encode(JSON.stringify(manifestObject));

    if (jsonBytes.length > SFE3_MANIFEST_PLAIN_LENGTH - 4) {
        throw new Error('The encrypted manifest is too large for the SFE3 fixed-size manifest record.');
    }

    const block = new Uint8Array(SFE3_MANIFEST_PLAIN_LENGTH);
    block.set(writeU32LE(jsonBytes.length), 0);
    block.set(jsonBytes, 4);

    jsonBytes.fill(0);

    return { block, entries, totalSize };
}

function parseSfe3Manifest(block) {
    if (block.length !== SFE3_MANIFEST_PLAIN_LENGTH) {
        throw new Error('Invalid SFE3 manifest record.');
    }

    const jsonLength = readU32LE(block, 0);

    if (jsonLength === 0 || jsonLength > SFE3_MANIFEST_PLAIN_LENGTH - 4) {
        throw new Error('Invalid SFE3 manifest length.');
    }

    const jsonBytes = block.slice(4, 4 + jsonLength);
    let manifest;

    try {
        manifest = JSON.parse(decoder.decode(jsonBytes));
    } catch {
        throw new Error('The SFE3 manifest is invalid.');
    } finally {
        jsonBytes.fill(0);
    }

    if (
        !manifest ||
        manifest.format !== 'SFE3' ||
        manifest.manifestVersion !== 1 ||
        manifest.chunkSize !== SFE3_CHUNK_SIZE ||
        !Array.isArray(manifest.files) ||
        manifest.files.length === 0 ||
        manifest.files.length > SFE3_MAX_MANIFEST_FILES
    ) {
        throw new Error('Unsupported or malformed SFE3 manifest.');
    }

    const entries = [];
    const seen = new Set();
    let totalSize = 0;

    for (const entry of manifest.files) {
        if (!entry || typeof entry.path !== 'string' || !Number.isSafeInteger(entry.size)) {
            throw new Error('Malformed SFE3 manifest entry.');
        }

        const path = validateRelativePathForManifest(entry.path);

        if (seen.has(path)) {
            throw new Error('Duplicate file path detected in the SFE3 manifest.');
        }

        if (entry.size <= 0 || entry.size > MAX_FILE_SIZE) {
            throw new Error('A file in the SFE3 manifest has an invalid size.');
        }

        totalSize += entry.size;
        if (totalSize > SFE3_MAX_TOTAL_SIZE) {
            throw new Error('The SFE3 manifest exceeds the supported total size.');
        }

        seen.add(path);
        entries.push({ path, size: entry.size });
    }

    block.fill(0);

    return { entries, totalSize };
}

/* ---------- SFE3 encryption ---------- */

function getSelectedKdf() {
    if (!DOM.kdf) return 'argon2id';
    return DOM.kdf.value === 'pbkdf2' ? 'pbkdf2' : 'argon2id';
}

function getSfe3EncryptionConfig() {
    const kdf = getSelectedKdf();

    if (kdf === 'pbkdf2') {
        const iterations = getPbkdf2Iterations();
        validatePbkdf2Iterations(iterations);

        return {
            kdf: SFE3_KDF_PBKDF2_SHA256,
            cost1: iterations,
            cost2: 0,
            cost3: 0
        };
    }

    const memorySize = getSelectedArgon2Memory();
    validateArgon2Parameters(memorySize, ARGON2_PASSES, ARGON2_PARALLELISM);

    return {
        kdf: SFE3_KDF_ARGON2ID,
        cost1: memorySize,
        cost2: ARGON2_PASSES,
        cost3: ARGON2_PARALLELISM
    };
}

async function encryptSfe3Files(files, password) {
    const normalizedPassword = normalizePassword(password);
    const passwordLength = passwordCodePointLength(normalizedPassword);

    if (passwordLength < 12 || passwordLength > SFE3_MAX_PASSWORD_CODE_POINTS) {
        throw new Error('SFE3 encryption passwords must contain 12 to 128 Unicode code points.');
    }

    if (typeof isObviousWeakPassword === 'function' && isObviousWeakPassword(normalizedPassword)) {
        throw new Error('The selected password is too predictable. Use a longer, less predictable password.');
    }

    const manifest = buildSfe3Manifest(files);
    const config = getSfe3EncryptionConfig();
    const salt = randomBytes(SFE3_SALT_LENGTH);
    const nonceBase = randomBytes(GCM_NONCE_LENGTH);
    const headerBytes = buildSfe3Header({
        ...config,
        salt,
        nonceBase
    });
    const header = parseSfe3Header(headerBytes);
    const key = await deriveSfe3Key(normalizedPassword, header);

    try {
        const parts = [headerBytes];
        let recordIndex = 0;

        const encryptedManifest = await encryptSfe3Record(
            key,
            header,
            SFE3_RECORD_MANIFEST,
            recordIndex,
            manifest.block
        );

        parts.push(encryptedManifest);
        recordIndex += 1;

        let processed = 0;
        const totalSize = manifest.totalSize;

        for (const file of files) {
            for (let offset = 0; offset < file.size; offset += SFE3_CHUNK_SIZE) {
                const end = Math.min(file.size, offset + SFE3_CHUNK_SIZE);
                const chunk = new Uint8Array(await file.slice(offset, end).arrayBuffer());
                const plainBlock = new Uint8Array(4 + SFE3_CHUNK_SIZE);

                try {
                    plainBlock.set(writeU32LE(chunk.length), 0);
                    plainBlock.set(chunk, 4);

                    const encryptedRecord = await encryptSfe3Record(
                        key,
                        header,
                        SFE3_RECORD_DATA,
                        recordIndex,
                        plainBlock
                    );

                    parts.push(encryptedRecord);
                    recordIndex += 1;
                    processed += chunk.length;

                    setProgress(20 + ((processed / totalSize) * 75));
                } finally {
                    chunk.fill(0);
                    plainBlock.fill(0);
                }
            }
        }

        return new Blob(parts, { type: 'application/octet-stream' });
    } finally {
        manifest.block.fill(0);
        salt.fill(0);
        nonceBase.fill(0);
    }
}

/* ---------- SFE3 decryption ---------- */

async function readBlobBytes(blob, start, end) {
    return new Uint8Array(await blob.slice(start, end).arrayBuffer());
}

function getSfe3RecordSize(type) {
    if (type === SFE3_RECORD_MANIFEST) {
        return 1 + GCM_NONCE_LENGTH + SFE3_MANIFEST_PLAIN_LENGTH + GCM_TAG_BYTES;
    }

    if (type === SFE3_RECORD_DATA) {
        return 1 + GCM_NONCE_LENGTH + 4 + SFE3_CHUNK_SIZE + GCM_TAG_BYTES;
    }

    throw new Error('Unknown SFE3 record type.');
}

function getBaseFilename(path) {
    const normalized = path.replace(/\\/g, '/');
    const index = normalized.lastIndexOf('/');
    return index === -1 ? normalized : normalized.slice(index + 1);
}

async function decryptSfe3File(file, password) {
    const headerBytes = await readBlobBytes(file, 0, SFE3_HEADER_LENGTH);
    const header = parseSfe3Header(headerBytes);
    const key = await deriveSfe3Key(password, header);

    const manifestRecordSize = getSfe3RecordSize(SFE3_RECORD_MANIFEST);
    const dataRecordSize = getSfe3RecordSize(SFE3_RECORD_DATA);

    if (file.size < SFE3_HEADER_LENGTH + manifestRecordSize) {
        throw new Error('SFE3 file is truncated.');
    }

    try {
        setProgress(15);

        const manifestBytes = await readBlobBytes(
            file,
            SFE3_HEADER_LENGTH,
            SFE3_HEADER_LENGTH + manifestRecordSize
        );

        const manifestPlain = await decryptSfe3Record(
            key,
            header,
            SFE3_RECORD_MANIFEST,
            0,
            manifestBytes,
            SFE3_MANIFEST_PLAIN_LENGTH + GCM_TAG_BYTES
        );

        manifestBytes.fill(0);
        const manifest = parseSfe3Manifest(manifestPlain);
        manifestPlain.fill(0);

        const expectedDataRecords = Math.ceil(manifest.totalSize / SFE3_CHUNK_SIZE);
        const dataStart = SFE3_HEADER_LENGTH + manifestRecordSize;
        const remaining = file.size - dataStart;

        if (remaining !== expectedDataRecords * dataRecordSize) {
            throw new Error('SFE3 data-record count does not match the authenticated manifest.');
        }

        const states = manifest.entries.map(entry => ({
            path: entry.path,
            size: entry.size,
            parts: [],
            written: 0,
            crc: 0xFFFFFFFF
        }));

        let currentFile = 0;
        let currentOffset = 0;
        let processed = 0;

        for (let record = 0; record < expectedDataRecords; record += 1) {
            const start = dataStart + (record * dataRecordSize);
            const end = start + dataRecordSize;
            const recordBytes = await readBlobBytes(file, start, end);
            const plain = await decryptSfe3Record(
                key,
                header,
                SFE3_RECORD_DATA,
                record + 1,
                recordBytes,
                4 + SFE3_CHUNK_SIZE + GCM_TAG_BYTES
            );

            recordBytes.fill(0);

            const actualLength = readU32LE(plain, 0);
            const remainingPlain = manifest.totalSize - processed;
            const expectedLength = Math.min(SFE3_CHUNK_SIZE, remainingPlain);

            if (actualLength !== expectedLength) {
                plain.fill(0);
                throw new Error('Invalid SFE3 chunk length.');
            }

            let chunkOffset = 0;

            while (chunkOffset < actualLength) {
                if (currentFile >= states.length) {
                    plain.fill(0);
                    throw new Error('SFE3 data exceeds the manifest.');
                }

                const state = states[currentFile];
                const remainingFileBytes = state.size - currentOffset;
                const take = Math.min(remainingFileBytes, actualLength - chunkOffset);
                const part = plain.subarray(4 + chunkOffset, 4 + chunkOffset + take);

                const ownedPart = part.slice();
                state.parts.push(ownedPart);
                state.crc = crc32Update(state.crc, ownedPart);
                state.written += take;

                chunkOffset += take;
                currentOffset += take;

                if (currentOffset === state.size) {
                    currentFile += 1;
                    currentOffset = 0;
                }
            }

            processed += actualLength;
            setProgress(20 + ((processed / manifest.totalSize) * 70));
        }

        if (currentFile !== states.length || currentOffset !== 0 || processed !== manifest.totalSize) {
            throw new Error('SFE3 payload length does not match the authenticated manifest.');
        }

        const outputs = states.map(state => ({
            name: sanitizeArchivePath(state.path),
            blob: new Blob(state.parts, { type: 'application/octet-stream' }),
            size: state.size,
            crc32: crc32Finalize(state.crc)
        }));

        if (outputs.length === 1) {
            setOutput(outputs[0].blob, getBaseFilename(outputs[0].name));
        } else {
            const zipBlob = await createZipBlobFromBlobEntries(outputs);
            setOutput(zipBlob, 'decrypted_files.zip');
        }

        completeProgress();
        return {
            fileCount: outputs.length,
            kdfDescription: describeSfe3Kdf(header)
        };
    } finally {
        headerBytes.fill(0);
    }
}

/* ---------- Legacy SFE2 decryption ---------- */

async function deriveLegacyArgon2id(password, salt, memorySize, passes, parallelism) {
    const normalized = password;
    const passwordBytes = encoder.encode(normalized);

    try {
        const result = window.SFEArgon2idLegacy.derive(
            passwordBytes,
            salt,
            {
                m: memorySize,
                t: passes,
                p: parallelism
            },
            progress => setKdfProgressSafe(progress)
        );

        if (!(result instanceof Uint8Array) || result.length !== KEY_LENGTH) {
            throw new Error('Argon2id returned an invalid legacy key.');
        }

        return await crypto.subtle.importKey(
            'raw',
            result,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        ).finally(() => result.fill(0));
    } finally {
        passwordBytes.fill(0);
    }
}

function parseSfe2(buffer) {
    const bytes = new Uint8Array(buffer);

    if (bytes.length < SFE2_HEADER_LENGTH + GCM_TAG_BYTES) {
        throw new Error('Encrypted file is truncated.');
    }

    if (!constantTimeEqual(bytes.slice(0, 4), SFE2_HEADER)) {
        throw new Error('Invalid SFE2 file.');
    }

    const version = bytes[4];
    const kdf = bytes[5];
    const memorySize = readU32LE(bytes, 6);
    const passes = readU32LE(bytes, 10);
    const parallelism = readU32LE(bytes, 14);
    const salt = bytes.slice(18, 34);
    const iv = bytes.slice(34, 46);

    if (version !== SFE2_VERSION || kdf !== SFE2_KDF_ARGON2ID) {
        throw new Error('Unsupported SFE2 version or KDF.');
    }

    validateArgon2Parameters(memorySize, passes, parallelism);

    return {
        header: bytes.slice(0, SFE2_HEADER_LENGTH),
        salt,
        iv,
        data: bytes.slice(SFE2_HEADER_LENGTH),
        memorySize,
        passes,
        parallelism
    };
}

async function decryptSfe1(buffer, password) {
    const bytes = new Uint8Array(buffer);

    if (bytes.length < 4 + 16 + 12 + GCM_TAG_BYTES) {
        throw new Error('Encrypted file is truncated.');
    }

    const header = decoder.decode(bytes.slice(0, 4));
    if (header !== SFE1_HEADER) throw new Error('Invalid encrypted file.');

    const salt = bytes.slice(4, 20);
    const iv = bytes.slice(20, 32);
    const data = bytes.slice(32);
    const passwordBytes = encoder.encode(password);

    try {
        const passwordKey = await crypto.subtle.importKey(
            'raw',
            passwordBytes,
            'PBKDF2',
            false,
            ['deriveKey']
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                hash: 'SHA-256',
                salt,
                iterations: 250000
            },
            passwordKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        return await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            data
        );
    } finally {
        passwordBytes.fill(0);
        salt.fill(0);
        iv.fill(0);
    }
}

async function decryptSfe2(buffer, password) {
    const parsed = parseSfe2(buffer);
    const key = await deriveLegacyArgon2id(
        password,
        parsed.salt,
        parsed.memorySize,
        parsed.passes,
        parsed.parallelism
    );

    try {
        return await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: parsed.iv,
                additionalData: parsed.header,
                tagLength: GCM_TAG_BITS
            },
            key,
            parsed.data
        );
    } finally {
        parsed.salt.fill(0);
        parsed.iv.fill(0);
        parsed.header.fill(0);
    }
}

/* ---------- Top-level operations ---------- */

async function detectFormat(blob) {
    const magic = await readBlobBytes(blob, 0, Math.min(4, blob.size));
    const text = magic.length === 4 ? decoder.decode(magic) : '';
    magic.fill(0);
    return text;
}

function formatArgon2Memory(kib) {
    return `${Math.round(kib / 1024)} MiB`;
}

window.setKdfProgress = progress => {
    setProgress(15 + Math.min(65, progress * 65));
};

// Security-only configuration hooks.
// No UI is attached to these yet; the future PBKDF2 control can use them
// without duplicating validation or touching the SFE3 binary format.
window.SFESecurity = Object.freeze({
    getPbkdf2Iterations: () => getPbkdf2Iterations(),
    setPbkdf2Iterations: iterations => setPbkdf2Iterations(iterations),
    validatePbkdf2Iterations: iterations => validatePbkdf2Iterations(iterations)
});

async function encryptFiles(files, password) {
    try {
        setBusy(true);
        setStatus('Preparing secure SFE3 container...');
        resetProgress();

        const output = await encryptSfe3Files(files, password);
        const outputName = buildEncryptedName('');

        setOutput(output, outputName);
        completeProgress();
        const selectedConfig = getSfe3EncryptionConfig();
        setStatus(`Encrypted with ${describeSfe3Kdf(selectedConfig)} + AES-256-GCM. SFE3 metadata protection enabled.`);
        return true;
    } catch (error) {
        console.error(error);
        clearOutput();
        setStatus(error instanceof Error ? error.message : 'Encryption failed.');
        return false;
    } finally {
        setBusy(false);
    }
}

async function decryptFile(file, password) {
    try {
        setBusy(true);
        setStatus('Inspecting encrypted container...');
        resetProgress();

        const format = await detectFormat(file);

        if (format === 'SFE3') {
            setStatus('Deriving SFE3 decryption key...');
            const result = await decryptSfe3File(file, password);
            setStatus(`SFE3 decrypted successfully using ${result.kdfDescription}.`);
            return true;
        }

        const buffer = await file.arrayBuffer();

        if (format === SFE1_HEADER) {
            setStatus('Decrypting legacy SFE1 container...');
            const decrypted = await decryptSfe1(buffer, password);
            setOutput(
                new Blob([decrypted], { type: 'application/octet-stream' }),
                buildDecryptedName(file.name)
            );
            new Uint8Array(buffer).fill(0);
            completeProgress();
            setStatus('Legacy SFE1 file decrypted successfully.');
            return true;
        }

        if (format === 'SFE2') {
            const parsed = parseSfe2(buffer);
            setStatus(`Decrypting legacy SFE2 container (${formatArgon2Memory(parsed.memorySize)}, ${parsed.passes} passes)...`);
            const decrypted = await decryptSfe2(buffer, password);
            setOutput(
                new Blob([decrypted], { type: 'application/octet-stream' }),
                buildDecryptedName(file.name)
            );
            new Uint8Array(buffer).fill(0);
            completeProgress();
            setStatus('Legacy SFE2 file decrypted successfully.');
            return true;
        }

        throw new Error('Unsupported encrypted file format.');
    } catch (error) {
        console.error(error);
        clearOutput();
        setStatus('Incorrect password or corrupted/unsupported encrypted file.');
        return false;
    } finally {
        setBusy(false);
    }
}

async function processFiles(files, password) {
    return State.mode === 'encrypt'
        ? encryptFiles(files, password)
        : decryptFile(files[0], password);
}

async function processFile(file, password) {
    return processFiles([file], password);
}

window.encryptFile = file => encryptFiles([file], DOM.password.value);
window.decryptFile = decryptFile;
window.processFile = processFile;
window.processFiles = processFiles;

window.SFE3 = Object.freeze({
    version: SFE3_VERSION,
    format: 'SFE3',
    cipher: 'AES-256-GCM',
    kdfs: Object.freeze({
        argon2id: 'Argon2id',
        pbkdf2: 'PBKDF2-HMAC-SHA-256'
    }),
    saltBytes: SFE3_SALT_LENGTH,
    nonceBytes: GCM_NONCE_LENGTH,
    chunkBytes: SFE3_CHUNK_SIZE,
    argon2id: Object.freeze({
        defaultMemoryKiB: ARGON2_DEFAULT_MEMORY_KIB,
        minMemoryKiB: ARGON2_MIN_MEMORY_KIB,
        maxMemoryKiB: ARGON2_MAX_MEMORY_KIB,
        passes: ARGON2_PASSES,
        parallelism: ARGON2_PARALLELISM
    }),
    pbkdf2: Object.freeze({
        defaultIterations: SFE3_DEFAULT_PBKDF2_ITERATIONS,
        minIterations: SFE3_MIN_PBKDF2_ITERATIONS,
        maxIterations: SFE3_MAX_PBKDF2_ITERATIONS
    })
});
