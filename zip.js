/* ==========================================
   Simple File Encryptor
   ZIP output builder

   This module is used only after successful decryption to package multiple
   plaintext files for the user's download. It is NOT part of the encrypted
   SFE3 container, so ZIP metadata is never exposed before decryption.
========================================== */

"use strict";

const ZIP_LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;
const ZIP_CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;
const ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50;
const zipTextEncoder = new TextEncoder();

function zipToUint8(value) {
    return value & 0xFF;
}

function zipU16(value) {
    return [zipToUint8(value), zipToUint8(value >>> 8)];
}

function zipU32(value) {
    return [
        zipToUint8(value),
        zipToUint8(value >>> 8),
        zipToUint8(value >>> 16),
        zipToUint8(value >>> 24)
    ];
}

function zipConcatBytes(chunks) {
    let total = 0;

    for (const chunk of chunks) {
        total += chunk.length;
    }

    const out = new Uint8Array(total);
    let offset = 0;

    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
    }

    return out;
}

let zipCrcTable = null;

function buildCrc32Table() {
    if (zipCrcTable) return zipCrcTable;

    const table = new Uint32Array(256);

    for (let n = 0; n < 256; n += 1) {
        let c = n;

        for (let k = 0; k < 8; k += 1) {
            c = (c & 1)
                ? (0xEDB88320 ^ (c >>> 1))
                : (c >>> 1);
        }

        table[n] = c >>> 0;
    }

    zipCrcTable = table;
    return table;
}

function crc32Update(crc, bytes) {
    const table = buildCrc32Table();
    let state = crc >>> 0;

    for (let i = 0; i < bytes.length; i += 1) {
        state = table[(state ^ bytes[i]) & 0xFF] ^ (state >>> 8);
    }

    return state >>> 0;
}

function crc32Finalize(crc) {
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

function crc32(bytes) {
    return crc32Finalize(crc32Update(0xFFFFFFFF, bytes));
}

function textBytes(text) {
    return zipTextEncoder.encode(text);
}

function sanitizeArchivePath(path) {
    if (typeof path !== 'string' || !path.length) {
        throw new Error('Invalid archive path.');
    }

    const normalized = path.replace(/\\/g, '/');

    if (
        normalized.startsWith('/') ||
        /^[A-Za-z]:\//.test(normalized) ||
        normalized.includes('\0')
    ) {
        throw new Error('Unsafe archive path.');
    }

    const parts = normalized.split('/');
    const safe = [];

    for (const part of parts) {
        if (!part || part === '.') continue;
        if (part === '..') throw new Error('Unsafe archive path.');
        safe.push(part);
    }

    const result = safe.join('/');

    if (!result || result.length > 65535) {
        throw new Error('Archive path is invalid or too long.');
    }

    return result;
}

function makeUniqueArchiveNames(entries) {
    const used = new Set();

    return entries.map(entry => {
        const base = sanitizeArchivePath(entry.name);

        if (!used.has(base)) {
            used.add(base);
            return { ...entry, name: base };
        }

        const slash = base.lastIndexOf('/');
        const directory = slash === -1 ? '' : base.slice(0, slash + 1);
        const filename = slash === -1 ? base : base.slice(slash + 1);
        const dot = filename.lastIndexOf('.');
        const stem = dot > 0 ? filename.slice(0, dot) : filename;
        const ext = dot > 0 ? filename.slice(dot) : '';

        let counter = 2;
        let candidate;

        do {
            candidate = `${directory}${stem} (${counter})${ext}`;
            counter += 1;
        } while (used.has(candidate));

        used.add(candidate);
        return { ...entry, name: candidate };
    });
}

async function createZipBlobFromBlobEntries(inputEntries) {
    if (!Array.isArray(inputEntries) || inputEntries.length === 0) {
        throw new Error('No files available for ZIP output.');
    }

    if (inputEntries.length > 65535) {
        throw new Error('Too many files for a classic ZIP archive.');
    }

    const entries = makeUniqueArchiveNames(inputEntries);
    const localHeaders = [];
    const centralHeaders = [];
    const dataParts = [];
    let offset = 0;
    let totalSize = 0;

    for (const entry of entries) {
        if (!(entry.blob instanceof Blob)) {
            throw new Error('Invalid ZIP entry blob.');
        }

        if (!Number.isInteger(entry.size) || entry.size < 0 || entry.size > 0xFFFFFFFF) {
            throw new Error('ZIP output exceeds classic ZIP size limits.');
        }

        if (entry.blob.size !== entry.size) {
            throw new Error('ZIP entry size mismatch.');
        }

        const nameBytes = textBytes(entry.name);
        const size = entry.size >>> 0;
        const crc = entry.crc32 >>> 0;

        const localHeader = zipConcatBytes([
            new Uint8Array(zipU32(ZIP_LOCAL_FILE_HEADER_SIGNATURE)),
            new Uint8Array(zipU16(20)),
            new Uint8Array(zipU16(0x0800)),
            new Uint8Array(zipU16(0)),
            new Uint8Array(zipU16(0)),
            new Uint8Array(zipU16(0)),
            new Uint8Array(zipU32(crc)),
            new Uint8Array(zipU32(size)),
            new Uint8Array(zipU32(size)),
            new Uint8Array(zipU16(nameBytes.length)),
            new Uint8Array(zipU16(0)),
            nameBytes
        ]);

        localHeaders.push(localHeader);
        dataParts.push(entry.blob);

        const centralHeader = zipConcatBytes([
            new Uint8Array(zipU32(ZIP_CENTRAL_DIRECTORY_SIGNATURE)),
            new Uint8Array(zipU16(20)),
            new Uint8Array(zipU16(20)),
            new Uint8Array(zipU16(0x0800)),
            new Uint8Array(zipU16(0)),
            new Uint8Array(zipU16(0)),
            new Uint8Array(zipU16(0)),
            new Uint8Array(zipU32(crc)),
            new Uint8Array(zipU32(size)),
            new Uint8Array(zipU32(size)),
            new Uint8Array(zipU16(nameBytes.length)),
            new Uint8Array(zipU16(0)),
            new Uint8Array(zipU16(0)),
            new Uint8Array(zipU16(0)),
            new Uint8Array(zipU16(0)),
            new Uint8Array(zipU32(0)),
            new Uint8Array(zipU32(offset)),
            nameBytes
        ]);

        centralHeaders.push(centralHeader);
        offset += localHeader.length + size;
        totalSize += size;

        if (offset > 0xFFFFFFFF || totalSize > 0xFFFFFFFF) {
            throw new Error('ZIP output exceeds classic ZIP limits.');
        }
    }

    const centralDirectory = zipConcatBytes(centralHeaders);

    const endRecord = zipConcatBytes([
        new Uint8Array(zipU32(ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE)),
        new Uint8Array(zipU16(0)),
        new Uint8Array(zipU16(0)),
        new Uint8Array(zipU16(entries.length)),
        new Uint8Array(zipU16(entries.length)),
        new Uint8Array(zipU32(centralDirectory.length)),
        new Uint8Array(zipU32(offset)),
        new Uint8Array(zipU16(0))
    ]);

    return new Blob([
        ...localHeaders,
        ...dataParts,
        centralDirectory,
        endRecord
    ], {
        type: 'application/zip'
    });
}

window.createZipBlobFromBlobEntries = createZipBlobFromBlobEntries;
window.crc32 = crc32;
window.crc32Update = crc32Update;
window.crc32Finalize = crc32Finalize;
window.sanitizeArchivePath = sanitizeArchivePath;
