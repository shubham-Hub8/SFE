/* ==========================================
   Simple File Encryptor
   File Management
========================================== */

"use strict";

/* ---------- Configuration ---------- */

const MAX_FILE_SIZE = 1024 * 1024 * 1024; // 1 GiB per file
const MAX_TOTAL_SIZE = (4 * 1024 * 1024 * 1024) - 1; // classic ZIP-safe total for decrypted multi-file output

/* ---------- Choose File Button ---------- */

DOM.chooseFile.addEventListener("click", () => {

    DOM.fileInput.click();

});

/* ---------- File Picker ---------- */

DOM.fileInput.addEventListener("change", (event) => {

    const files = Array.from(event.target.files || []);

    if (!files.length) {

        return;

    }

    loadFiles(files);

});

/* ---------- Load Files ---------- */

function loadFiles(files) {

    const validFiles = files.filter(file => file instanceof File);

    if (!validFiles.length) {

        setStatus("Invalid file selection.");

        return false;

    }

    const nonEmptyFiles = validFiles.filter(file => file.size > 0);

    if (!nonEmptyFiles.length) {

        setStatus("The selected file(s) are empty.");

        return false;

    }

    if (nonEmptyFiles.some(file => file.size > MAX_FILE_SIZE)) {

        setStatus("One or more files exceed the 1 GB size limit.");

        DOM.fileInput.value = "";

        return false;

    }

    const totalSize = nonEmptyFiles.reduce(
        (sum, file) => sum + file.size,
        0
    );

    if (totalSize > MAX_TOTAL_SIZE) {

        setStatus("The selected files exceed the total container size limit.");

        DOM.fileInput.value = "";

        return false;

    }

    State.selectedFiles = nonEmptyFiles;

    clearOutput();

    const countLabel = getSelectionCountLabel(nonEmptyFiles);
    const folderName = getFolderNameFromSelection(nonEmptyFiles);
    const previewFiles = nonEmptyFiles.slice(0, 5);

    const previewHTML = previewFiles.map(file => {
        const path = getRelativePath(file);
        return `<li>${escapeHTML(path)} <span class="muted">(${bytesToSize(file.size)})</span></li>`;
    }).join("");

    const remaining = nonEmptyFiles.length - previewFiles.length;
    const remainingHTML = remaining > 0
        ? `<li class="muted">…and ${remaining} more</li>`
        : "";

    DOM.selectedFile.innerHTML = `
        <strong>${escapeHTML(countLabel)}</strong>
        ${folderName ? `<br>Folder: ${escapeHTML(folderName)}` : ""}
        <ul class="file-selection-list">
            ${previewHTML}
            ${remainingHTML}
        </ul>
    `;

    setStatus(
        nonEmptyFiles.length === 1
            ? "File loaded successfully."
            : "Files loaded successfully."
    );

    return true;

}

/* ---------- Backward-Compatible Load File ---------- */

function loadFile(file) {

    return loadFiles([file]);

}

/* ---------- Clear File ---------- */

function clearFile() {

    State.selectedFiles = [];

    DOM.fileInput.value = "";

    DOM.selectedFile.textContent = "No files selected";

    clearOutput();

}

/* ---------- Validation ---------- */

function hasFiles() {

    if (!State.selectedFiles.length) {

        setStatus("Please choose a file or folder first.");

        return false;

    }

    if (State.mode === "decrypt" && State.selectedFiles.length !== 1) {

        setStatus("Please choose one encrypted file to decrypt.");

        return false;

    }

    return true;

}

function hasFile() {

    return hasFiles();

}

/* ---------- Selection Helpers ---------- */

function getSelectedFiles() {

    return State.selectedFiles.slice();

}
