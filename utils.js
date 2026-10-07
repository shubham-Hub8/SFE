/* ==========================================
   Simple File Encryptor
   Shared Utilities
========================================== */

"use strict";

/* ---------- DOM Cache ---------- */

const DOM = {

    encryptTab:
        document.getElementById("encryptTab"),

    decryptTab:
        document.getElementById("decryptTab"),

    fileInput:
        document.getElementById("fileInput"),

    chooseFile:
        document.getElementById("chooseFile"),

    pickerFiles:
        document.getElementById("pickerFiles"),

    pickerFolder:
        document.getElementById("pickerFolder"),

    dropZone:
        document.getElementById("dropZone"),

    selectedFile:
        document.getElementById("selectedFile"),

    password:
        document.getElementById("password"),

    confirmPassword:
        document.getElementById("confirmPassword"),

    showPassword:
        document.getElementById("showPassword"),

    generatePassword:
        document.getElementById("generatePassword"),

    strength:
        document.getElementById("strength"),

    actionButton:
        document.getElementById("actionButton"),

    progressBar:
        document.getElementById("progressBar"),

    status:
        document.getElementById("status"),

    outputFilename:
        document.getElementById("outputFilename"),

    downloadButton:
        document.getElementById("downloadButton"),

    argonMemoryRange:
        document.getElementById("argonMemoryRange"),

    argonMemoryInput:
        document.getElementById("argonMemoryInput"),

    argonMemoryValue:
        document.getElementById("argonMemoryValue"),

    argonControls:
        document.getElementById("argonControls"),

    pbkdf2Controls:
        document.getElementById("pbkdf2Controls"),

    pbkdf2IterationsRange:
        document.getElementById("pbkdf2IterationsRange"),

    pbkdf2IterationsInput:
        document.getElementById("pbkdf2IterationsInput"),

    pbkdf2IterationsValue:
        document.getElementById("pbkdf2IterationsValue"),

    kdf:
        document.getElementById("kdf"),

    kdfPicker:
        document.getElementById("kdfPicker"),

    kdfTrigger:
        document.getElementById("kdfTrigger"),

    kdfMenu:
        document.getElementById("kdfMenu"),

    kdfOptions:
        document.querySelectorAll(".kdf-picker__option"),

    kdfValue:
        document.querySelector(".kdf-picker__value"),

    strengthScore:
        document.getElementById("strengthScore"),

    strengthMeterBar:
        document.getElementById("strengthMeterBar"),

    strengthAdvice:
        document.getElementById("strengthAdvice")

};

/* ---------- Application State ---------- */

const State = {

    mode: "encrypt",

    selectedFiles: [],

    pickerMode: "files",

    previousEncryptPickerMode: "files",

    encryptedBlob: null,

    decryptedBlob: null,

    outputName: "",

    busy: false,

    argonMemoryKib: 65536,

    kdf: "argon2id",

    // Security setting used by the SFE3 PBKDF2 path.
    // This state is controlled by the visible security settings on the home page.
    pbkdf2Iterations: 600000

};

/* ---------- Status ---------- */

function setStatus(message) {

    DOM.status.textContent = message;

}

function clearStatus() {

    setStatus("Waiting...");

}

/* ---------- Progress ---------- */

function setProgress(percent) {

    const value = Math.max(

        0,

        Math.min(

            100,

            Number(percent)

        )

    );

    DOM.progressBar.style.width =

        value + "%";

}

function resetProgress() {

    setProgress(0);

}

function completeProgress() {

    setProgress(100);

}

/* ---------- Download ---------- */

function enableDownload() {

    DOM.downloadButton.disabled = false;

}

function disableDownload() {

    DOM.downloadButton.disabled = true;

}

/* ---------- Busy State ---------- */

function getSelectedArgon2Memory() {

    const value = Number.parseInt(
        DOM.argonMemoryInput?.value || State.argonMemoryKib / 1024,
        10
    );

    if (!Number.isFinite(value)) {
        return State.argonMemoryKib;
    }

    return value * 1024;

}

function setArgon2MemoryMiB(memoryMiB) {

    const value = Number(memoryMiB);

    if (!Number.isInteger(value)) {
        throw new Error("Argon2id memory must be a whole MiB value.");
    }

    if (value < 12 || value > 256) {
        throw new Error("Argon2id memory must be between 12 and 256 MiB.");
    }

    State.argonMemoryKib = value * 1024;
    return value;

}

function getPbkdf2Iterations() {

    const value = Number.parseInt(State.pbkdf2Iterations, 10);

    if (!Number.isFinite(value)) {
        return 600000;
    }

    return value;

}

function setPbkdf2Iterations(iterations) {

    const value = Number(iterations);

    if (!Number.isSafeInteger(value)) {
        throw new Error("PBKDF2 iteration count must be a whole number.");
    }

    // Keep the definitive security-range check inside crypto.js too.
    if (typeof validatePbkdf2Iterations === "function") {
        validatePbkdf2Iterations(value);
    }

    State.pbkdf2Iterations = value;
    return value;

}

function updateSecurityControlsUI() {

    const encryptMode = State.mode === "encrypt";
    const argonVisible = State.kdf === "argon2id";
    const pbkdf2Visible = State.kdf === "pbkdf2";
    const disabled = State.busy || !encryptMode;

    if (DOM.kdf) {
        DOM.kdf.value = State.kdf;
        DOM.kdf.disabled = disabled;
    }
    if (DOM.kdfTrigger) {
        DOM.kdfTrigger.disabled = disabled;
    }

    if (DOM.argonControls) {
        DOM.argonControls.hidden = !argonVisible;
    }

    if (DOM.pbkdf2Controls) {
        DOM.pbkdf2Controls.hidden = !pbkdf2Visible;
    }

    const memoryMiB = Math.round(State.argonMemoryKib / 1024);
    if (DOM.argonMemoryRange) {
        DOM.argonMemoryRange.value = String(memoryMiB);
        DOM.argonMemoryRange.disabled = disabled || !argonVisible;
    }
    if (DOM.argonMemoryInput) {
        DOM.argonMemoryInput.value = String(memoryMiB);
        DOM.argonMemoryInput.disabled = disabled || !argonVisible;
    }
    if (DOM.argonMemoryValue) {
        DOM.argonMemoryValue.textContent = `${memoryMiB} MiB`;
    }

    const iterations = getPbkdf2Iterations();
    if (DOM.pbkdf2IterationsRange) {
        const rangeMin = Number(DOM.pbkdf2IterationsRange.min);
        const rangeMax = Number(DOM.pbkdf2IterationsRange.max);
        DOM.pbkdf2IterationsRange.value = String(Math.min(rangeMax, Math.max(rangeMin, iterations)));
        DOM.pbkdf2IterationsRange.disabled = disabled || !pbkdf2Visible;
    }
    if (DOM.pbkdf2IterationsInput) {
        DOM.pbkdf2IterationsInput.value = String(iterations);
        DOM.pbkdf2IterationsInput.disabled = disabled || !pbkdf2Visible;
    }
    if (DOM.pbkdf2IterationsValue) {
        DOM.pbkdf2IterationsValue.textContent = iterations.toLocaleString();
    }

}

// Shared security-control refresh used by startup and mode changes.
function updateArgonMemoryUI() {
    updateSecurityControlsUI();
}

function setBusy(value) {

    State.busy = Boolean(value);

    DOM.actionButton.disabled =

        State.busy;

    DOM.chooseFile.disabled =

        State.busy;

    DOM.fileInput.disabled =

        State.busy;

    updateArgonMemoryUI();

}

/* ---------- Output ---------- */

/* ---------- Picker Mode ---------- */

function setPickerMode(mode, options = {}) {

    const nextMode = mode === "folder" ? "folder" : "files";

    if (State.mode === "encrypt") {

        State.pickerMode = nextMode;

    }

    else {

        if (options.preservePrevious !== false) {

            State.previousEncryptPickerMode = nextMode;

        }

        State.pickerMode = "files";

    }

    syncPickerInputMode();

    updatePickerModeUI();

}

function syncPickerInputMode() {

    DOM.fileInput.multiple = true;

    if (State.mode === "encrypt" && State.pickerMode === "folder") {

        DOM.fileInput.setAttribute("webkitdirectory", "");

    }

    else {

        DOM.fileInput.removeAttribute("webkitdirectory");

    }

}

function updatePickerModeUI() {

    const folderActive = State.mode === "encrypt" && State.pickerMode === "folder";
    const filesActive = !folderActive;

    if (DOM.pickerFiles) {
        DOM.pickerFiles.classList.toggle("active", filesActive);
        DOM.pickerFiles.disabled = State.busy || State.mode !== "encrypt";
    }

    if (DOM.pickerFolder) {
        DOM.pickerFolder.classList.toggle("active", folderActive);
        DOM.pickerFolder.disabled = State.busy || State.mode !== "encrypt";
    }

    if (DOM.chooseFile) {
        DOM.chooseFile.textContent = folderActive ? "Select Folder" : "Select Files";
    }

}

function clearOutput() {

    State.encryptedBlob = null;

    State.decryptedBlob = null;

    State.outputName = "";

    DOM.outputFilename.textContent =

        "No file generated.";

    disableDownload();

    resetProgress();

}

/* ---------- File Size ---------- */

function bytesToSize(bytes) {

    if (bytes === 0) {

        return "0 Bytes";

    }

    const units = [

        "Bytes",

        "KB",

        "MB",

        "GB",

        "TB"

    ];

    const index = Math.floor(

        Math.log(bytes) /

        Math.log(1024)

    );

    return (

        bytes /

        Math.pow(1024, index)

    ).toFixed(2)

    + " "

    + units[index];

}

/* ---------- Escape HTML ---------- */

function escapeHTML(text) {

    const div =

        document.createElement("div");

    div.textContent = text;

    return div.innerHTML;

}

/* ---------- Random ID ---------- */

function randomID(length = 8) {

    const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
    const values = new Uint32Array(length);
    crypto.getRandomValues(values);

    let output = "";

    for (const value of values) {
        output += alphabet[value % alphabet.length];
    }

    values.fill(0);
    return output;

}

function randomHex(byteLength = 16) {

    if (!Number.isInteger(byteLength) || byteLength < 1 || byteLength > 64) {
        throw new Error("Invalid random filename length.");
    }

    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);

    let output = "";

    for (const byte of bytes) {
        output += byte.toString(16).padStart(2, "0");
    }

    bytes.fill(0);
    return output;

}

/* ---------- File Names ---------- */

function removeExtension(filename) {

    const index =

        filename.lastIndexOf(".");

    if (index === -1) {

        return filename;

    }

    return filename.substring(

        0,

        index

    );

}

function getExtension(filename) {

    const index =

        filename.lastIndexOf(".");

    if (index === -1) {

        return "";

    }

    return filename.substring(index);

}

function buildEncryptedName() {

    // SFE3 must not expose the original filename in the encrypted artifact.
    return `${randomHex(16)}.sfe3`;

}

function buildDecryptedName(filename) {

    if (filename.endsWith(".sfe3")) {
        return filename.slice(0, -5) + "_decrypted";
    }

    if (filename.endsWith(".sfe")) {
        return filename.slice(0, -4);
    }

    return removeExtension(filename) + "_decrypted";

}

function getRelativePath(file) {

    if (

        file &&
        typeof file.webkitRelativePath === "string" &&
        file.webkitRelativePath.length > 0

    ) {

        return file.webkitRelativePath;

    }

    return file.name;

}

function getFolderNameFromSelection(files) {

    if (!Array.isArray(files) || files.length === 0) {

        return "";

    }

    const first = files[0];

    if (
        !first ||
        typeof first.webkitRelativePath !== "string" ||
        first.webkitRelativePath.length === 0
    ) {

        return "";

    }

    const parts = first.webkitRelativePath.split("/");

    return parts.length > 1 ? parts[0] : "";

}

function getSelectionCountLabel(files) {

    const count = Array.isArray(files) ? files.length : 0;

    return count === 1 ? "1 file selected" : `${count} files selected`;

}

/* ---------- Reset Helpers ---------- */

function resetInterface() {

    clearOutput();

    clearStatus();

    setBusy(false);

}

/* ---------- Browser Support ---------- */

function browserSupported() {

    return (

        window.isSecureContext &&

        window.crypto &&

        window.crypto.subtle &&

        window.File &&

        window.Blob &&

        window.TextEncoder &&

        window.TextDecoder

    );

}

function requireBrowserSupport() {

    if (browserSupported()) {

        return true;

    }

    setStatus(

        "Your browser does not support the required Web Crypto features."

    );

    DOM.actionButton.disabled = true;

    DOM.chooseFile.disabled = true;

    DOM.fileInput.disabled = true;

    return false;

}

/* ---------- Output Helpers ---------- */

function setOutput(blob, filename) {

    if (State.mode === "encrypt") {

        State.encryptedBlob = blob;

        State.decryptedBlob = null;

    }

    else {

        State.decryptedBlob = blob;

        State.encryptedBlob = null;

    }

    State.outputName = filename;

    DOM.outputFilename.textContent = filename;

    enableDownload();

}

/* ---------- Active Blob ---------- */

function getOutputBlob() {

    return (

        State.mode === "encrypt"

            ? State.encryptedBlob

            : State.decryptedBlob

    );

}

/* ---------- Startup ---------- */

resetInterface();

requireBrowserSupport();
