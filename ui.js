/* ==========================================
   Simple File Encryptor
   User Interface
========================================== */

"use strict";

/* ---------- Encrypt Mode ---------- */

DOM.encryptTab.addEventListener(

    "click",

    () => {

        setMode("encrypt");

    }

);

/* ---------- Decrypt Mode ---------- */

DOM.decryptTab.addEventListener(

    "click",

    () => {

        setMode("decrypt");

    }

);

/* ---------- Picker Mode ---------- */

if (DOM.pickerFiles) {

    DOM.pickerFiles.addEventListener("click", () => {

        setPickerMode("files");

        DOM.fileInput.value = "";

    });

}

if (DOM.pickerFolder) {

    DOM.pickerFolder.addEventListener("click", () => {

        setPickerMode("folder");

        DOM.fileInput.value = "";

    });

}


function syncArgonMemoryFromInput(rawValue) {
    const value = Number.parseInt(rawValue, 10);
    if (!Number.isFinite(value)) {
        updateSecurityControlsUI();
        return;
    }
    try {
        setArgon2MemoryMiB(value);
        updateSecurityControlsUI();
    } catch (error) {
        setStatus(error instanceof Error ? error.message : "Invalid Argon2id memory setting.");
        updateSecurityControlsUI();
    }
}

if (DOM.argonMemoryRange) {
    DOM.argonMemoryRange.addEventListener("input", () => {
        syncArgonMemoryFromInput(DOM.argonMemoryRange.value);
    });
}

if (DOM.argonMemoryInput) {
    DOM.argonMemoryInput.addEventListener("change", () => {
        syncArgonMemoryFromInput(DOM.argonMemoryInput.value);
    });

    DOM.argonMemoryInput.addEventListener("input", () => {
        const value = Number.parseInt(DOM.argonMemoryInput.value, 10);
        if (Number.isFinite(value) && value >= 12 && value <= 256) {
            State.argonMemoryKib = value * 1024;
            if (DOM.argonMemoryRange) DOM.argonMemoryRange.value = String(value);
            if (DOM.argonMemoryValue) DOM.argonMemoryValue.textContent = `${value} MiB`;
        }
    });
}

function syncPbkdf2IterationsFromInput(rawValue) {
    const value = Number(rawValue);
    if (!Number.isSafeInteger(value)) {
        setStatus("PBKDF2 iterations must be a whole number.");
        updateSecurityControlsUI();
        return;
    }
    try {
        setPbkdf2Iterations(value);
        updateSecurityControlsUI();
    } catch (error) {
        setStatus(error instanceof Error ? error.message : "Invalid PBKDF2 iteration count.");
        updateSecurityControlsUI();
    }
}

if (DOM.pbkdf2IterationsRange) {
    DOM.pbkdf2IterationsRange.addEventListener("input", () => {
        syncPbkdf2IterationsFromInput(DOM.pbkdf2IterationsRange.value);
    });
}

if (DOM.pbkdf2IterationsInput) {
    DOM.pbkdf2IterationsInput.addEventListener("change", () => {
        syncPbkdf2IterationsFromInput(DOM.pbkdf2IterationsInput.value);
    });
}

/* ---------- Inbuilt KDF Picker ---------- */

function renderKdfPicker() {
    const value = State.kdf === "pbkdf2" ? "pbkdf2" : "argon2id";
    const label = value === "pbkdf2" ? "PBKDF2" : "Argon2id";

    if (DOM.kdf) {
        DOM.kdf.value = value;
    }

    if (DOM.kdfValue) {
        DOM.kdfValue.textContent = label;
    }

    if (DOM.kdfTrigger) {
        DOM.kdfTrigger.setAttribute("aria-expanded", String(Boolean(DOM.kdfMenu && !DOM.kdfMenu.hidden)));
    }

    if (DOM.kdfOptions) {
        DOM.kdfOptions.forEach(option => {
            const selected = option.dataset.kdf === value;
            option.classList.toggle("is-selected", selected);
            option.setAttribute("aria-selected", String(selected));
        });
    }
}

function setKdfFromPicker(value) {
    State.kdf = value === "pbkdf2" ? "pbkdf2" : "argon2id";
    if (DOM.kdf) {
        DOM.kdf.value = State.kdf;
    }
    renderKdfPicker();
    updateSecurityControlsUI();
    updateActionButton();
}

function closeKdfPicker() {
    if (!DOM.kdfMenu || !DOM.kdfTrigger) return;
    DOM.kdfMenu.hidden = true;
    DOM.kdfTrigger.setAttribute("aria-expanded", "false");
    DOM.kdfPicker?.classList.remove("is-open");
}

function toggleKdfPicker() {
    if (!DOM.kdfMenu || !DOM.kdfTrigger || State.busy) return;
    const willOpen = DOM.kdfMenu.hidden;
    DOM.kdfMenu.hidden = !willOpen;
    DOM.kdfTrigger.setAttribute("aria-expanded", String(willOpen));
    DOM.kdfPicker?.classList.toggle("is-open", willOpen);

    if (willOpen) {
        window.requestAnimationFrame(() => {
            const selected = Array.from(DOM.kdfOptions).find(option => option.dataset.kdf === State.kdf);
            selected?.focus({ preventScroll: true });
        });
    }
}

if (DOM.kdfTrigger && DOM.kdfMenu && DOM.kdfOptions) {
    DOM.kdfTrigger.addEventListener("click", toggleKdfPicker);

    DOM.kdfOptions.forEach(option => {
        option.addEventListener("click", () => {
            setKdfFromPicker(option.dataset.kdf);
            closeKdfPicker();
            DOM.kdfTrigger.focus({ preventScroll: true });
        });
    });

    DOM.kdfTrigger.addEventListener("keydown", event => {
        if (event.key === "ArrowDown" || event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            toggleKdfPicker();
        }
        if (event.key === "Escape") {
            closeKdfPicker();
        }
    });

    DOM.kdfMenu.addEventListener("keydown", event => {
        const options = Array.from(DOM.kdfOptions);
        const currentIndex = Math.max(0, options.findIndex(option => option.dataset.kdf === State.kdf));

        if (event.key === "Escape") {
            event.preventDefault();
            closeKdfPicker();
            DOM.kdfTrigger.focus({ preventScroll: true });
            return;
        }

        if (event.key === "ArrowDown" || event.key === "ArrowUp") {
            event.preventDefault();
            const delta = event.key === "ArrowDown" ? 1 : -1;
            const nextIndex = (currentIndex + delta + options.length) % options.length;
            options[nextIndex].focus({ preventScroll: true });
            return;
        }

        if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            const focused = document.activeElement?.closest(".kdf-picker__option");
            if (focused) {
                setKdfFromPicker(focused.dataset.kdf);
                closeKdfPicker();
                DOM.kdfTrigger.focus({ preventScroll: true });
            }
        }
    });

    document.addEventListener("click", event => {
        if (!DOM.kdfPicker?.contains(event.target)) {
            closeKdfPicker();
        }
    });

    document.addEventListener("keydown", event => {
        if (event.key === "Escape" && DOM.kdfMenu && !DOM.kdfMenu.hidden) {
            closeKdfPicker();
            DOM.kdfTrigger.focus({ preventScroll: true });
        }
    });
}

/* ---------- Mode ---------- */

function setMode(mode) {

    if (

        State.mode === mode

    ) {

        return;

    }

    State.mode = mode;

    if (mode === "decrypt") {

        State.previousEncryptPickerMode = State.pickerMode;
        State.pickerMode = "files";

    }

    else if (State.previousEncryptPickerMode === "folder") {

        State.pickerMode = "folder";

    }

    else {

        State.pickerMode = "files";

    }

    clearFile();

    updateTabs();

    updateActionButton();

    updatePickerButton();

    updatePickerModeUI();

    syncPickerInputMode();

    updatePasswordSection();
    updateArgonMemoryUI();

    clearOutput();

    resetProgress();

    setStatus(

        mode === "encrypt"

            ? "Encryption mode selected."

            : "Decryption mode selected."

    );

}

/* ---------- Tabs ---------- */

function updateTabs() {

    DOM.encryptTab.classList.toggle(

        "active",

        State.mode === "encrypt"

    );

    DOM.decryptTab.classList.toggle(

        "active",

        State.mode === "decrypt"

    );

}

/* ---------- Action Button ---------- */

function updateActionButton() {

    DOM.actionButton.textContent =

        State.mode === "encrypt"

            ? "Encrypt Files"

            : "Decrypt File";

}

function updatePickerButton() {

    if (State.mode === "encrypt") {

        DOM.chooseFile.textContent =

            State.pickerMode === "folder"

                ? "Select Folder"

                : "Select Files";

    }

    else {

        DOM.chooseFile.textContent = "Select Encrypted File";

    }

}

/* ---------- Confirm Password ---------- */

function updatePasswordSection() {

    const label =

        DOM.confirmPassword
            .previousElementSibling;

    const visible =

        State.mode === "encrypt";

    label.hidden = !visible;

    DOM.confirmPassword.hidden = !visible;

    if (!visible) {

        DOM.confirmPassword.value = "";

        DOM.confirmPassword.style.borderColor = "";

    }

}

/* ---------- Reset ---------- */

function resetUI() {

    DOM.password.value = "";

    DOM.confirmPassword.value = "";

    DOM.showPassword.checked = false;

    DOM.password.type = "password";

    DOM.confirmPassword.type = "password";

    DOM.strength.textContent =

        "Strength: —";

    DOM.strength.style.color =

        "";

    DOM.selectedFile.textContent =

        "No files selected";

    updatePickerButton();

    updatePickerModeUI();

    syncPickerInputMode();

    clearOutput();

    resetProgress();

    updateTabs();

    updateActionButton();

    updatePasswordSection();
    updateArgonMemoryUI();

    setStatus("Waiting...");

}

/* ---------- Startup ---------- */

resetUI();
renderKdfPicker();


/* ---------- First-open intro ---------- */

(() => {

    const overlay = document.getElementById("introOverlay");
    const gotItButton = document.getElementById("introGotIt");

    if (!overlay || !gotItButton) {
        return;
    }

    const storageKey = "sfe3-intro-seen";
    const returningFromAbout = new URLSearchParams(window.location.search).get("returning") === "about";

    let alreadySeen = false;

    try {
        alreadySeen = sessionStorage.getItem(storageKey) === "1";
    }
    catch (_) {
        alreadySeen = false;
    }

    if (returningFromAbout) {
        alreadySeen = true;
        try {
            sessionStorage.setItem(storageKey, "1");
        }
        catch (_) {
            /* Private browsing environments may block sessionStorage. */
        }

        if (window.history && window.history.replaceState) {
            try {
                window.history.replaceState({}, document.title, window.location.pathname);
            }
            catch (_) {
                /* Keep the query string when history APIs are unavailable. */
            }
        }
    }

    function closeIntro() {

        try {
            sessionStorage.setItem(storageKey, "1");
        }
        catch (_) {
            /* The UI still works when storage is unavailable. */
        }

        overlay.classList.remove("is-visible");
        overlay.setAttribute("aria-hidden", "true");
        document.body.classList.remove("intro-open");

        window.setTimeout(() => {
            overlay.hidden = true;
        }, 320);
    }

    if (alreadySeen) {
        overlay.hidden = true;
        return;
    }

    overlay.hidden = false;
    overlay.classList.add("is-visible");
    overlay.setAttribute("aria-hidden", "false");
    document.body.classList.add("intro-open");

    window.setTimeout(() => {
        gotItButton.focus({ preventScroll: true });
    }, 120);

    gotItButton.addEventListener("click", closeIntro);

    document.addEventListener("keydown", event => {
        if (event.key === "Escape" && overlay.classList.contains("is-visible")) {
            closeIntro();
        }
    });

})();
