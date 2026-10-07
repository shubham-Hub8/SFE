/* ==========================================
   Simple File Encryptor
   App Controller
========================================== */

"use strict";

/* ---------- Action ---------- */

DOM.actionButton.addEventListener(

    "click",

    processAction

);

/* ---------- Process ---------- */

async function processAction() {

    if (State.busy) {
        return;
    }

    if (!hasFiles()) {

        return;

    }

    if (!validatePassword()) {

        return;

    }

    const password = getPassword();

    await processFiles(State.selectedFiles, password);

}

/* ---------- Keyboard Shortcut ---------- */

document.addEventListener(

    "keydown",

    event => {

        if (

            event.key === "Enter" &&

            document.activeElement !==

            DOM.actionButton

        ) {

            event.preventDefault();

            processAction();

        }

    }

);

/* ---------- Startup ---------- */

window.addEventListener(

    "load",

    () => {

        setStatus(

            "Waiting..."

        );

        resetProgress();

        disableDownload();

        updateTabs();

        updateActionButton();

        updatePickerButton();

        updatePasswordSection();

    }

);
