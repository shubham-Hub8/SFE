/* ==========================================
   Simple File Encryptor
   Download Management
========================================== */

"use strict";

/* ---------- Download ---------- */

DOM.downloadButton.addEventListener(

    "click",

    downloadOutput

);

/* ---------- Save File ---------- */

function downloadOutput() {

    const blob = getOutputBlob();

    if (!blob) {

        setStatus(

            "There is no file to download."

        );

        return;

    }

    try {

        const url =

            URL.createObjectURL(blob);

        const link =

            document.createElement("a");

        link.href = url;

        link.download =

            State.outputName;

        document.body.appendChild(link);

        link.click();

        link.remove();

        setTimeout(() => {

            URL.revokeObjectURL(url);

        }, 100);

        setStatus(

            "Download completed."

        );

    }

    catch (error) {

        console.error(error);

        setStatus(

            "Download failed."

        );

    }

}

/* ---------- Download State ---------- */

function hasDownload() {

    return getOutputBlob() !== null;

}

function clearDownload() {

    clearOutput();

}