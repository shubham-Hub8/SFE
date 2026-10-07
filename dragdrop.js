/* ==========================================
   Simple File Encryptor
   Drag and Drop
========================================== */

"use strict";

let dragDepth = 0;

if (DOM.dropZone) {

    DOM.dropZone.addEventListener("dragenter", event => {

        event.preventDefault();
        dragDepth += 1;
        DOM.dropZone.classList.add("drag-over");

    });

    DOM.dropZone.addEventListener("dragover", event => {

        event.preventDefault();
        DOM.dropZone.classList.add("drag-over");

    });

    DOM.dropZone.addEventListener("dragleave", event => {

        event.preventDefault();
        dragDepth = Math.max(0, dragDepth - 1);

        if (dragDepth === 0) {
            DOM.dropZone.classList.remove("drag-over");
        }

    });

    DOM.dropZone.addEventListener("drop", async event => {

        event.preventDefault();
        dragDepth = 0;
        DOM.dropZone.classList.remove("drag-over");

        const files = Array.from(event.dataTransfer?.files || []);

        if (files.length > 0) {
            loadFiles(files);
            return;
        }

        setStatus("Drop files here to select them.");
    });

}
