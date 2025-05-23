const visibility = [{ id: 0, name: "Public" }, { id: 1, name: "Unlisted" }, { id: 2, name: "Private" }];

document.addEventListener("DOMContentLoaded", async function () {
    const id = window.location.pathname.split("/")[1];
    const contentPromise = fetch(`/api/pastes/${id}`).then(response => response.text());
    const infoPromise = fetch(`/api/pastes/${id}/info`).then(response => response.json());

    const blur = document.createElement("div");
    blur.id = "blur";
    blur.dataset.decrypted = "false";
    document.body.appendChild(blur);
    const blur2 = document.getElementById("blur");

    const [content, info] = await Promise.all([contentPromise, infoPromise]);
    const paste = info.paste;

    function showPasswordModal(errorMsg = "") {
        return new Promise((resolve, reject) => {
            const oldModal = document.getElementById("password-modal-bg");
            if (oldModal) oldModal.remove();

            const modalBg = document.createElement("div");
            modalBg.id = "password-modal-bg";

            const modal = document.createElement("div");
            modal.id = "password-modal";

            const title = document.createElement("div");
            title.innerText = "Private Paste";
            title.className = "modal-title";

            const label = document.createElement("label");
            label.innerText = "Enter the password to view this paste:";
            label.htmlFor = "password-input";

            const input = document.createElement("input");
            input.type = "password";
            input.id = "password-input";
            input.autocomplete = "current-password";

            if (errorMsg) {
                showNotification(errorMsg, "error", 3000);
            }

            const btnRow = document.createElement("div");
            btnRow.className = "modal-btn-row";

            const okBtn = document.createElement("button");
            okBtn.innerText = "Unlock";

            const cancelBtn = document.createElement("button");
            cancelBtn.innerText = "Cancel";

            btnRow.appendChild(cancelBtn);
            btnRow.appendChild(okBtn);

            modal.appendChild(title);
            modal.appendChild(label);
            modal.appendChild(input);
            modal.appendChild(btnRow);
            modalBg.appendChild(modal);
            document.body.appendChild(modalBg);

            input.focus();

            function cleanup() {
                if (modalBg.parentNode) modalBg.parentNode.removeChild(modalBg);
            }

            okBtn.onclick = () => {
                resolve(input.value);
            };
            cancelBtn.onclick = () => {
                cleanup();
                reject(new Error("User cancelled"));
            };
            input.addEventListener("keydown", e => {
                if (e.key === "Enter") {
                    okBtn.click();
                } else if (e.key === "Escape") {
                    cancelBtn.click();
                }
            });
            modalBg.addEventListener("click", e => {
                if (e.target === modalBg) {
                    cancelBtn.click();
                }
            });
        });
    }

    if (paste.visibility === 2) {
        let success = false;
        let lastError = "";
        while (!success) {
            try {
                const password = await showPasswordModal(lastError);
                const decrypted = await decryptAES(content, password);
                blur2.dataset.decrypted = "true";
                addContent(decrypted, paste.syntax);
                document.getElementById("password-modal-bg")?.remove();
                success = true;
            } catch (error) {
                if (error.message === "User cancelled") {
                    document.getElementById("password-modal-bg")?.remove();
                    break;
                }
                lastError = "Failed to decrypt, invalid password, or invalid data.";
            }
        }
    } else {
        blur2.dataset.decrypted = "true";
        addContent(content, paste.syntax);
    }
    document.title = `${paste.title} - Sharpbin`;
    addInfo(paste);
});

function addInfo(paste) {
    document.getElementById("paste-title").innerText = paste.title;
    document.getElementById("paste-date").innerText = `${convertUnixToLocal(paste.created)}`;
    document.getElementById("paste-syntax").innerText = paste.syntax;
    document.getElementById("paste-size").innerText = paste.size === 0 ? "" : formatSize(paste.size);
    if (paste.size !== paste.trueSize && paste.trueSize) {
        const sizeElem = document.getElementById("paste-size");
        sizeElem.classList.add("has-true-size-tooltip");
        let tooltip = document.createElement("div");
        tooltip.className = "true-size-tooltip";
        tooltip.innerText = `True size: ${formatSize(paste.trueSize)}`;
        sizeElem.appendChild(tooltip);
        sizeElem.onmouseenter = () => { tooltip.style.opacity = 1; };
        sizeElem.onmouseleave = () => { tooltip.style.opacity = 0; };
    }
    document.getElementById("paste-author").innerText = paste.username;
    document.getElementById("author-link").href = paste.username === "Anonymous" ? "" : `/u/${paste.username}`;
    if (paste.username === "Anonymous") {
        document.getElementById("author-link").innerText = "Anonymous";
        document.getElementById("author-link").href = "";
        document.getElementById("author-link").style.pointerEvents = "none";
        document.getElementById("author-link").style.cursor = "not-allowed";
        document.getElementById("author-link").style.color = "var(--text-color)";
        document.getElementById("author-link").style.textDecoration = "none";
    }
    document.getElementById("paste-views").innerText = paste.views;
    document.getElementById("info-throbber").style.display = "none";
    document.getElementById("copy-button").addEventListener("click", function () {
        navigator.clipboard.writeText(window.location.href);
        showNotification("Paste copied to clipboard!", "info", 2000);
    });
    document.getElementById("download-button").addEventListener("click", function () {
        const content = document.getElementById("paste-content").innerText;
        const blob = new Blob([content], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${paste.title}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showNotification("Paste downloaded!", "info", 2000);
    });
    document.getElementById("raw-button").addEventListener("click", function () {
        window.location.href = `/raw/${paste.id}`;
    });
}

function addContent(content, syntax) {
    var code = document.createElement("code");
    code.textContent = content;
    var pre = document.getElementById("paste-content");
    pre.innerText = "";
    pre.appendChild(code);
    pre.removeAttribute("id");
    code.id = "paste-content";
    code.classList.add("language-" + syntax === "plaintext" ? "none" : syntax);
    if (syntax !== "plaintext" && syntax !== "none" && syntax !== "" && syntax !== null) {
        hljs.highlightElement(code);
        document.getElementById("paste-content").style.padding = "0px"
    }
    hljs.lineNumbersBlock(code);
    document.getElementById("content-throbber").style.display = "none";
}

async function decryptAES(content, password) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    const key = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: enc.encode("salt"),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
    );
    const rawData = atob(content);
    const rawDataArray = Uint8Array.from(rawData, c => c.charCodeAt(0));
    const iv = rawDataArray.slice(0, 12);
    const ciphertext = rawDataArray.slice(12);
    const decrypted = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        ciphertext
    );
    return new TextDecoder().decode(decrypted);
}

function convertUnixToLocal(unix) {
    return new Date(unix * 1000).toLocaleString();
}

function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}