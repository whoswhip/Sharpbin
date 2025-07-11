const visibility = [{ id: 0, name: "Public" }, { id: 1, name: "Unlisted" }, { id: 2, name: "Private" }];

let paste = null;

const ELEMENTS = {
    get: (id) => document.getElementById(id),
    create: (tag, props = {}) => {
        const element = document.createElement(tag);
        Object.assign(element, props);
        return element;
    },
    setText: (id, text) => ELEMENTS.get(id).innerText = text,
    setStyle: (id, styles) => Object.assign(ELEMENTS.get(id).style, styles),
    hide: (id) => ELEMENTS.get(id).style.display = "none",
    show: (id, display = "inline-block") => ELEMENTS.get(id).style.display = display
};

document.addEventListener("DOMContentLoaded", async function () {
    const id = window.location.pathname.split("/")[1];
    const [content, info] = await Promise.all([
        fetch(`/api/pastes/${id}`).then(response => response.text()),
        fetch(`/api/pastes/${id}/info`).then(response => response.json())
    ]);

    const blur = ELEMENTS.create("div", { id: "blur" });
    blur.dataset.decrypted = "false";
    document.body.appendChild(blur);

    paste = info.paste;
    const finalContent = paste.visibility === 2 ? await handlePrivatePaste(content) : content;
    
    if (finalContent) {
        blur.dataset.decrypted = "true";
        addContent(finalContent, paste.syntax);
    }
    
    document.title = `${paste.title} - Sharpbin`;
    addInfo(paste);
});

async function handlePrivatePaste(content) {
    try {
        const modalController = await Modal.prompt(
            "Enter the password to view this paste:",
            "",
            "Private Paste",
            "password",
            { keepOpen: true }
        );

        while (true) {
            try {
                const password = await modalController.update("Enter the password to view this paste:");
                
                if (password === null) {
                    modalController.close();
                    return null;
                }

                const decrypted = await decryptAES(content, password);
                modalController.close();
                return decrypted;
            } catch (error) {
                showNotification("Incorrect password. Please try again.", "error", 3000);
            }
        }
    } catch (error) {
        console.error('Error in handlePrivatePaste:', error);
        return null;
    }
}

function addInfo(paste) {
    const isAnonymous = paste.username === "Anonymous";
    
    ELEMENTS.setText("paste-title", paste.title);
    ELEMENTS.setText("paste-date", convertUnixToLocal(paste.created));
    ELEMENTS.setText("paste-syntax", paste.syntax);
    ELEMENTS.setText("paste-size", paste.size === 0 ? "" : formatSize(paste.size));
    
    setupSizeTooltip(paste);
    setupAuthorLink(paste, isAnonymous);
    
    ELEMENTS.setText("paste-views", paste.views);
    ELEMENTS.hide("info-throbber");
    
    setupActionButtons(paste);
    setupDeleteButton(paste);
}

function setupSizeTooltip(paste) {
    if (paste.size !== paste.trueSize && paste.trueSize) {
        const sizeElem = ELEMENTS.get("paste-size");
        sizeElem.classList.add("has-true-size-tooltip");
        const tooltip = ELEMENTS.create("div", {
            className: "true-size-tooltip",
            innerText: `True size: ${formatSize(paste.trueSize)}`
        });
        sizeElem.appendChild(tooltip);
        sizeElem.onmouseenter = () => tooltip.style.opacity = 1;
        sizeElem.onmouseleave = () => tooltip.style.opacity = 0;
    }
}

function setupAuthorLink(paste, isAnonymous) {
    const authorLink = ELEMENTS.get("author-link");
    ELEMENTS.setText("paste-author", paste.username);
    
    if (isAnonymous) {
        Object.assign(authorLink, {
            innerText: "Anonymous",
            href: ""
        });
        Object.assign(authorLink.style, {
            pointerEvents: "none",
            textDecoration: "none"
        });
    } else {
        authorLink.href = `/u/${paste.username}`;
    }
}

function setupActionButtons(paste) {
    const actions = [
        {
            id: "copy-button",
            action: () => {
                const content = ELEMENTS.get("paste-content").innerText;
                navigator.clipboard.writeText(content);
                showNotification("Paste copied to clipboard!", "info", 2000);
            }
        },
        {
            id: "download-button", 
            action: () => downloadPaste(paste.title)
        },
        {
            id: "raw-button",
            action: () => window.location.href = `/raw/${paste.id}`
        }
    ];
    
    actions.forEach(({ id, action }) => {
        ELEMENTS.get(id).addEventListener("click", action);
    });
}

function downloadPaste(title) {
    const content = ELEMENTS.get("paste-content").innerText;
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = ELEMENTS.create("a", {
        href: url,
        download: `${title}.txt`
    });
    
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showNotification("Paste downloaded!", "info", 2000);
}

function setupDeleteButton(paste) {
    waitForAuthData().then(() => {
        if (authData.user.uuid === paste.authorUUID || authData.user.type === 255) {
            ELEMENTS.show("delete-button");
            ELEMENTS.get("delete-button").addEventListener("click", async () => {
                const confirmed = await Modal.confirm(
                    "Are you sure you want to delete this paste? This action cannot be undone.",
                    "Delete Paste",
                    "danger"
                );
                if (confirmed) {
                    deletePaste(paste.id);
                }
            });
        }
    });
}

function deletePaste(pasteId) {
    fetch(`/api/pastes/${pasteId}`, { method: "DELETE" })
        .then(response => {
            const message = response.ok ? "Paste deleted!" : "Failed to delete paste.";
            const type = response.ok ? "info" : "error";
            showNotification(message, type, 2000);
            if (response.ok) window.location.href = "/";
        });
}

function waitForAuthData() {
    return new Promise((resolve) => {
        const checkAuth = setInterval(() => {
            if (authData) {
                clearInterval(checkAuth);
                resolve();
            }
        }, 100);
    });
}

function addContent(content, syntax) {
    const code = ELEMENTS.create("code", { 
        textContent: content, 
        id: "paste-content" 
    });
    const pre = ELEMENTS.get("paste-content");
    
    pre.innerText = "";
    pre.appendChild(code);
    pre.removeAttribute("id");
    
    const isPlaintext = ["plaintext", "none", "", null].includes(syntax);
    code.classList.add(`language-${isPlaintext ? "none" : syntax}`);
    
    if (!isPlaintext) {
        hljs.highlightElement(code);
        code.style.padding = "0px";
    }
    
    hljs.lineNumbersBlock(code);
    ELEMENTS.hide("content-throbber");
}

async function decryptAES(content, password) {
    const rawData = atob(content);
    const rawDataArray = Uint8Array.from(rawData, c => c.charCodeAt(0));
    const [salt, iv, ciphertext] = [
        rawDataArray.slice(0, 16),
        rawDataArray.slice(16, 28),
        rawDataArray.slice(28)
    ];

    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    
    const key = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        ciphertext
    );
    
    return new TextDecoder().decode(decrypted);
}

const convertUnixToLocal = (unix) => new Date(unix * 1000).toLocaleString();

const formatSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
};