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

    if (paste.visibility === 2) {
        const password = prompt("Enter the password");
        try {
            const decrypted = await decryptAES(content, password);
            blur2.dataset.decrypted = "true";
            addContent(decrypted, paste.syntax);
        } catch (error) {
            alert("Failed to decrypt, invalid password, or invalid data.");
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
    document.getElementById("paste-date").innerText = convertUnixToLocal(paste.created);
    document.getElementById("paste-syntax").innerText = paste.syntax === "none" ? "" : paste.syntax || "";
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