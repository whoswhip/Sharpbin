const visibility = [{ id: 0, name: "Public" }, { id: 1, name: "Unlisted" }, { id: 2, name: "Private" }];

document.addEventListener("DOMContentLoaded", async function () {
    const id = window.location.pathname.split("/")[1];
    const content = await (await fetch(`/api/pastes/${id}`)).text();
    const info = await (await fetch(`/api/pastes/${id}/info`)).json();
    const paste = info.paste;
    const blur = document.createElement("div");
    blur.id = "blur";
    blur.dataset.decrypted = "false";
    document.body.appendChild(blur);
    const blur2 = document.getElementById("blur");

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
    document.getElementById("copy-button").addEventListener("click", function () {
        navigator.clipboard.writeText(window.location.href);
    });
    document.getElementById("download-button").addEventListener("click", function () {
        if (paste.visibility === 2) {
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
        }
        else {
            const blob = new Blob([document.getElementById("paste-content").innerText], { type: "text/plain" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `${paste.title}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
    });
    document.getElementById("raw-button").addEventListener("click", function () {
        window.location.href = `/raw/${paste.id}`;
    });

}

function addContent(content, syntax) {
    if (syntax === "none" || syntax === "" || syntax === null) {
        document.getElementById("paste-content").innerText = content;
    } else {
        var code = document.createElement("code");
        code.innerText = content;
        var pre = document.getElementById("paste-content");
        pre.innerText = "";
        pre.appendChild(code);
        pre.removeAttribute("id");
        code.id = "paste-content";
        code.classList.add("language-" + syntax);
        hljs.highlightElement(code);
    }
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