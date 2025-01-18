document.addEventListener("DOMContentLoaded", async function () {
    var visibility = document.getElementById("visibility");
    visibility.value = "0";
});


document.getElementById("create-form").addEventListener("submit", async function (event) {
    event.preventDefault();
    var title = document.getElementById("title").value;
    var content = document.getElementById("content").value;

    var visibility = document.getElementById("visibility").value;
    var password = document.getElementById("password").value;
    var syntax = document.getElementById("syntax").value;

    if (visibility === "2" && password !== "" && password.length >= 6) {
        content = await encryptAES(content, password);
        console.log(content);
    }
    else if (visibility === "2") {
        alert("Password must be at least 6 characters long");
        return;
    }

    fetch(`/api/pastes/create?title=${title}&visibility=${visibility}&syntax=${syntax}`, {
        method: "POST",
        body: content
    })
        .then(response => response.json())
        .then(data => {
            const paste = data.paste;
            window.location.href = `/${paste.id}`;
        });
});

function changeVisibility() {
    var visibility = document.getElementById("visibility").value;
    var password = document.getElementById("password");
    if (visibility === "2") {
        password.style.display = "block";
    } else {
        password.style.display = "none";
    }
}

async function encryptAES(content, password) {
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
        ["encrypt"]
    );
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedContent = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        enc.encode(content)
    );
    const encryptedArray = new Uint8Array(encryptedContent);
    const encryptedString = btoa(String.fromCharCode(...iv) + String.fromCharCode(...encryptedArray));
    return encryptedString;
}
