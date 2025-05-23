let currentPage = 0;
const PAGE_SIZE = 25;
let totalPastes = 0;
let lastPage = false;

async function loadUserPastes(userData, page = 0) {
    const pastesRes = await fetch(`/api/users/${userData.uuid}/pastes?limit=${PAGE_SIZE}&page=${page}`);
    const data = await pastesRes.json();
    let pastes = [];
    if (pastesRes.ok) {
        pastes = data.pastes || [];
        totalPastes = data.total || 0;
        lastPage = pastes.length < PAGE_SIZE;
    }
    const list = document.getElementById("user-pastes-list");
    list.innerHTML = "";
    if (!pastes.length) {
        list.innerHTML = "<p style='color:var(--neutral-400)'>No pastes found.</p>";
        return;
    }
    for (const paste of pastes) {
        const li = document.createElement("li");
        const link = document.createElement("a");
        link.href = `/${paste.id}`;
        link.innerHTML = `
            <p>${paste.title}</p>
            <p>${new Date(paste.created * 1000).toLocaleDateString()}</p>
            <p>${paste.syntax || "Plaintext"}</p>
        `;
        li.appendChild(link);
        list.appendChild(li);
    }
    document.getElementById("paste-pages").innerText = `${page + 1}/${data.pages + 1}`;
    document.getElementById("next-button").disabled = page === 0;
    document.getElementById("previous-button").disabled = lastPage;
}

document.addEventListener("DOMContentLoaded", async function () {
    const username = window.location.pathname.split("/")[2]
    if (!username) {
        window.location.href = "/error?code=404&message=User not found";
        return;
    }
    const userInfoRes = await fetch(`/api/users/${username}`);
    if (!userInfoRes.ok) {
        document.getElementById("user-name").innerText = "User not found";
        document.getElementById("user-pastes-list").innerHTML = "<p style='color:var(--neutral-400)'>No user data.</p>";
        return;
    }
    const user = await userInfoRes.json();
    const userData = user.user ? user.user : user;
    document.title = `${userData.username} - Sharpbin`;
    document.getElementById("user-name").innerText = userData.username;
    document.getElementById("user-uuid").innerText = userData.uuid;

    await loadUserPastes(userData, 0);
    currentPage = 0;
    document.getElementById("previous-button").onclick = async function () {
        if (currentPage > 0) {
            currentPage--;
            await loadUserPastes(userData, currentPage);
        }
    };
    document.getElementById("next-button").onclick = async function () {
        if (!lastPage) {
            currentPage++;
            await loadUserPastes(userData, currentPage);
        }
    };
});

function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}
