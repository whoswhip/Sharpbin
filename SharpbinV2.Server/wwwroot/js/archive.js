let pages = 0;
let currentPage = 0;
let limit = 25;

async function renderArchive(page, limit) {
    const archiveList = document.getElementById("archives");
    const pagesElement = document.getElementById("paste-pages");
    const previousButton = document.getElementById("previous-button");
    const nextButton = document.getElementById("next-button");

    let loadingOverlay = document.getElementById("archive-loading-overlay");
    if (!loadingOverlay) {
        loadingOverlay = document.createElement("div");
        loadingOverlay.id = "archive-loading-overlay";
        loadingOverlay.innerHTML = '<div class="loading-spinner"><div></div><div></div><div></div></div>';
        loadingOverlay.style.position = "absolute";
        loadingOverlay.style.top = 0;
        loadingOverlay.style.left = 0;
        loadingOverlay.style.width = "100%";
        loadingOverlay.style.height = "100%";
        loadingOverlay.style.display = "flex";
        loadingOverlay.style.justifyContent = "center";
        loadingOverlay.style.alignItems = "center";
        loadingOverlay.style.background = "transparent";
        loadingOverlay.style.zIndex = 10;
        archiveList.parentElement.style.position = "relative";
        archiveList.parentElement.appendChild(loadingOverlay);
    } else {
        loadingOverlay.style.display = "flex";
    }

    try {
        const archiveData = await getPastes(page, limit);
        const pastes = archiveData.pastes;
        pages = archiveData.pages;
        currentPage = page;

        pagesElement.innerText = `${page + 1}/${pages}`;
        previousButton.disabled = page <= 0;
        nextButton.disabled = page + 1 >= pages;

        let archiveListHTML = "";
        if (pastes.length === 0) {
            archiveListHTML = '<div class="no-pastes">No pastes found</div>';
        } else {
            pastes.forEach(paste => {
                const title = paste.title.length > 30 ? paste.title.substring(0, 30) + '...' : paste.title;
                archiveListHTML += `
                    <li>
                        <a href="/${paste.id}">
                            <p id="archive-title" title="${paste.title}">${title}</p>
                            <p id="archive-date">${formatDate(paste.created)}</p>
                            <p id="archive-syntax">${paste.syntax || 'Plain Text'}</p>
                        </a>
                    </li>
                `;
            });
        }
        archiveList.innerHTML = archiveListHTML;
    } catch (error) {
        console.error('Error fetching pastes:', error);
        archiveList.innerHTML = '<div class="error-message">Failed to load pastes. Please try again later.</div>';
    } finally {
        if (loadingOverlay) loadingOverlay.style.display = "none";
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    const queries = new URLSearchParams(window.location.search);
    let page = parseInt(queries.get("page"));
    limit = parseInt(queries.get("limit"));

    if (isNaN(page) || page < 0) page = 0;
    if (isNaN(limit) || limit < 1 || limit > 25) limit = 25;

    await renderArchive(page, limit);

    document.getElementById("previous-button").addEventListener("click", previousPage);
    document.getElementById("next-button").addEventListener("click", nextPage);
});

async function getPastes(page, limit) {
    const response = await fetch(`/api/pastes/archive?page=${page}&limit=${limit}`);
    if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
    }
    const data = await response.json();
    return data;
}

function formatDate(unix) {
    if (typeof unix !== 'number' || isNaN(unix)) {
        return 'Invalid date';
    }
    const nowunix = Math.floor(Date.now() / 1000);
    const diff = nowunix - unix;

    if (diff < 60) {
        return `${diff} second${diff !== 1 ? 's' : ''} ago`;
    } else if (diff < 3600) {
        const minutes = Math.floor(diff / 60);
        return `${minutes} minute${minutes !== 1 ? 's' : ''} ago`;
    } else if (diff < 86400) {
        const hours = Math.floor(diff / 3600);
        return `${hours} hour${hours !== 1 ? 's' : ''} ago`;
    } else {
        const days = Math.floor(diff / 86400);
        return `${days} day${days !== 1 ? 's' : ''} ago`;
    }
}

function nextPage() {
    if (currentPage + 1 >= pages) return;
    currentPage++;
    updateUrlAndRender();
}

function previousPage() {
    if (currentPage <= 0) return;
    currentPage--;
    updateUrlAndRender();
}

function updateUrlAndRender() {
    const url = `/archive?page=${currentPage}&limit=${limit}`;
    window.history.pushState({page: currentPage, limit: limit}, '', url);
    renderArchive(currentPage, limit);
}

window.onpopstate = function(event) {
    if (event.state) {
        currentPage = event.state.page;
        limit = event.state.limit;
        renderArchive(currentPage, limit);
    }
};