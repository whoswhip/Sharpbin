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
                            <p id="archive-date" title="${formatDate(paste.created)}">${formatDate(paste.created, true)}</p>
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

function getRelativeTime(date) {
    const now = new Date();
    const diff = now - date;
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    if (isNaN(date.getTime())) return '';
    if (seconds < 60) return 'just now';
    if (minutes < 60) return `${minutes} min ago`;
    if (hours < 24) return `${hours} hr${hours > 1 ? 's' : ''} ago`;
    if (days < 7) return `${days} day${days > 1 ? 's' : ''} ago`;
    return date.toLocaleDateString();
}


function formatDate(unix, relative = false) {
    if (typeof unix !== 'number' || isNaN(unix)) {
        return 'Invalid date';
    }
    const date = new Date(unix * 1000);
    if (isNaN(date.getTime())) {
        return 'Invalid date';
    }
    if (relative) {
        return getRelativeTime(date);
    }
    return date.toLocaleDateString([], { year: 'numeric', month: '2-digit', day: '2-digit' });
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