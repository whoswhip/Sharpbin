pages = 0;

document.addEventListener('DOMContentLoaded', async () => {
    var queries = new URLSearchParams(window.location.search);
    var page = queries.get("page");
    var limit = queries.get("limit");

    if (parseInt(page).isNaN) {
        page = 0;
    }

    var archiveList = document.getElementById("archives");
    var archiveListHTML = "";
    var pagesElement = document.getElementById("paste-pages");

    if (page == null || page < 0) {
        page = 0;
    }
    if (limit == null || limit < 1 || limit > 25) {
        limit = 25;
    }

    var archiveData = await getPastes(page, limit);

    var pastes = archiveData.pastes;
    pages = archiveData.pages;
    pagesElement.innerText = `${parseInt(page) + 1}/${pages + 1}`;


    pastes.forEach(paste => {
        var title = paste.title.length > 30 ? paste.title.substring(0, 30) + '...' : paste.title;
        archiveListHTML += `
            <li>
                <a href="/${paste.id}">
                    <p id="archive-title" title="${paste.title}">${title}</p>
                    <p id="archive-date">${formatDate(paste.created)}</p>
                    <p id="archive-syntax">${paste.syntax}</p>
                </a>
            </li>
        `;
    });

    archiveList.innerHTML = archiveListHTML;
});

async function getPastes(page, limit) {
    const response = await fetch(`/api/pastes/archive?page=${page}&limit=${limit}`);
    const data = await response.json();
    return data;
}

function formatDate(unix) {
    if (typeof unix !== 'number' || isNaN(unix)) {
        return 'Invalid date';
    }
    var nowunix = Math.floor(Date.now() / 1000);
    var diff = nowunix - unix;

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
    var queries = new URLSearchParams(window.location.search);
    var page = queries.get("page");
    var limit = queries.get("limit");

    if (page == null || page < 0) {
        page = 0;
    }
    if (limit == null || limit < 1 || limit > 25) {
        limit = 25;
    }

    if (page + 1 > pages) {
        return;
    }

    page++;
    window.location.href = `/archive?page=${page}&limit=${limit}`;
}

function previousPage() {
    var queries = new URLSearchParams(window.location.search);
    var page = queries.get("page");
    var limit = queries.get("limit");

    if (page == null || page < 0) {
        page = 0;
    }
    if (limit == null || limit < 1 || limit > 25) {
        limit = 25;
    }

    if (page < pages) {
        return;
    }

    page--;
    window.location.href = `/archive?page=${page}&limit=${limit}`;
} 