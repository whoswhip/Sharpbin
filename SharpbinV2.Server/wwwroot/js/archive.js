let pages = 0;
let currentPage = 0;

document.addEventListener('DOMContentLoaded', async () => {
    const queries = new URLSearchParams(window.location.search);
    let page = parseInt(queries.get("page"));
    let limit = parseInt(queries.get("limit"));

    if (isNaN(page)) {
        page = 0;
    }

    if (page < 0) {
        page = 0;
    }
    
    if (isNaN(limit) || limit < 1 || limit > 25) {
        limit = 25;
    }

    currentPage = page;

    const archiveList = document.getElementById("archives");
    const pagesElement = document.getElementById("paste-pages");
    const previousButton = document.getElementById("previous-button");
    const nextButton = document.getElementById("next-button");
    
    try {
        archiveList.innerHTML = '<div class="loading-spinner"><div></div><div></div><div></div></div>';
        
        const archiveData = await getPastes(page, limit);
        
        const pastes = archiveData.pastes;
        pages = archiveData.pages;
        
        pagesElement.innerText = `${parseInt(page) + 1}/${pages}`;
        
        previousButton.disabled = page <= 0;
        nextButton.disabled = page + 1 >= pages;

        if (pastes.length === 0) {
            archiveList.innerHTML = '<div class="no-pastes">No pastes found</div>';
            return;
        }

        let archiveListHTML = "";
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

        archiveList.innerHTML = archiveListHTML;
    } catch (error) {
        console.error('Error fetching pastes:', error);
        archiveList.innerHTML = '<div class="error-message">Failed to load pastes. Please try again later.</div>';
    }
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
    const queries = new URLSearchParams(window.location.search);
    let page = parseInt(queries.get("page"));
    let limit = parseInt(queries.get("limit"));

    if (isNaN(page) || page < 0) {
        page = 0;
    }
    
    if (isNaN(limit) || limit < 1 || limit > 25) {
        limit = 25;
    }

    if (page + 1 > pages) {
        return;
    }

    page++;
    window.location.href = `/archive?page=${page}&limit=${limit}`;
}

function previousPage() {
    const queries = new URLSearchParams(window.location.search);
    let page = parseInt(queries.get("page"));
    let limit = parseInt(queries.get("limit"));

    if (isNaN(page) || page < 0) {
        page = 0;
    }
    
    if (isNaN(limit) || limit < 1 || limit > 25) {
        limit = 25;
    }

    if (page <= 0) {
        return;
    }

    page--;
    window.location.href = `/archive?page=${page}&limit=${limit}`;
}