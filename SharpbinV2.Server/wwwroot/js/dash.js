let currentPage = 1;
let totalPages = 1;
let pastesPerPage = 10;
let userPastes = [];


document.addEventListener('DOMContentLoaded', function () {
    waitForAuthData().then(data => {
        if (data.success === false) {
            window.location.href = '/login';
        } else {
            updateAccountInfo(data.user);
            fetchUserPastes();
        }
    }).catch(error => {
        console.error('Error waiting for auth data:', error);
        window.location.href = '/login';
    });
});

function waitForAuthData() {
    return new Promise(resolve => {
        const interval = setInterval(() => {
            if (authData) {
                clearInterval(interval);
                resolve(authData);
            }
        }, 100);
    });
}

function updateAccountInfo(data) {
    document.getElementById('account-username').textContent = `Username: ${data.username}`;
    document.getElementById('account-email').textContent = `Email: ${data.email || 'Not provided'}`;


    if (data.displayname) {
        const usernameElement = document.getElementById('account-header');
        usernameElement.textContent = data.displayname;
    }


    const createdDate = new Date(data.created * 1000);
    const lastLoginDate = new Date(data.lastLogin * 1000);

    document.getElementById('account-joindate').textContent = `Joined: ${formatDate(createdDate)}`;
    document.getElementById('account-lastlogin').textContent = `Last Login: ${formatDate(lastLoginDate)}`;
}


function formatDate(date, minutes = false) {
    if (isNaN(date.getTime())) {
        return 'Never';
    }

    if (minutes) 
    {
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { minute: '2-digit', hour: '2-digit' });
    } else {
        return date.toLocaleDateString([], { year: 'numeric', month: '2-digit', day: '2-digit' });
    }
}

async function fetchUserPastes() {
    try {
        const response = await fetch('/api/pastes/my?page=1&limit=15');
        const pastesData = await response.json();

        if (pastesData.message === 'No pastes found.' || pastesData.message === 'Page out of range.') {
            userPastes = [];
            document.getElementById('account-pastes').textContent = `Pastes: 0`;
            totalPages = 0;
            document.getElementById('paste-pages').textContent = `0/0`;
            displayPastes();
            return;
        }

        userPastes = pastesData.pastes;
        document.getElementById('account-pastes').textContent = `Pastes: ${userPastes.length}`;
        totalPages = Math.ceil(userPastes.length / pastesPerPage);
        document.getElementById('paste-pages').textContent = `${currentPage}/${totalPages || 1}`;
        displayPastes();
    } catch (error) {
        console.error('Error fetching user pastes:', error);
    }
}


function displayPastes() {
    const pastesList = document.getElementById('pastes');
    pastesList.innerHTML = '';


    const pasteInfoHeader = document.querySelector('.paste-information');
    const pasteActions = document.querySelector('.paste-actions');
    const prevButton = document.getElementById('previous-button');
    const nextButton = document.getElementById('next-button');


    if (userPastes.length === 0) {
        if (pasteInfoHeader) pasteInfoHeader.style.display = 'none';
        if (pasteActions) pasteActions.style.display = 'none';
        if (prevButton) prevButton.disabled = true;
        if (nextButton) nextButton.disabled = true;
        const noItems = document.createElement('li');
        noItems.textContent = 'No pastes found';
        pastesList.appendChild(noItems);
        return;
    } else {
        if (pasteInfoHeader) pasteInfoHeader.style.display = '';
        if (pasteActions) pasteActions.style.display = '';
    }


    if (prevButton) prevButton.disabled = currentPage <= 1;
    if (nextButton) nextButton.disabled = currentPage >= totalPages || totalPages <= 1;


    const startIndex = (currentPage - 1) * pastesPerPage;
    const endIndex = Math.min(startIndex + pastesPerPage, userPastes.length);


    for (let i = startIndex; i < endIndex; i++) {
        const paste = userPastes[i];
        const pasteItem = document.createElement('li');


        const pasteLink = document.createElement('a');
        pasteLink.href = `/${paste.id}`;

        pasteLink.style.display = 'grid';
        pasteLink.style.gridTemplateColumns = '2fr 1fr 1fr';
        pasteLink.style.gap = '1rem';


        const titleP = document.createElement('p');
        titleP.id = 'paste-title';
        titleP.textContent = paste.title || 'Untitled';


        const dateP = document.createElement('p');
        dateP.id = 'paste-date';
        const createdDate = new Date(paste.created * 1000);
        dateP.textContent = `${formatDate(createdDate)}`;


        const syntaxP = document.createElement('p');
        syntaxP.id = 'paste-syntax';
        syntaxP.textContent = paste.syntax || 'plaintext';

        pasteLink.appendChild(titleP);
        pasteLink.appendChild(dateP);
        pasteLink.appendChild(syntaxP);
        pasteItem.appendChild(pasteLink);
        pastesList.appendChild(pasteItem);
    }
}


function previousPage() {
    if (currentPage > 1) {
        currentPage--;
        document.getElementById('paste-pages').textContent = `${currentPage}/${totalPages || 1}`;
        displayPastes();
    }
}


function nextPage() {
    if (currentPage < totalPages) {
        currentPage++;
        document.getElementById('paste-pages').textContent = `${currentPage}/${totalPages || 1}`;
        displayPastes();
    }
}


function logout() {

    if (document.querySelector('.logout-modal-overlay')) return;

    const modalOverlay = document.createElement('div');
    modalOverlay.className = 'logout-modal-overlay';

    const modalBox = document.createElement('div');
    modalBox.className = 'logout-modal-box';
    modalBox.innerHTML = `
        <h2>Confirm Logout</h2>
        <p>Are you sure you want to log out?</p>
        <button id="confirm-logout">Logout</button>
        <button id="cancel-logout">Cancel</button>
    `;
    modalOverlay.appendChild(modalBox);
    document.body.appendChild(modalOverlay);

    document.getElementById('cancel-logout').onclick = function () {
        document.body.removeChild(modalOverlay);
    };

    document.getElementById('confirm-logout').onclick = async function () {
        try {
            await fetch('/api/auth/logout', { method: 'POST'});
        } catch { }
        window.location.href = '/login';
    };
}


function deleteAccount() {

    if (document.querySelector('.delete-modal-overlay')) return;

    const username = document.getElementById('account-username').textContent.replace('Username: ', '').trim();
    const pasteCount = userPastes.length;

    const modalOverlay = document.createElement('div');
    modalOverlay.className = 'delete-modal-overlay';

    const modalBox = document.createElement('div');
    modalBox.className = 'delete-modal-box';
    modalBox.innerHTML = `
        <h2>Delete Account</h2>
        <p>This action is <b>irreversible</b> and will delete your account and all your ${pasteCount} pastes.</p>
        <p>Type your username <b>${username}</b> and your paste count <b>${pasteCount}</b> to confirm:</p>
        <input id="delete-username" type="text" placeholder="Username" style="margin-bottom:8px;width:90%;padding:8px;border-radius:5px;border:1px solid var(--neutral-700);background:var(--neutral-800);color:var(--neutral-100);"><br>
        <input id="delete-pastecount" type="number" placeholder="Paste count" style="margin-bottom:16px;width:90%;padding:8px;border-radius:5px;border:1px solid var(--neutral-700);background:var(--neutral-800);color:var(--neutral-100);"><br>
        <button id="confirm-delete-account" disabled>Delete</button>
        <button id="cancel-delete-account">Cancel</button>
        <p id="delete-error" style="color:#e74c3c;margin-top:1rem;display:none;"></p>
    `;
    modalOverlay.appendChild(modalBox);
    document.body.appendChild(modalOverlay);

    document.getElementById('cancel-delete-account').onclick = function () {
        document.body.removeChild(modalOverlay);
    };

    const userInput = document.getElementById('delete-username');
    const countInput = document.getElementById('delete-pastecount');
    const confirmBtn = document.getElementById('confirm-delete-account');
    function validateInputs() {
        if (userInput.value.trim() === username && countInput.value.trim() === String(pasteCount)) {
            confirmBtn.disabled = false;
        } else {
            confirmBtn.disabled = true;
        }
    }
    userInput.addEventListener('input', validateInputs);
    countInput.addEventListener('input', validateInputs);

    confirmBtn.onclick = async function () {
        if (confirmBtn.disabled) return;
        try {
            await fetch('/api/auth/delete', { method: 'DELETE'});
        } catch { }
        window.location.href = '/register';
    };
}