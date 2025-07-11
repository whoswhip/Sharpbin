let currentPage = 1;
let totalPages = 1;
let pastesPerPage = 10;
let userPastes = [];

const userTypes = {
    "Admin": 255,
    "User": 0
};

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


async function logout() {
    const confirmed = await Modal.confirm(
        "Are you sure you want to log out?",
        "Confirm Logout",
        "danger"
    );
    
    if (confirmed) {
        try {
            await fetch('/api/auth/logout', { method: 'POST' });
        } catch { }
        window.location.href = '/login';
    }
}


async function deleteAccount() {
    const username = document.getElementById('account-username').textContent.replace('Username: ', '').trim();
    const pasteCount = userPastes.length;

    const customContent = document.createElement('div');
    customContent.innerHTML = `
        <p style="color: var(--text-color); margin-bottom: 1rem; line-height: 1.6;">
            This action is <strong>irreversible</strong> and will delete your account and all your ${pasteCount} pastes.
        </p>
        <p style="color: var(--text-color); margin-bottom: 1.5rem;">
            To confirm, type your username <strong>${username}</strong> and your paste count <strong>${pasteCount}</strong>:
        </p>
        <div style="margin-bottom: 1rem;">
            <label class="modal-label">Username:</label>
            <input type="text" id="delete-username" class="modal-input" placeholder="Username">
        </div>
        <div style="margin-bottom: 1.5rem;">
            <label class="modal-label">Paste count:</label>
            <input type="number" id="delete-pastecount" class="modal-input" placeholder="Paste count">
        </div>
        <div style="display: flex; gap: 0.75rem; justify-content: flex-end;">
            <button class="btn btn-secondary delete-cancel">Cancel</button>
            <button class="btn btn-danger delete-confirm" disabled>Delete Account</button>
        </div>
    `;

    const { body, close } = Modal.custom(customContent, {
        title: 'Delete Account',
        className: 'modal-delete-account'
    });

    const userInput = customContent.querySelector('#delete-username');
    const countInput = customContent.querySelector('#delete-pastecount');
    const confirmBtn = customContent.querySelector('.delete-confirm');
    const cancelBtn = customContent.querySelector('.delete-cancel');

    function validateInputs() {
        const usernameValid = userInput.value.trim() === username;
        const countValid = countInput.value.trim() === String(pasteCount);
        
        if (usernameValid && countValid) {
            confirmBtn.disabled = false;
            confirmBtn.style.opacity = '1';
        } else {
            confirmBtn.disabled = true;
            confirmBtn.style.opacity = '0.6';
        }
    }

    validateInputs();

    userInput.addEventListener('input', validateInputs);
    countInput.addEventListener('input', validateInputs);

    cancelBtn.onclick = () => close();

    confirmBtn.onclick = async function () {
        if (confirmBtn.disabled) return;
        
        if (userInput.value.trim() !== username || countInput.value.trim() !== String(pasteCount)) {
            return;
        }
        
        try {
            await fetch('/api/auth/delete', { method: 'DELETE' });
        } catch { }
        window.location.href = '/register';
    };

    setTimeout(() => userInput.focus(), 100);
}