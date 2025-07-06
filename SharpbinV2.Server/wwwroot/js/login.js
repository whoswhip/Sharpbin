document.addEventListener('DOMContentLoaded', function () {
    const loginForm = document.getElementById('login-form');
    const errorMessage = document.getElementById('error-message');


    checkAuthStatus();

    loginForm.addEventListener('submit', async function (event) {
        event.preventDefault();


        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;


        if (!username || !password) {
            showError('Please fill in all required fields');
            return;
        }

        try {

            const submitButton = loginForm.querySelector('button[type="submit"]');
            const originalButtonText = submitButton.textContent;
            submitButton.disabled = true;
            submitButton.textContent = 'Logging in...';


            const isEmail = username.includes('@');
            const requestData = isEmail
                ? { email: username, password: password }
                : { username: username, password: password };


            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(requestData)
            });

            const data = await response.json();

            if (data.success) {

                window.location.href = '/dash';
            } else {
                showError(data.message || 'Login failed. Please check your credentials.');
                submitButton.disabled = false;
                submitButton.textContent = originalButtonText;
            }
        } catch (error) {
            console.error('Login error:', error);
            showError('An unexpected error occurred. Please try again later.');

            const submitButton = loginForm.querySelector('button[type="submit"]');
            submitButton.disabled = false;
            submitButton.textContent = 'Login';
        }
    });


    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.classList.add('visible');


        setTimeout(() => {
            errorMessage.classList.remove('visible');
        }, 5000);
    }


    async function checkAuthStatus() {
        try {
            const response = await fetch('/api/accounts/authorized');
            const data = await response.json();

            if (data.success) {

                window.location.href = '/dash';
            }
        } catch (error) {

            console.log('Not logged in');
        }
    }
});
