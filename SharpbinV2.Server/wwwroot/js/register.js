document.addEventListener('DOMContentLoaded', function() {
    const registerForm = document.getElementById('register-form');
    const errorMessage = document.getElementById('error-message');

    
    checkAuthStatus();

    registerForm.addEventListener('submit', async function(event) {
        event.preventDefault();
        
        
        const username = document.getElementById('username').value.trim();
        const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        
        
        if (!username || !password) {
            showError('Please fill in all required fields');
            return;
        }
        
        if (password !== confirmPassword) {
            showError('Passwords do not match');
            return;
        }
        
        if (password.length < 6) {
            showError('Password must be at least 6 characters long');
            return;
        }
        
        if (username.length < 3) {
            showError('Username must be at least 3 characters long');
            return;
        }
        
        try {
            
            const submitButton = registerForm.querySelector('button[type="submit"]');
            const originalButtonText = submitButton.textContent;
            submitButton.disabled = true;
            submitButton.textContent = 'Creating account...';
            
            
            const requestData = {
                username: username,
                password: password
            };
            
            
            if (email) {
                requestData.email = email;
            }
                
            
            const response = await fetch('/api/auth/register', {
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
                showError(data.message || 'Registration failed. Please try again.');
                submitButton.disabled = false;
                submitButton.textContent = originalButtonText;
            }
        } catch (error) {
            console.error('Registration error:', error);
            showError('An unexpected error occurred. Please try again later.');
            
            const submitButton = registerForm.querySelector('button[type="submit"]');
            submitButton.disabled = false;
            submitButton.textContent = 'Register';
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
