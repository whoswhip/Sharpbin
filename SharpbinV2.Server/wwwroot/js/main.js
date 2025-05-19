const navbarHTML = `
    <div class="nav-bar">
        <div class="nav-brand">
            <a href="/" class="brand-link">Sharpbin</a>
        </div>
        <div class="nav-center">
            <div class="nav-links">
                <a href="/archive" class="nav-link">Archives</a>
                <a href="/" class="nav-link home-link">Home</a>
                <a href="#" class="nav-link">Account</a>
            </div>
        </div>
        <button class="hamburger" onclick="toggleMenu()" aria-label="Toggle menu">
            <span class="hamburger-line"></span>
            <span class="hamburger-line"></span>
            <span class="hamburger-line"></span>
        </button>
        <style>
            .nav-bar {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 0.75rem 2rem;
                background-color: var(--neutral-900);
                color: #fff;
                position: fixed;
                width: 100%;
                top: 0;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                z-index: 1000;
            }
            
            .nav-brand {
                flex: 0 0 auto;
                z-index: 15;
            }
            
            .brand-link {
                font-size: 1.5rem;
                font-weight: 700;
                color: #fff;
                text-decoration: none;
                letter-spacing: 0.5px;
                transition: transform 0.2s ease;
            }
            
            .brand-link:hover {
                transform: scale(1.05);
            }
            
            .nav-center {
                position: absolute;
                left: 0;
                right: 0;
                display: flex;
                justify-content: center;
                align-items: center;
            }
            
            .nav-links {
                display: flex;
                flex-direction: row;
                align-items: center;
                justify-content: center;
                gap: 1rem;
            }
            
            .nav-link {
                color: rgba(255, 255, 255, 0.85);
                text-decoration: none;
                font-size: 1.1rem;
                padding: 0.6rem 1.2rem;
                border-radius: 6px;
                transition: all 0.3s ease;
                font-weight: 500;
                text-align: center;
                border: 1px solid rgba(255, 255, 255, 0.2);
                max-width: 125px;
                width: 125px;
            }
            
            .nav-link:hover {
                color: #fff;
                background-color: rgba(255, 255, 255, 0.1);
                transform: translateY(-2px);
            }
            
            #nav-bar-selected {
                color: #fff;
                background-color: rgba(255, 255, 255, 0.15);
                font-weight: 500;
            }
            
            .hamburger {
                display: none;
                flex-direction: column;
                justify-content: space-between;
                width: 30px;
                height: 21px;
                background: transparent;
                border: none;
                cursor: pointer;
                padding: 0;
                z-index: 15;
            }
            
            .hamburger-line {
                display: block;
                height: 3px;
                width: 100%;
                border-radius: 10px;
                background: #fff;
                transition: all 0.3s ease;
            }
            
            @media (max-width: 800px) {
                .nav-center {
                    position: static;
                }
                
                .nav-links {
                    position: fixed;
                    top: 55px;
                    left: 0;
                    right: 0;
                    background-color: var(--neutral-900);
                    flex-direction: column;
                    align-items: center;
                    padding: 0;
                    max-height: 0;
                    overflow: hidden;
                    transition: max-height 0.3s ease-out, padding 0.3s ease;
                    box-shadow: 0 5px 10px rgba(0, 0, 0, 0.2);
                }
                
                .nav-links.show {
                    max-height: 350px;
                    padding: 1rem 0;
                    padding-bottom: 2rem;
                }
                
                .nav-link {
                    width: 90%;
                    max-width: 90%;
                    text-align: center;
                    padding: 1rem;
                }
                
                .home-link {
                    order: -1;
                }
                
                .hamburger {
                    display: flex;
                }
                
                .hamburger.active .hamburger-line:nth-child(1) {
                    transform: translateY(9px) rotate(45deg);
                }
                
                .hamburger.active .hamburger-line:nth-child(2) {
                    opacity: 0;
                }
                
                .hamburger.active .hamburger-line:nth-child(3) {
                    transform: translateY(-9px) rotate(-45deg);
                }
            }
        </style>
    </div>
`;

document.addEventListener('DOMContentLoaded', async () => {
    document.body.insertAdjacentHTML('afterbegin', navbarHTML);
    var path = window.location.pathname;
    var links = document.querySelectorAll('.nav-link');
    
    let accountHref = '/login';
    try {
        const resp = await fetch('/api/accounts/authorized');
        const data = await resp.json();
        if (data && data.success !== false) {
            accountHref = '/dash';
        }
    } catch {}
    
    const accountLink = document.querySelector('.nav-link[href="#"]');
    if (accountLink) {
        accountLink.setAttribute('href', accountHref);
    }
    
    links.forEach(link => {
        const href = link.getAttribute('href');
        if (href === path) {
            link.id = 'nav-bar-selected';
        }
        
        if ((path === '/dash' || path === '/login' || path === '/register') && (href === '/dash' || href === '/login')) {
            link.id = 'nav-bar-selected';
        }
    });
});

window.toggleMenu = function () {
    const nav = document.querySelector('.nav-links');
    const hamburger = document.querySelector('.hamburger');
    nav.classList.toggle('show');
    hamburger.classList.toggle('active');
};

function showNotification(message, type = 'info', duration = 3000) {
    if (!document.getElementById('notification-style')) {
        const style = document.createElement('style');
        style.id = 'notification-style';
        style.textContent = `
        .notification-container {
            position: fixed;
            bottom: 32px;
            right: 32px;
            z-index: 2000;
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 0.75rem;
        }
        .notification {
            min-width: 240px;
            max-width: 350px;
            padding: 12px 20px;
            border-radius: 8px;
            color: #ef4444;
            font-size: 1rem;
            font-weight: 500;
            box-shadow: 0 6px 24px rgba(0,0,0,0.28);
            margin-top: 0.5rem;
            opacity: 0;
            transform: translateY(20px);
            animation: notification-in 0.3s forwards;
            border: 1px solid rgba(220, 38, 38, 0.2);
            background: rgba(220, 38, 38, 0.1);
            letter-spacing: 0.01em;
            display: flex;
            align-items: center;
            gap: 0.75em;
        }
        .notification-info {
            color: #e5e7eb;
            background: var(--neutral-900, #181a20);
            border: 1px solid var(--neutral-800, #23272f);
        }
        .notification-warning {
            color: #f59e42;
            background: rgba(245, 158, 66, 0.10);
            border: 1px solid rgba(245, 158, 66, 0.18);
        }
        .notification-error {
            color: #ef4444;
            background: rgba(220, 38, 38, 0.1);
            border: 1px solid rgba(220, 38, 38, 0.2);
        }
        @keyframes notification-in {
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        @media (max-width: 600px) {
            .notification-container {
                right: 8px;
                bottom: 8px;
            }
            .notification {
                min-width: 160px;
                max-width: 90vw;
                padding: 0.75rem 1rem;
            }
        }
        `;
        document.head.appendChild(style);
    }

    let container = document.querySelector('.notification-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'notification-container';
        document.body.appendChild(container);
    }

    const notif = document.createElement('div');
    notif.className = `notification notification-${type}`;
    notif.textContent = message;
    container.appendChild(notif);

    setTimeout(() => {
        notif.style.opacity = '0';
        notif.style.transform = 'translateY(20px)';
        setTimeout(() => {
            notif.remove();
            if (container.childElementCount === 0) {
                container.remove();
            }
        }, 300);
    }, duration);
}