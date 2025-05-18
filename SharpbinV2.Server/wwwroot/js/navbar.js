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
                    top: 60px;
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
                    max-height: 300px;
                    padding: 1rem 0;
                }
                
                .nav-link {
                    width: 90%;
                    text-align: center;
                    padding: 1rem;
                    border-bottom: 1px solid var(--neutral-800);
                }
                
                .home-link {
                    border: none;
                    border-bottom: 1px solid var(--neutral-800);
                    order: -1;
                }
                
                .nav-link:last-child {
                    border-bottom: none;
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