const navbarHTML = `
    <div class="nav-bar">
        <button class="hamburger" onclick="toggleMenu()">☰</button>
        <div class="nav-links">
            <a href="index.html" class="nav-link">Home</a>
            <a href="archive.html" class="nav-link">Paste Archive</a>
        </div>
        <style>
            .nav-bar {display: flex;justify-content: space-between;align-items: center;padding: 1rem 2rem;background-color: var(--neutral-900);color: #fff;position: fixed;width: 100%;top: 0;left: 0;right: 0;}.nav-link {color: #fff;text-decoration: none;font-size: 1.2rem;transition: color 0.3s;}.nav-link:hover {color: var(--neutral-300);}.nav-links .nav-link {width: auto;padding: 0 1rem;border-bottom: none;}.nav-links .nav-link:last-child {border-bottom: none;}.hamburger {display: none;background: none;border: none;font-size: 2rem;cursor: pointer;margin: 0 auto;}.nav-links {display: flex;flex-direction: row;position: static;background-color: transparent;padding: 0;max-height: none;transition: none;}.nav-links.show {display: flex;flex-direction: column;position: absolute;top: 100%;left: 0;right: 0;background-color: var(--neutral-900);padding: 1rem 2rem;max-height: 500px;transition: max-height 0.3s ease-out;overflow: hidden;}@media (max-width: 800px) {.nav-links {display: none;flex-direction: column;width: 100%;position: absolute;top: 100%;left: 0;right: 0;border-top: 1px solid var(--neutral-800);background-color: var(--neutral-900);padding: 1rem 2rem;max-height: 0;transition: max-height 0.3s ease-out;overflow: hidden;}.nav-link{width: 100% !important;padding: 1rem 0 !important;text-align: center;border-bottom: 1px solid var(--neutral-800) !important;}.nav-links.show {display: flex;max-height: 500px;flex-direction: column;align-items: center;}.hamburger {display: block;margin: 0 auto;}.nav-bar {justify-content: center;}}
        </style>
    </div>
`;

document.addEventListener('DOMContentLoaded', () => {
    document.body.insertAdjacentHTML('afterbegin', navbarHTML);
});

window.toggleMenu = function () {
    const nav = document.querySelector('.nav-links');
    nav.classList.toggle('show');
};

