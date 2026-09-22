/**
 * Global application utilities for IL2CPP Analyzer.
 */

document.addEventListener('DOMContentLoaded', () => {
    // Mobile Drawer Toggle
    const toggleBtn = document.getElementById('sidebarToggleBtn');
    const sidebar = document.getElementById('appSidebar');
    const backdrop = document.getElementById('sidebarBackdrop');

    if (toggleBtn && sidebar && backdrop) {
        toggleBtn.addEventListener('click', () => {
            sidebar.classList.toggle('open');
            backdrop.classList.toggle('active');
        });

        backdrop.addEventListener('click', () => {
            sidebar.classList.remove('open');
            backdrop.classList.remove('active');
        });
    }

    // Global copy to clipboard for address badges
    document.querySelectorAll('.badge-address, .copy-btn').forEach(elem => {
        elem.addEventListener('click', (e) => {
            const val = elem.getAttribute('data-copy') || elem.innerText.trim();
            if (val) {
                navigator.clipboard.writeText(val).then(() => {
                    showToast(`Copied ${val} to clipboard!`);
                }).catch(err => {
                    console.error('Copy failed:', err);
                });
            }
        });
    });

    // Keyboard shortcut: Ctrl+K or / to focus search
    window.addEventListener('keydown', (e) => {
        if ((e.ctrlKey && e.key === 'k') || (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA')) {
            e.preventDefault();
            const searchInput = document.getElementById('globalSearchInput');
            if (searchInput) {
                searchInput.focus();
                searchInput.select();
            }
        }
    });
});

/**
 * Toast Notification Helper
 */
function showToast(message, type = 'info') {
    let container = document.getElementById('toastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.style.position = 'fixed';
        container.style.bottom = '20px';
        container.style.right = '20px';
        container.style.zIndex = '9999';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = 'glass-card';
    toast.style.padding = '10px 18px';
    toast.style.marginTop = '8px';
    toast.style.fontSize = '0.85rem';
    toast.style.borderLeft = '4px solid #3b82f6';
    toast.style.color = '#fff';
    toast.style.boxShadow = '0 6px 20px rgba(0,0,0,0.5)';
    toast.innerText = message;

    container.appendChild(toast);
    setTimeout(() => {
        toast.style.transition = 'opacity 0.4s ease';
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 400);
    }, 2500);
}
