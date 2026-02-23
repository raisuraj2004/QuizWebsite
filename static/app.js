function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    const toggle = document.getElementById('theme-toggle');
    if (toggle) {
        const isDark = theme === 'dark';
        toggle.textContent = isDark ? '☀' : '🌙';
        toggle.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
        toggle.setAttribute('title', isDark ? 'Switch to light mode' : 'Switch to dark mode');
    }
}

function initTheme() {
    const stored = localStorage.getItem('theme');
    if (stored === 'dark' || stored === 'light') {
        applyTheme(stored);
        return;
    }

    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    applyTheme(prefersDark ? 'dark' : 'light');
}

initTheme();

const themeToggle = document.getElementById('theme-toggle');
if (themeToggle) {
    themeToggle.addEventListener('click', function () {
        const currentTheme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
        const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
        localStorage.setItem('theme', nextTheme);
        applyTheme(nextTheme);
    });
}

document.querySelectorAll('.copy-btn').forEach(function (button) {
    button.addEventListener('click', function () {
        const code = button.dataset.code;
        if (!code) {
            return;
        }

        navigator.clipboard.writeText(code).then(function () {
            button.textContent = 'Copied';
            setTimeout(function () {
                button.textContent = 'Copy';
            }, 1400);
        }).catch(function () {
            button.textContent = 'Failed';
            setTimeout(function () {
                button.textContent = 'Copy';
            }, 1400);
        });
    });
});

document.querySelectorAll('.confirm-form').forEach(function (form) {
    form.addEventListener('submit', function (event) {
        const message = form.dataset.confirm || 'Are you sure?';
        if (!window.confirm(message)) {
            event.preventDefault();
        }
    });
});
