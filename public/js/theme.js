// Simple, bulletproof theme system
(function() {
    'use strict';
    
    function applyTheme() {
        const isDark = localStorage.getItem('darkMode') === 'true';
        const html = document.documentElement;
        
        if (isDark) {
            html.classList.add('dark');
        } else {
            html.classList.remove('dark');
        }
        
        console.log('Theme applied:', isDark ? 'dark' : 'light');
    }
    
    function setTheme(isDark) {
        localStorage.setItem('darkMode', isDark.toString());
        applyTheme();
    }
    
    // Apply theme immediately
    applyTheme();
    
    // Apply on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', applyTheme);
    }
    
    // Listen for storage changes
    window.addEventListener('storage', function(e) {
        if (e.key === 'darkMode') {
            applyTheme();
        }
    });
    
    // Expose functions globally
    window.setTheme = setTheme;
    window.applyTheme = applyTheme;
    
    // Check every 100ms to ensure sync
    setInterval(applyTheme, 100);
})();
