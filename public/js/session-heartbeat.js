// Session heartbeat to keep user logged in
(function() {
    'use strict';
    
    // Only run heartbeat if user is logged in
    const userElement = document.querySelector('[data-user]');
    if (!userElement) return;
    
    let heartbeatInterval;
    let isPageVisible = true;
    let lastActivity = Date.now();
    
    // Send heartbeat to server
    function sendHeartbeat() {
        fetch('/api/heartbeat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) {
                console.log('Session expired, user needs to login again');
                clearInterval(heartbeatInterval);
            }
            return response.json();
        })
        .then(data => {
            if (data.status === 'ok') {
                console.log('Session refreshed for user:', data.user);
            }
        })
        .catch(error => {
            console.log('Heartbeat failed:', error);
        });
    }
    
    // Track user activity
    function updateActivity() {
        lastActivity = Date.now();
    }
    
    // Page visibility change handler
    function handleVisibilityChange() {
        isPageVisible = !document.hidden;
        
        if (isPageVisible) {
            // Page became visible, send immediate heartbeat
            sendHeartbeat();
            startHeartbeat();
        } else {
            // Page hidden, reduce heartbeat frequency
            clearInterval(heartbeatInterval);
        }
    }
    
    // Start heartbeat interval
    function startHeartbeat() {
        clearInterval(heartbeatInterval);
        
        // Send heartbeat every 10 minutes when page is active
        heartbeatInterval = setInterval(() => {
            const timeSinceActivity = Date.now() - lastActivity;
            
            // Only send heartbeat if user was active in last 30 minutes
            if (timeSinceActivity < 30 * 60 * 1000) {
                sendHeartbeat();
            }
        }, 10 * 60 * 1000); // 10 minutes
    }
    
    // Activity event listeners
    const activityEvents = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'];
    activityEvents.forEach(event => {
        document.addEventListener(event, updateActivity, { passive: true });
    });
    
    // Page visibility API
    document.addEventListener('visibilitychange', handleVisibilityChange);
    
    // Window focus/blur events as fallback
    window.addEventListener('focus', () => {
        isPageVisible = true;
        sendHeartbeat();
        startHeartbeat();
    });
    
    window.addEventListener('blur', () => {
        isPageVisible = false;
        clearInterval(heartbeatInterval);
    });
    
    // Start the heartbeat system
    startHeartbeat();
    
    // Send initial heartbeat
    sendHeartbeat();
    
    console.log('Session heartbeat system initialized');
})();
