// Vercel Analytics for vanilla JavaScript
import { inject } from '@vercel/analytics';

// Initialize analytics
inject();

// Track custom events (optional)
window.va = window.va || function() {
    (window.vaq = window.vaq || []).push(arguments);
};

// Track page views automatically
console.log('📊 Vercel Analytics initialized');
