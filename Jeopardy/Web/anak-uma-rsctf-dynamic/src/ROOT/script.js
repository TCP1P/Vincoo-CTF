// Mobile Navigation Toggle
const hamburger = document.querySelector('.hamburger');
const navMenu = document.querySelector('.nav-menu');

hamburger.addEventListener('click', () => {
    hamburger.classList.toggle('active');
    navMenu.classList.toggle('active');
});

// Close mobile menu when clicking on a link
document.querySelectorAll('.nav-link').forEach(n => n.addEventListener('click', () => {
    hamburger.classList.remove('active');
    navMenu.classList.remove('active');
}));

// Smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Message handling
function closeMessage() {
    const messages = document.querySelectorAll('.message');
    messages.forEach(message => {
        message.style.display = 'none';
    });
}

// Auto-hide messages after 5 seconds
setTimeout(() => {
    closeMessage();
}, 5000);

// History management functions
function clearHistory() {
    if (confirm('Are you certain you want to clear all training data from the race records?')) {
        window.location.href = 'clear-history.jsp';
    }
}

function exportHistory() {
    // Create a JSON export of the history
    const historyData = [];
    const historyItems = document.querySelectorAll('.history-item');

    historyItems.forEach(item => {
        const url = item.querySelector('h3').textContent;
        const details = item.querySelector('p').textContent;
        const timestamp = item.querySelector('.history-timestamp')?.textContent || '';

        historyData.push({
            source: url,
            details: details,
            timestamp: timestamp
        });
    });

    // Create and download JSON file
    const dataStr = JSON.stringify(historyData, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    const url = URL.createObjectURL(dataBlob);

    const link = document.createElement('a');
    link.href = url;
    link.download = 'uma-musume-training-records.json';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    alert('Training records exported successfully!');
}

function deleteHistoryContent(button) {
    const url = button.getAttribute('data-url');

    if (confirm(`Are you certain you want to delete the training data from ${url}?`)) {
        window.location.href = `delete-screenshot.jsp?url=${encodeURIComponent(url)}`;
    }
}

// Content result functions
function downloadContent() {
    const url = document.getElementById('scraped-url').textContent;
    const scrapingType = document.getElementById('scraped-type').textContent;

    // Show loading message
    const downloadBtn = document.querySelector('.action-btn');
    const originalText = downloadBtn.innerHTML;
    downloadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Downloading...';
    downloadBtn.disabled = true;

    // Fetch the full content from the server
    fetch(`get-content.jsp?url=${encodeURIComponent(url)}`)
        .then(response => response.text())
        .then(content => {
            if (content.startsWith('Content not found') || content.startsWith('No URL provided')) {
                alert('Training data not found. Please collect the data again.');
            } else {
                // Decode Base64 content
                const decodedContent = atob(content);

                // Create and download file with decoded content
                const blob = new Blob([decodedContent], {type: 'application/octet-stream'});
                const downloadUrl = URL.createObjectURL(blob);

                const link = document.createElement('a');
                link.href = downloadUrl;
                link.download = `uma-musume-training-${url.replace(/[^a-zA-Z0-9]/g, '-')}-${scrapingType.toLowerCase()}.bin`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                URL.revokeObjectURL(downloadUrl);

                alert('Training data downloaded successfully!');
            }
        })
        .catch(error => {
            alert('Download failed: ' + error.message);
        })
        .finally(() => {
            // Restore button
            downloadBtn.innerHTML = originalText;
            downloadBtn.disabled = false;
        });
}

function copyContent() {
    const url = document.getElementById('scraped-url').textContent;

    // Show loading message
    const copyBtn = document.querySelector('.action-btn:nth-child(2)');
    const originalText = copyBtn.innerHTML;
    copyBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Copying...';
    copyBtn.disabled = true;

    // Fetch the full content from the server
    fetch(`get-content.jsp?url=${encodeURIComponent(url)}`)
        .then(response => response.text())
        .then(content => {
            if (content.startsWith('Content not found') || content.startsWith('No URL provided')) {
                alert('Training data not found. Please collect the data again.');
            } else {
                // Decode Base64 content
                const decodedContent = atob(content);

                navigator.clipboard.writeText(decodedContent).then(() => {
                    alert('Training data copied to clipboard!');
                }).catch(() => {
                    alert('Copy failed. Please try downloading instead.');
                });
            }
        })
        .catch(error => {
            alert('Copy failed: ' + error.message);
        })
        .finally(() => {
            // Restore button
            copyBtn.innerHTML = originalText;
            copyBtn.disabled = false;
        });
}

function viewHistoryContent(button) {
    const historyItem = button.closest('.history-item');
    const url = button.getAttribute('data-url');
    const title = historyItem.querySelector('h3').textContent;
    const description = historyItem.querySelector('p').textContent;

    // Show loading message
    const lightbox = document.getElementById('lightbox');
    const rawHtmlContent = document.getElementById('raw-html-content');

    rawHtmlContent.textContent = 'Loading training data...';
    lightbox.style.display = 'block';
    document.body.style.overflow = 'hidden';

    // Fetch the full content from the server
    fetch(`get-content.jsp?url=${encodeURIComponent(url)}`)
        .then(response => response.text())
        .then(content => {
            if (content.startsWith('Content not found') || content.startsWith('No URL provided') || content.startsWith('Training data not found')) {
                rawHtmlContent.textContent = 'Training data not found. Please collect the data again.';
            } else {
                try {
                    // Decode Base64 content
                    const decodedContent = atob(content);

                    // Check if content looks like HTML
                    if (decodedContent.trim().startsWith('<') && decodedContent.includes('</')) {
                        try {
                            // Create blob iframe for HTML content with cleaning
                            const cleanContent = cleanHtmlContent(decodedContent);
                            const blob = new Blob([cleanContent], {type: 'text/html;charset=utf-8'});
                            const url = URL.createObjectURL(blob);
                            rawHtmlContent.innerHTML = `<iframe src="${url}" style="width: 100%; height: 500px; border: none; background: white;"></iframe>`;
                        } catch (error) {
                            rawHtmlContent.textContent = 'Failed to render training data: ' + error.message;
                        }
                    } else {
                        // Show as text for non-HTML content
                        rawHtmlContent.textContent = decodedContent;
                    }
                } catch (error) {
                    // If Base64 decoding fails, show as binary data
                    rawHtmlContent.textContent = '[Binary data - cannot display as text]';
                }
            }
        })
        .catch(error => {
            rawHtmlContent.textContent = 'Failed to load training data: ' + error.message;
        });
}

function downloadHistoryContent(button) {
    const url = button.getAttribute('data-url');

    // Show loading message
    const originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    button.disabled = true;

    // Fetch the full content from the server
    fetch(`get-content.jsp?url=${encodeURIComponent(url)}`)
        .then(response => response.text())
        .then(content => {
            if (content.startsWith('Content not found') || content.startsWith('No URL provided')) {
                alert('Training data not found. Please collect the data again.');
            } else {
                // Decode Base64 content
                const decodedContent = atob(content);

                // Create and download file with decoded content
                const blob = new Blob([decodedContent], {type: 'application/octet-stream'});
                const downloadUrl = URL.createObjectURL(blob);

                const link = document.createElement('a');
                link.href = downloadUrl;
                link.download = `uma-musume-training-${url.replace(/[^a-zA-Z0-9]/g, '-')}.bin`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                URL.revokeObjectURL(downloadUrl);

                alert('Training data downloaded successfully!');
            }
        })
        .catch(error => {
            alert('Download failed: ' + error.message);
        })
        .finally(() => {
            // Restore button
            button.innerHTML = originalText;
            button.disabled = false;
        });
}

function cleanHtmlContent(html) {
    // Remove dangerous elements and attributes
    const cleaned = html
        .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
        .replace(/<iframe[^>]*>[\s\S]*?<\/iframe>/gi, '')
        .replace(/<object[^>]*>[\s\S]*?<\/object>/gi, '')
        .replace(/<embed[^>]*>/gi, '')
        .replace(/<form[^>]*>[\s\S]*?<\/form>/gi, '')
        .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/vbscript:/gi, '');

    return cleaned;
}

// Raw HTML viewer
function viewRawHtml() {
    const url = document.getElementById('scraped-url').textContent;

    // Show loading message
    const rawBtn = document.querySelector('.action-btn:nth-child(3)');
    const originalText = rawBtn.innerHTML;
    rawBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';
    rawBtn.disabled = true;

    // Fetch the full content from the server
    fetch(`get-content.jsp?url=${encodeURIComponent(url)}`)
        .then(response => response.text())
        .then(content => {
            if (content.startsWith('Content not found') || content.startsWith('No URL provided')) {
                alert('Training data not found. Please collect the data again.');
            } else {
                try {
                    // Decode Base64 content
                    const decodedContent = atob(content);

                    // Show raw content in lightbox
                    const lightbox = document.getElementById('lightbox');
                    const rawHtmlContent = document.getElementById('raw-html-content');

                    rawHtmlContent.textContent = decodedContent;
                    lightbox.style.display = 'block';
                    document.body.style.overflow = 'hidden';
                } catch (error) {
                    // If Base64 decoding fails, show as binary data
                    const lightbox = document.getElementById('lightbox');
                    const rawHtmlContent = document.getElementById('raw-html-content');

                    rawHtmlContent.textContent = '[Binary data - cannot display as text]';
                    lightbox.style.display = 'block';
                    document.body.style.overflow = 'hidden';
                }
            }
        })
        .catch(error => {
            alert('Failed to load raw data: ' + error.message);
        })
        .finally(() => {
            // Restore button
            rawBtn.innerHTML = originalText;
            rawBtn.disabled = false;
        });
}

// Close lightbox
document.querySelector('.close-lightbox').addEventListener('click', () => {
    document.getElementById('lightbox').style.display = 'none';
    document.body.style.overflow = 'auto';
});

// Close lightbox when clicking outside
document.getElementById('lightbox').addEventListener('click', (e) => {
    if (e.target === document.getElementById('lightbox')) {
        document.getElementById('lightbox').style.display = 'none';
        document.body.style.overflow = 'auto';
    }
});

// Scroll to scraper section
function scrollToScraper() {
    const scraperSection = document.getElementById('scraper');
    if (scraperSection) {
        scraperSection.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });
    }
}

// Enhanced form validation
document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('scraper-form');
    const submitBtn = document.getElementById('scrape-btn');
    const urlInput = document.getElementById('website-url');

    if (form && submitBtn && urlInput) {
        form.addEventListener('submit', function(e) {
            const url = urlInput.value.trim();

            if (!url) {
                e.preventDefault();
                alert('Please enter a racing data source URL!');
                urlInput.focus();
                return false;
            }

            if (!isValidUrl(url)) {
                e.preventDefault();
                alert('Please enter a valid racing data source URL!');
                urlInput.focus();
                return false;
            }

            // Show loading state
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Collecting Data...';
            submitBtn.disabled = true;

            // Add timeout to prevent button staying disabled
            setTimeout(() => {
                if (submitBtn.disabled) {
                    submitBtn.innerHTML = '<i class="fas fa-cloud-download-alt"></i> Collect Data';
                    submitBtn.disabled = false;
                }
            }, 30000); // 30 seconds timeout
        });

        // Real-time URL validation
        urlInput.addEventListener('input', function() {
            const url = this.value.trim();
            if (url && !isValidUrl(url)) {
                this.style.borderColor = '#ff6b6b';
                this.style.boxShadow = '0 0 0 3px rgba(255, 107, 107, 0.2)';
            } else {
                this.style.borderColor = '';
                this.style.boxShadow = '';
            }
        });
    }

    // Auto-focus URL input
    if (urlInput) {
        urlInput.focus();
    }
});

function isValidUrl(string) {
    try {
        const url = new URL(string);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
        return false;
    }
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl+Enter or Cmd+Enter to submit form
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        const form = document.getElementById('scraper-form');
        if (form) {
            form.submit();
        }
    }

    // Escape key to close lightbox
    if (e.key === 'Escape') {
        const lightbox = document.getElementById('lightbox');
        if (lightbox && lightbox.style.display === 'block') {
            lightbox.style.display = 'none';
            document.body.style.overflow = 'auto';
        }
    }
});

// Animate elements on scroll
function animateOnScroll() {
    const elements = document.querySelectorAll('.history-item, .horse-girl, .contact-item');

    elements.forEach(element => {
        const elementTop = element.getBoundingClientRect().top;
        const elementVisible = 150;

        if (elementTop < window.innerHeight - elementVisible) {
            element.classList.add('animate');
        }
    });
}

window.addEventListener('scroll', animateOnScroll);

// Initialize animations
document.addEventListener('DOMContentLoaded', function() {
    // Trigger initial animation check
    animateOnScroll();

    // Add CSS for animations
    const style = document.createElement('style');
    style.textContent = `
        .history-item, .horse-girl, .contact-item {
            opacity: 0;
            transform: translateY(20px);
            transition: all 0.6s ease;
        }

        .history-item.animate, .horse-girl.animate, .contact-item.animate {
            opacity: 1;
            transform: translateY(0);
        }
    `;
    document.head.appendChild(style);
});

// Session timeout warning
let sessionTimeout;
let warningShown = false;

function resetSessionTimeout() {
    clearTimeout(sessionTimeout);
    warningShown = false;

    // Set timeout for 25 minutes (session expires at 30 minutes)
    sessionTimeout = setTimeout(() => {
        if (!warningShown) {
            warningShown = true;
            if (confirm('Your training session will expire in 5 minutes. Would you like to continue?')) {
                // Extend session by making a simple request
                fetch('scraper-handler.jsp', {
                    method: 'HEAD'
                }).then(() => {
                    resetSessionTimeout();
                }).catch(() => {
                    alert('Session extension failed. Please save your work.');
                });
            }
        }
    }, 25 * 60 * 1000); // 25 minutes
}

// Initialize session timeout
document.addEventListener('DOMContentLoaded', resetSessionTimeout);

// Reset timeout on user activity
document.addEventListener('click', resetSessionTimeout);
document.addEventListener('keypress', resetSessionTimeout);

// Performance monitoring
function logPerformance() {
    if (window.performance && window.performance.timing) {
        const timing = window.performance.timing;
        const loadTime = timing.loadEventEnd - timing.navigationStart;
        console.log(`Uma Musume Training System loaded in ${loadTime}ms`);
    }
}

window.addEventListener('load', logPerformance);

// Error handling
window.addEventListener('error', function(e) {
    console.error('Training system error:', e.error);

    // Show user-friendly error message
    if (e.error && e.error.message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'message error-message';
        errorDiv.innerHTML = `
            <i class="fas fa-exclamation-circle"></i>
            Training system error occurred. Please refresh the page.
            <button onclick="closeMessage()" class="close-message">&times;</button>
        `;
        document.body.appendChild(errorDiv);

        setTimeout(() => {
            errorDiv.remove();
        }, 5000);
    }
});

// Service Worker registration (if available)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
        navigator.serviceWorker.register('/sw.js').then(function(registration) {
            console.log('Service Worker registered with scope:', registration.scope);
        }).catch(function(error) {
            console.log('Service Worker registration failed:', error);
        });
    });
}

// Dark mode toggle (bonus feature)
function toggleDarkMode() {
    document.body.classList.toggle('dark-mode');
    localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
}

// Initialize dark mode from localStorage
document.addEventListener('DOMContentLoaded', function() {
    const darkMode = localStorage.getItem('darkMode');
    if (darkMode === 'true') {
        document.body.classList.add('dark-mode');
    }
});

// Add dark mode styles
const darkModeStyles = `
    .dark-mode {
        --bg-color: #1a1a1a;
        --text-color: #e0e0e0;
        --border-color: #333;
    }

    .dark-mode body {
        background: var(--bg-color);
        color: var(--text-color);
    }

    .dark-mode .navbar {
        background: rgba(26, 26, 26, 0.95);
    }

    .dark-mode .scraper-form,
    .dark-mode .contact-form {
        background: #2a2a2a;
        border: 1px solid var(--border-color);
    }
`;

// Add styles to head
const darkModeStyleSheet = document.createElement('style');
darkModeStyleSheet.textContent = darkModeStyles;
document.head.appendChild(darkModeStyleSheet);