// Browser Extension for Remote Proctoring
// Monitors student activity during remote exams

class BrowserProctor {
    constructor() {
        this.violations = [];
        this.startTime = Date.now();
        this.examActive = false;
        this.initializeMonitoring();
    }
    
    initializeMonitoring() {
        // Monitor tab changes
        chrome.tabs.onActivated.addListener((activeInfo) => {
            this.checkTabSwitch(activeInfo.tabId);
        });
        
        // Monitor window focus changes
        chrome.windows.onFocusChanged.addListener((windowId) => {
            if (windowId === chrome.windows.WINDOW_ID_NONE) {
                this.logViolation('window_lost_focus', 'Student switched away from browser');
            }
        });
        
        // Monitor new tab creation
        chrome.tabs.onCreated.addListener((tab) => {
            this.checkNewTab(tab);
        });
        
        // Monitor navigation
        chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
            if (changeInfo.status === 'complete') {
                this.checkNavigation(tab);
            }
        });
    }
    
    checkTabSwitch(tabId) {
        if (!this.examActive) return;
        
        chrome.tabs.get(tabId, (tab) => {
            const url = tab.url;
            
            // Check for suspicious domains
            const suspiciousDomains = [
                'teamviewer.com', 'anydesk.com', 'remotedesktop.google.com',
                'gotoassist.com', 'logmein.com', 'supremo.com',
                'chat.openai.com', 'chatgpt.com', 'claude.ai',
                'bard.google.com', 'bing.com/chat', 'discord.com',
                'telegram.org', 'whatsapp.com', 'web.whatsapp.com'
            ];
            
            for (const domain of suspiciousDomains) {
                if (url.includes(domain)) {
                    this.logViolation('suspicious_domain', `Accessed ${domain}`);
                    break;
                }
            }
        });
    }
    
    checkNewTab(tab) {
        if (!this.examActive) return;
        
        this.logViolation('new_tab_opened', `New tab: ${tab.url}`);
    }
    
    checkNavigation(tab) {
        if (!this.examActive) return;
        
        const url = tab.url;
        
        // Check for search engines (possible cheating)
        const searchEngines = ['google.com/search', 'bing.com/search', 'duckduckgo.com'];
        for (const engine of searchEngines) {
            if (url.includes(engine)) {
                this.logViolation('search_engine', `Used search engine: ${engine}`);
                break;
            }
        }
        
        // Check for copy-paste sites
        const copySites = ['pastebin.com', 'gist.github.com', 'jsfiddle.net'];
        for (const site of copySites) {
            if (url.includes(site)) {
                this.logViolation('copy_paste_site', `Accessed code sharing site: ${site}`);
                break;
            }
        }
    }
    
    logViolation(type, details) {
        const violation = {
            timestamp: new Date().toISOString(),
            type: type,
            details: details,
            examDuration: Date.now() - this.startTime
        };
        
        this.violations.push(violation);
        
        // Send to server
        this.sendViolationToServer(violation);
        
        // Show warning to student
        this.showWarning(type);
    }
    
    sendViolationToServer(violation) {
        // Send violation data to your proctoring server
        fetch('https://your-proctoring-server.com/api/violations', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(violation)
        }).catch(err => console.error('Failed to send violation:', err));
    }
    
    showWarning(violationType) {
        const warnings = {
            'suspicious_domain': '⚠️ Warning: Accessing external assistance sites is prohibited',
            'search_engine': '⚠️ Warning: Using search engines during exam is not allowed',
            'copy_paste_site': '⚠️ Warning: Code sharing sites are prohibited during exams',
            'new_tab_opened': '⚠️ Warning: Opening new tabs during exam is monitored',
            'window_lost_focus': '⚠️ Warning: Please keep the exam window active'
        };
        
        const message = warnings[violationType] || '⚠️ Warning: Suspicious activity detected';
        
        // Show notification
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'warning.png',
            title: 'Exam Proctoring Alert',
            message: message
        });
    }
    
    startExam() {
        this.examActive = true;
        this.startTime = Date.now();
        
        // Clear previous violations
        this.violations = [];
        
        // Put browser into full screen
        chrome.windows.getCurrent((window) => {
            chrome.windows.update(window.id, { state: 'fullscreen' });
        });
        
        // Disable right-click context menu
        chrome.contextMenus.removeAll();
    }
    
    endExam() {
        this.examActive = false;
        
        // Generate final report
        const report = {
            examDuration: Date.now() - this.startTime,
            totalViolations: this.violations.length,
            violations: this.violations,
            endTime: new Date().toISOString()
        };
        
        // Send final report
        fetch('https://your-proctoring-server.com/api/exam-report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(report)
        });
        
        // Exit full screen
        chrome.windows.getCurrent((window) => {
            chrome.windows.update(window.id, { state: 'normal' });
        });
    }
    
    // Monitor clipboard access
    monitorClipboard() {
        document.addEventListener('copy', (e) => {
            if (this.examActive) {
                this.logViolation('clipboard_copy', 'Student copied content to clipboard');
            }
        });
        
        document.addEventListener('paste', (e) => {
            if (this.examActive) {
                this.logViolation('clipboard_paste', 'Student pasted content from clipboard');
            }
        });
    }
    
    // Monitor keyboard shortcuts
    monitorKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            if (!this.examActive) return;
            
            // Check for alt-tab like behavior
            if (e.altKey && e.key === 'Tab') {
                this.logViolation('alt_tab', 'Student attempted to switch applications');
                e.preventDefault();
            }
            
            // Check for print screen
            if (e.key === 'PrintScreen') {
                this.logViolation('print_screen', 'Student attempted to take screenshot');
                e.preventDefault();
            }
            
            // Check for developer tools
            if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I')) {
                this.logViolation('developer_tools', 'Student attempted to open developer tools');
                e.preventDefault();
            }
        });
    }
}

// Initialize proctor
const proctor = new BrowserProctor();

// Messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'startExam') {
        proctor.startExam();
        sendResponse({status: 'exam_started'});
    } else if (request.action === 'endExam') {
        proctor.endExam();
        sendResponse({status: 'exam_ended'});
    } else if (request.action === 'getStatus') {
        sendResponse({
            examActive: proctor.examActive,
            violations: proctor.violations.length
        });
    }
});
