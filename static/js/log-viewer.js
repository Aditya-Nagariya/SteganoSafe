/**
 * Enhanced Log Viewer for SteganoSafe Admin Panel
 */

class LogViewer {
    constructor(options = {}) {
        // DOM elements
        this.container = document.getElementById(options.containerId || 'logs');
        this.searchInput = document.getElementById(options.searchInputId || 'log-search');
        this.filterButtons = document.querySelectorAll(options.filterButtonsSelector || '.btn-filter');
        
        // State
        this.currentFilter = 'all';
        this.isAutoRefreshing = false;
        this.autoRefreshInterval = null;
        
        // Settings
        this.autoRefreshInterval = options.autoRefreshInterval || 30000; // 30 seconds
        
        // Initialize
        if (this.container) {
            this.init();
        }
    }
    
    init() {
        this.logContent = this.container.querySelector('tbody') || this.container;
        this.logLines = this.container.querySelectorAll('.log-line');
        
        // Set up event listeners
        this.setupFilterButtons();
        this.setupSearch();
        this.setupTimeFilters();
        this.setupScrollButtons();
        this.setupExportButtons();
        
        // Initialize stats
        this.updateStats();
        
        // Apply default filter (usually 'last 24 hours')
        this.applyTimeRange('day');
        
        // Scroll to bottom on load
        this.scrollToBottom();
    }
    
    setupFilterButtons() {
        this.filterButtons.forEach(button => {
            button.addEventListener('click', () => {
                // Update active state
                this.filterButtons.forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');
                
                // Update filter and apply
                this.currentFilter = button.getAttribute('data-filter');
                this.applyFilters();
            });
        });
    }
    
    setupSearch() {
        const searchButton = document.getElementById('search-btn');
        const clearButton = document.getElementById('clear-search');
        
        if (searchButton) {
            searchButton.addEventListener('click', () => this.performSearch());
        }
        
        if (clearButton) {
            clearButton.addEventListener('click', () => {
                this.searchInput.value = '';
                this.performSearch();
            });
        }
        
        if (this.searchInput) {
            this.searchInput.addEventListener('keyup', (e) => {
                if (e.key === 'Enter') {
                    this.performSearch();
                }
            });
        }
    }
    
    performSearch() {
        const searchText = this.searchInput.value;
        const regexSearch = document.getElementById('regex-search')?.checked || false;
        const caseSensitive = document.getElementById('case-sensitive')?.checked || false;
        
        if (!searchText) {
            // Clear search
            this.logLines.forEach(line => {
                line.dataset.searchFilter = 'show';
                const messageCell = line.querySelector('.message');
                if (messageCell) {
                    messageCell.innerHTML = messageCell.textContent;
                }
            });
        } else {
            // Apply search
            this.logLines.forEach(line => {
                const messageCell = line.querySelector('.message');
                if (!messageCell) return;
                
                const content = messageCell.textContent;
                let isMatch = false;
                
                try {
                    if (regexSearch) {
                        // Regex search
                        const flags = caseSensitive ? 'g' : 'gi';
                        const regex = new RegExp(searchText, flags);
                        isMatch = regex.test(content);
                        
                        // Highlight matches
                        if (isMatch) {
                            messageCell.innerHTML = content.replace(regex, match => 
                                `<span class="search-highlight">${match}</span>`
                            );
                        }
                    } else {
                        // Standard search
                        if (caseSensitive) {
                            isMatch = content.includes(searchText);
                        } else {
                            isMatch = content.toLowerCase().includes(searchText.toLowerCase());
                        }
                        
                        // Highlight matches
                        if (isMatch) {
                            const escapedText = searchText.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                            const regex = new RegExp(escapedText, 'gi');
                            messageCell.innerHTML = content.replace(regex, match => 
                                `<span class="search-highlight">${match}</span>`
                            );
                        }
                    }
                } catch (e) {
                    console.error('Search error:', e);
                    isMatch = false;
                }
                
                line.dataset.searchFilter = isMatch ? 'show' : 'hide';
            });
        }
        
        this.applyFilters();
    }
    
    setupTimeFilters() {
        const timeRangeSelect = document.getElementById('time-range');
        const customDateRange = document.getElementById('custom-date-range');
        const applyDateRange = document.getElementById('apply-date-range');
        
        if (timeRangeSelect) {
            timeRangeSelect.addEventListener('change', () => {
                if (timeRangeSelect.value === 'custom') {
                    customDateRange?.classList.remove('d-none');
                } else {
                    customDateRange?.classList.add('d-none');
                    this.applyTimeRange(timeRangeSelect.value);
                }
            });
        }
        
        if (applyDateRange) {
            applyDateRange.addEventListener('click', () => this.applyCustomTimeRange());
        }
    }
    
    applyTimeRange(range) {
        const now = new Date();
        let cutoffDate = new Date(now);
        
        switch (range) {
            case 'hour':
                cutoffDate.setHours(now.getHours() - 1);
                break;
            case 'day':
                cutoffDate.setDate(now.getDate() - 1);
                break;
            case 'week':
                cutoffDate.setDate(now.getDate() - 7);
                break;
            case 'all':
            default:
                // Show all logs
                this.logLines.forEach(line => {
                    line.dataset.timeFilter = 'show';
                });
                this.applyFilters();
                return;
        }
        
        this.logLines.forEach(line => {
            const timestamp = line.dataset.timestamp;
            if (timestamp) {
                const logDate = new Date(timestamp);
                if (logDate >= cutoffDate) {
                    line.dataset.timeFilter = 'show';
                } else {
                    line.dataset.timeFilter = 'hide';
                }
            } else {
                // If no timestamp, always show
                line.dataset.timeFilter = 'show';
            }
        });
        
        this.applyFilters();
    }
    
    applyCustomTimeRange() {
        const dateFrom = document.getElementById('date-from');
        const dateTo = document.getElementById('date-to');
        
        if (!dateFrom || !dateTo) return;
        
        const fromDate = new Date(dateFrom.value);
        const toDate = new Date(dateTo.value);
        
        if (isNaN(fromDate.getTime()) || isNaN(toDate.getTime())) {
            this.showToast('Please enter valid dates', 'warning');
            return;
        }
        
        this.logLines.forEach(line => {
            const timestamp = line.dataset.timestamp;
            if (timestamp) {
                const logDate = new Date(timestamp);
                if (logDate >= fromDate && logDate <= toDate) {
                    line.dataset.timeFilter = 'show';
                } else {
                    line.dataset.timeFilter = 'hide';
                }
            }
        });
        
        this.applyFilters();
    }
    
    applyFilters() {
        let visibleCount = 0;
        
        this.logLines.forEach(line => {
            const levelMatch = this.currentFilter === 'all' || line.dataset.level === this.currentFilter;
            const timeMatch = !line.dataset.timeFilter || line.dataset.timeFilter === 'show';
            const searchMatch = !line.dataset.searchFilter || line.dataset.searchFilter === 'show';
            
            if (levelMatch && timeMatch && searchMatch) {
                line.style.display = '';
                visibleCount++;
            } else {
                line.style.display = 'none';
            }
        });
        
        // Update counter
        const filteredCountElement = document.getElementById('filtered-count');
        if (filteredCountElement) {
            filteredCountElement.textContent = visibleCount;
        }
    }
    
    setupScrollButtons() {
        const scrollTopButton = document.getElementById('scroll-top');
        const scrollBottomButton = document.getElementById('scroll-bottom');
        
        if (scrollTopButton) {
            scrollTopButton.addEventListener('click', () => this.scrollToTop());
        }
        
        if (scrollBottomButton) {
            scrollBottomButton.addEventListener('click', () => this.scrollToBottom());
        }
    }
    
    scrollToTop() {
        this.container.scrollTop = 0;
    }
    
    scrollToBottom() {
        this.container.scrollTop = this.container.scrollHeight;
    }
    
    setupExportButtons() {
        document.getElementById('exportTxt')?.addEventListener('click', () => this.exportLogs('txt'));
        document.getElementById('exportCsv')?.addEventListener('click', () => this.exportLogs('csv'));
        document.getElementById('exportJson')?.addEventListener('click', () => this.exportLogs('json'));
    }
    
    exportLogs(format) {
        this.showLoading();
        
        // Collect visible logs
        const visibleLogs = [];
        this.logLines.forEach(line => {
            if (line.style.display !== 'none') {
                const timestamp = line.querySelector('.timestamp')?.textContent || '';
                const level = line.querySelector('.level')?.textContent || '';
                const message = line.querySelector('.message')?.textContent || '';
                
                visibleLogs.push({ timestamp, level, message });
            }
        });
        
        let content, filename, mimeType;
        const date = new Date().toISOString().slice(0, 10);
        
        switch (format) {
            case 'txt':
                content = visibleLogs.map(log => 
                    `[${log.timestamp}] ${log.level}: ${log.message}`
                ).join('\n');
                filename = `steganosafe_logs_${date}.txt`;
                mimeType = 'text/plain';
                break;
                
            case 'csv':
                content = 'Timestamp,Level,Message\n';
                content += visibleLogs.map(log => 
                    `"${log.timestamp}","${log.level}","${log.message.replace(/"/g, '""')}"`
                ).join('\n');
                filename = `steganosafe_logs_${date}.csv`;
                mimeType = 'text/csv';
                break;
                
            case 'json':
                content = JSON.stringify(visibleLogs, null, 2);
                filename = `steganosafe_logs_${date}.json`;
                mimeType = 'application/json';
                break;
        }
        
        // Generate and download the file
        this.downloadFile(content, filename, mimeType);
    }
    
    downloadFile(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        
        // Cleanup
        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            this.hideLoading();
            
            this.showToast(`Logs exported as ${format.toUpperCase()}`, 'success');
        }, 100);
    }
    
    updateStats() {
        let errorCount = 0;
        let warningCount = 0;
        let infoCount = 0;
        let debugCount = 0;
        
        this.logLines.forEach(line => {
            const level = line.dataset.level;
            
            switch (level) {
                case 'error': errorCount++; break;
                case 'warning': warningCount++; break;
                case 'info': infoCount++; break;
                case 'debug': debugCount++; break;
            }
        });
        
        document.getElementById('total-count').textContent = this.logLines.length;
        document.getElementById('error-count').textContent = errorCount;
        document.getElementById('warning-count').textContent = warningCount;
        document.getElementById('info-count').textContent = infoCount;
        document.getElementById('debug-count').textContent = debugCount;
        document.getElementById('total-logs-count').textContent = this.logLines.length;
        document.getElementById('filtered-count').textContent = this.logLines.length;
    }
    
    toggleAutoRefresh() {
        const autoRefreshButton = document.getElementById('auto-refresh');
        if (!autoRefreshButton) return;
        
        if (this.isAutoRefreshing) {
            clearInterval(this.autoRefreshInterval);
            autoRefreshButton.classList.remove('btn-primary');
            autoRefreshButton.classList.add('btn-outline-secondary');
            this.isAutoRefreshing = false;
        } else {
            this.autoRefreshInterval = setInterval(() => {
                location.reload();
            }, this.autoRefreshInterval);
            
            autoRefreshButton.classList.remove('btn-outline-secondary');
            autoRefreshButton.classList.add('btn-primary');
            this.isAutoRefreshing = true;
            
            this.showToast(`Auto-refresh enabled (${this.autoRefreshInterval/1000}s interval)`, 'info');
        }
    }
    
    showLoading() {
        const loadingOverlay = document.getElementById('loading-overlay');
        if (loadingOverlay) {
            loadingOverlay.classList.add('active');
        }
    }
    
    hideLoading() {
        const loadingOverlay = document.getElementById('loading-overlay');
        if (loadingOverlay) {
            loadingOverlay.classList.remove('active');
        }
    }
    
    showToast(message, type = 'info') {
        if (typeof Swal !== 'undefined') {
            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: type,
                title: message,
                showConfirmButton: false,
                timer: 3000
            });
        } else {
            alert(message);
        }
    }
}

// Initialize on DOM content loaded
document.addEventListener('DOMContentLoaded', () => {
    const logViewer = new LogViewer();
    
    // Set up auto-refresh toggle
    document.getElementById('auto-refresh')?.addEventListener('click', () => {
        logViewer.toggleAutoRefresh();
    });
    
    // Set up refresh button
    document.getElementById('refresh-logs')?.addEventListener('click', () => {
        logViewer.showLoading();
        setTimeout(() => {
            location.reload();
        }, 500);
    });
    
    // Set up log detail modal
    const logContent = document.getElementById('log-content');
    if (logContent) {
        logContent.addEventListener('click', (e) => {
            const logLine = e.target.closest('.log-line');
            if (logLine) {
                const timestamp = logLine.querySelector('.timestamp')?.textContent || '';
                const level = logLine.querySelector('.level')?.textContent || '';
                const message = logLine.querySelector('.message')?.textContent || '';
                
                const logText = `Timestamp: ${timestamp}\nLevel: ${level}\n\nMessage:\n${message}`;
                
                const logDetailContent = document.getElementById('log-detail-content');
                if (logDetailContent) {
                    logDetailContent.textContent = logText;
                    
                    // Show modal if Bootstrap is available
                    const logDetailModal = new bootstrap.Modal(document.getElementById('logDetailModal'));
                    logDetailModal.show();
                }
            }
        });
    }
    
    // Set up copy log button
    document.getElementById('copy-log-btn')?.addEventListener('click', () => {
        const logDetailContent = document.getElementById('log-detail-content');
        if (logDetailContent) {
            const logText = logDetailContent.textContent;
            
            navigator.clipboard.writeText(logText)
                .then(() => {
                    logViewer.showToast('Log copied to clipboard', 'success');
                })
                .catch(err => {
                    console.error('Could not copy text: ', err);
                    logViewer.showToast('Failed to copy to clipboard', 'error');
                });
        }
    });
});
