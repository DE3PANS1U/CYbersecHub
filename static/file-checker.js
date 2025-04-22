document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const fileForm = document.getElementById('fileForm');
    const resultsSection = document.querySelector('.results-section');
    const resultsTable = document.querySelector('.results-table tbody');
    const downloadBtn = document.getElementById('downloadBtn');
    const loadingIndicator = document.querySelector('.loading');
    const fileError = document.getElementById('fileError');
    const fileInput = document.querySelector('input[type="file"]');
    const fileInputLabel = document.querySelector('.file-input p');
    const fileInputContainer = document.querySelector('.file-input');
    const currentFileSpan = document.getElementById('currentFile');
    const totalFilesSpan = document.getElementById('totalFiles');

    // Utility Functions
    function showLoading() {
        loadingIndicator.style.display = 'block';
        resultsSection.style.display = 'none';
        fileError.textContent = '';
    }

    function hideLoading() {
        loadingIndicator.style.display = 'none';
    }

    function showError(message) {
        fileError.textContent = message;
        hideLoading();
    }

    function getMaliciousClass(count) {
        if (count >= 5) return 'high';
        if (count >= 2) return 'medium';
        return 'low';
    }

    function createTruncatedCell(content, isHash = false) {
        const td = document.createElement('td');
        td.className = isHash ? 'hash-value truncate-with-tooltip' : 'truncate-with-tooltip';
        td.textContent = content;
        td.setAttribute('data-full-text', content);
        return td;
    }

    function displayResults(results) {
        if (!results || !Array.isArray(results)) {
            console.error('Invalid results format:', results);
            return;
        }

        resultsTable.innerHTML = '';
        
        if (results.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = '<td colspan="6">No results found</td>';
            resultsTable.appendChild(row);
        } else {
            results.forEach(result => {
                const row = document.createElement('tr');
                const maliciousClass = getMaliciousClass(result.malicious || 0);

                // File name cell with truncation
                row.appendChild(createTruncatedCell(result.filename || 'Unknown'));
                
                // Hash cell with truncation
                row.appendChild(createTruncatedCell(result.hash || 'N/A', true));
                
                // Stats cells
                row.innerHTML += `
                    <td class="malicious-count ${maliciousClass}">${result.malicious || 0}</td>
                    <td>${result.suspicious || 0}</td>
                    <td>${result.harmless || 0}</td>
                    <td>${result.undetected || 0}</td>
                `;
                
                resultsTable.appendChild(row);
            });
        }

        resultsSection.style.display = 'block';
    }

    function updateFileInputLabel() {
        const fileCount = fileInput.files.length;
        if (fileCount === 0) {
            fileInputLabel.textContent = 'Drop your files here or click to browse';
        } else if (fileCount === 1) {
            fileInputLabel.textContent = fileInput.files[0].name;
        } else {
            fileInputLabel.textContent = `${fileCount} files selected`;
        }
    }

    // File input handling
    fileInputContainer.addEventListener('click', () => fileInput.click());

    fileInputContainer.addEventListener('dragover', (e) => {
        e.preventDefault();
        fileInputContainer.style.borderColor = 'var(--primary-color)';
        fileInputContainer.style.background = 'rgba(var(--primary-color-rgb), 0.05)';
    });

    fileInputContainer.addEventListener('dragleave', () => {
        fileInputContainer.style.borderColor = 'var(--border-color)';
        fileInputContainer.style.background = 'var(--bg-color)';
    });

    fileInputContainer.addEventListener('drop', (e) => {
        e.preventDefault();
        fileInput.files = e.dataTransfer.files;
        updateFileInputLabel();
        fileInputContainer.style.borderColor = 'var(--border-color)';
        fileInputContainer.style.background = 'var(--bg-color)';
        fileError.textContent = '';
    });

    fileInput.addEventListener('change', function() {
        updateFileInputLabel();
        fileError.textContent = '';
    });

    // Form submission
    fileForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const files = fileInput.files;
        if (!files || files.length === 0) {
            showError('Please select at least one file to check');
            return;
        }

        showLoading();
        totalFilesSpan.textContent = files.length;
        currentFileSpan.textContent = '0';

        const results = [];
        let currentIndex = 0;

        for (const file of files) {
            currentIndex++;
            currentFileSpan.textContent = currentIndex;

            const formData = new FormData();
            formData.append('file', file);

            try {
                const response = await fetch('/upload_file', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();
                if (data.error) {
                    results.push({
                        filename: file.name,
                        error: data.error
                    });
                } else {
                    results.push({
                        filename: file.name,
                        hash: data.hash || 'N/A',
                        malicious: data.malicious || 0,
                        suspicious: data.suspicious || 0,
                        harmless: data.harmless || 0,
                        undetected: data.undetected || 0
                    });
                }
            } catch (error) {
                console.error('Error processing file:', error);
                results.push({
                    filename: file.name,
                    error: 'Failed to process file'
                });
            }
        }

        displayResults(results);
        hideLoading();
    });

    // Download button
    downloadBtn.addEventListener('click', async function() {
        try {
            downloadBtn.disabled = true;
            downloadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Downloading...';
            
            const response = await fetch('/download_file');
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to download results');
            }
            
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'file_scan_results.xlsx';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            // Show success message
            const successMessage = document.createElement('div');
            successMessage.className = 'success-message';
            successMessage.innerHTML = '<i class="fas fa-check-circle"></i> Results downloaded successfully!';
            downloadBtn.parentNode.insertBefore(successMessage, downloadBtn.nextSibling);
            
            // Remove success message after 3 seconds
            setTimeout(() => {
                successMessage.remove();
            }, 3000);
        } catch (error) {
            console.error('Download error:', error);
            
            // Show error message
            const errorMessage = document.createElement('div');
            errorMessage.className = 'error-message';
            errorMessage.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${error.message}`;
            downloadBtn.parentNode.insertBefore(errorMessage, downloadBtn.nextSibling);
            
            // Remove error message after 5 seconds
            setTimeout(() => {
                errorMessage.remove();
            }, 5000);
        } finally {
            downloadBtn.disabled = false;
            downloadBtn.innerHTML = '<i class="fas fa-download"></i> Download Results';
        }
    });

    // Theme toggle
    const themeToggle = document.getElementById('theme-toggle');
    themeToggle.addEventListener('click', function() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        themeToggle.textContent = newTheme === 'light' ? '🌙' : '☀️';
    });

    // Set initial theme
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    themeToggle.textContent = savedTheme === 'light' ? '🌙' : '☀️';
}); 