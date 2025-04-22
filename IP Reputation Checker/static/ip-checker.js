document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const ipForm = document.getElementById('ipForm');
    const fileForm = document.getElementById('fileForm');
    const resultsSection = document.querySelector('.results-section');
    const resultsTable = document.querySelector('.results-table tbody');
    const downloadBtn = document.getElementById('downloadBtn');
    const loadingIndicator = document.querySelector('.loading');
    const ipError = document.getElementById('ipError');
    const fileError = document.getElementById('fileError');

    // Utility Functions
    function showLoading() {
        loadingIndicator.style.display = 'block';
        resultsSection.style.display = 'none';
        ipError.textContent = '';
        fileError.textContent = '';
    }

    function hideLoading() {
        loadingIndicator.style.display = 'none';
    }

    function showError(element, message) {
        element.textContent = message;
        hideLoading();
    }

    function getMaliciousClass(count) {
        if (count >= 5) return 'high';
        if (count >= 2) return 'medium';
        return 'low';
    }

    function displayResults(results) {
        if (!results || typeof results !== 'object') {
            console.error('Invalid results format:', results);
            return;
        }

        resultsTable.innerHTML = '';
        
        if (results.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = '<td colspan="5">No results found</td>';
            resultsTable.appendChild(row);
        } else {
            for (let i = 0; i < results.length; i++) {
                const result = results[i];
                if (result && typeof result === 'object') {
                    const row = document.createElement('tr');
                    const maliciousClass = getMaliciousClass(result.malicious || 0);
                    
                    row.innerHTML = `
                        <td>${result.ip || 'N/A'}</td>
                        <td class="malicious-count ${maliciousClass}">${result.malicious || 0}</td>
                        <td>${result.suspicious || 0}</td>
                        <td>${result.as_owner || 'Unknown'}</td>
                        <td>${result.country || 'Unknown'}</td>
                    `;
                    resultsTable.appendChild(row);
                }
            }
        }

        resultsSection.style.display = 'block';
    }

    async function handleFormSubmission(url, formData) {
        showLoading();

        try {
            const response = await fetch(url, {
                method: 'POST',
                body: formData
            });

            const text = await response.text();
            console.log('Raw response:', text);

            let data;
            try {
                data = JSON.parse(text);
                console.log('Parsed data:', data);
            } catch (err) {
                throw new Error('Invalid response format from server');
            }

            if (!response.ok) {
                throw new Error(data.error || 'Server error');
            }

            if (!data.results || typeof data.results !== 'object') {
                throw new Error('Invalid results format from server');
            }

            displayResults(data.results);
        } catch (error) {
            console.error('Error:', error);
            showError(
                url.includes('upload') ? fileError : ipError,
                error.message || 'An error occurred. Please try again.'
            );
        } finally {
            hideLoading();
        }
    }

    // Event Listeners
    ipForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        const formData = new FormData(this);
        await handleFormSubmission('/process_ips', formData);
    });

    fileForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        const formData = new FormData(this);
        await handleFormSubmission('/upload_ip', formData);
    });

    // File input handling
    const fileInput = document.querySelector('input[type="file"]');
    const fileInputLabel = document.querySelector('.file-input p');
    
    fileInput.addEventListener('change', function() {
        const fileName = this.files[0]?.name;
        fileInputLabel.textContent = fileName || 'Click to upload or drag and drop';
        fileError.textContent = '';
    });

    // Download button
    downloadBtn.addEventListener('click', async function() {
        try {
            const response = await fetch('/download_results');
            if (!response.ok) {
                throw new Error('Failed to download results');
            }
            
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'ip_scan_results.xlsx';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } catch (error) {
            console.error('Download error:', error);
            alert('Failed to download results. Please try again.');
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