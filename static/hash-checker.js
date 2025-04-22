document.addEventListener('DOMContentLoaded', function() {
    const hashForm = document.getElementById('hashForm');
    const fileForm = document.getElementById('fileForm');
    const resultsSection = document.querySelector('.results-section');
    const resultsTable = document.querySelector('.results-table tbody');
    const downloadBtn = document.querySelector('.download-btn');

    // Handle manual hash input form submission
    hashForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        const formData = new FormData(this);
        
        try {
            const response = await fetch('/process_hash', {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            
            const results = await response.json();
            displayResults(results);
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred while processing the hashes. Please try again.');
        }
    });

    // Handle file upload form submission
    fileForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        const formData = new FormData(this);
        
        try {
            const response = await fetch('/upload', {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            
            const results = await response.json();
            if (results.error) {
                throw new Error(results.error);
            }
            displayResults(results);
        } catch (error) {
            console.error('Error:', error);
            alert(error.message || 'An error occurred while processing the file. Please try again.');
        }
    });

    // Display results in the table
    function displayResults(results) {
        resultsTable.innerHTML = '';
        if (!Array.isArray(results)) {
            results = [results]; // Convert single result to array
        }
        
        if (results.length === 0) {
            const noResults = document.createElement('tr');
            noResults.innerHTML = `
                <td colspan="4" class="no-results">No results found</td>
            `;
            resultsTable.appendChild(noResults);
            return;
        }
        
        results.forEach((result, index) => {
            const row = document.createElement('tr');
            row.style.animation = `slideIn 0.3s ease-out ${index * 0.1}s forwards`;
            row.style.opacity = '0';
            
            if (result.error) {
                row.innerHTML = `
                    <td class="hash-cell">${result.hash || 'Unknown'}</td>
                    <td class="filename-cell">-</td>
                    <td class="malicious-count" data-count="0">-</td>
                    <td>
                        <div class="details-container">
                            <div class="detail-item undetected">
                                <span>Error</span>
                                <span>${result.error}</span>
                            </div>
                        </div>
                    </td>
                `;
            } else {
                const malicious = parseInt(result.malicious) || 0;
                const suspicious = parseInt(result.suspicious) || 0;
                const harmless = parseInt(result.harmless) || 0;
                const undetected = parseInt(result.undetected) || 0;
                const total = malicious + suspicious + harmless + undetected;
                
                row.innerHTML = `
                    <td class="hash-cell" title="${result.hash}">${result.hash || 'Unknown'}</td>
                    <td class="filename-cell" title="${result.filename || '-'}">${result.filename || '-'}</td>
                    <td class="malicious-count" data-count="${malicious}">${malicious > 0 ? `${malicious}/${total}` : '0'}</td>
                    <td>
                        <div class="details-container">
                            <div class="detail-item malicious">
                                <span>Malicious</span>
                                <span>${malicious}</span>
                            </div>
                            <div class="detail-item suspicious">
                                <span>Suspicious</span>
                                <span>${suspicious}</span>
                            </div>
                            <div class="detail-item harmless">
                                <span>Harmless</span>
                                <span>${harmless}</span>
                            </div>
                            <div class="detail-item undetected">
                                <span>Undetected</span>
                                <span>${undetected}</span>
                            </div>
                        </div>
                    </td>
                `;
            }
            
            resultsTable.appendChild(row);
        });
        
        resultsSection.style.display = 'block';

        // Add keyframe animation for row entrance
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: translateX(-20px);
                }
                to {
                    opacity: 1;
                    transform: translateX(0);
                }
            }
        `;
        document.head.appendChild(style);
    }

    // Handle file input change
    const fileInput = document.querySelector('input[type="file"]');
    if (fileInput) {
        fileInput.addEventListener('change', function() {
            const fileName = this.files[0]?.name;
            if (fileName) {
                document.querySelector('.file-input p').textContent = fileName;
            }
        });
    }

    // Theme toggle functionality
    const themeToggle = document.getElementById('theme-toggle');
    themeToggle.addEventListener('click', function() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
    });

    // Set initial theme
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
}); 