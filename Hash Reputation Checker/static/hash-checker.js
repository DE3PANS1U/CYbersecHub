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
            const response = await fetch('/process_hashes', {
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
            displayResults(results);
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred while processing the file. Please try again.');
        }
    });

    // Display results in the table
    function displayResults(results) {
        resultsTable.innerHTML = '';
        results.forEach(result => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${result.hash}</td>
                <td>${result.malicious}</td>
                <td>${result.details}</td>
            `;
            resultsTable.appendChild(row);
        });
        
        resultsSection.style.display = 'block';
    }

    // Handle file input change
    const fileInput = document.querySelector('input[type="file"]');
    fileInput.addEventListener('change', function() {
        const fileName = this.files[0]?.name;
        if (fileName) {
            document.querySelector('.file-input p').textContent = fileName;
        }
    });

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