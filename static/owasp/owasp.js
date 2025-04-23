document.addEventListener('DOMContentLoaded', function() {
    // Theme toggle functionality
    const themeToggle = document.getElementById('theme-toggle');
    const body = document.body;
    
    // Check for saved theme preference
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        body.setAttribute('data-theme', savedTheme);
        updateThemeIcon(savedTheme);
    }

    themeToggle.addEventListener('click', () => {
        const currentTheme = body.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        body.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateThemeIcon(newTheme);
    });

    function updateThemeIcon(theme) {
        const icon = themeToggle.querySelector('i');
        icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-shield-alt';
    }

    // Get all select elements
    const selects = document.querySelectorAll('select');
    
    // Add change event listeners to all selects
    selects.forEach(select => {
        select.addEventListener('change', calculateRisk);
    });

    // Initialize chart
    const ctx = document.getElementById('riskChart').getContext('2d');
    let riskChart = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: ['Threat Agent', 'Vulnerability', 'Technical Impact', 'Business Impact'],
            datasets: [{
                label: 'Risk Factors',
                data: [0, 0, 0, 0],
                backgroundColor: 'rgba(54, 162, 235, 0.2)',
                borderColor: 'rgba(54, 162, 235, 1)',
                pointBackgroundColor: 'rgba(54, 162, 235, 1)',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: 'rgba(54, 162, 235, 1)'
            }]
        },
        options: {
            scales: {
                r: {
                    beginAtZero: true,
                    max: 9
                }
            }
        }
    });

    function calculateRisk() {
        // Calculate Threat Agent Factors
        const threatAgentFactors = [
            parseInt(document.getElementById('skill-level').value),
            parseInt(document.getElementById('motive').value),
            parseInt(document.getElementById('opportunity').value),
            parseInt(document.getElementById('size').value)
        ];
        const threatAgentScore = threatAgentFactors.reduce((a, b) => a + b, 0) / threatAgentFactors.length;

        // Calculate Vulnerability Factors
        const vulnerabilityFactors = [
            parseInt(document.getElementById('ease-of-discovery').value),
            parseInt(document.getElementById('ease-of-exploit').value),
            parseInt(document.getElementById('awareness').value),
            parseInt(document.getElementById('intrusion-detection').value)
        ];
        const vulnerabilityScore = vulnerabilityFactors.reduce((a, b) => a + b, 0) / vulnerabilityFactors.length;

        // Calculate Technical Impact Factors
        const technicalImpactFactors = [
            parseInt(document.getElementById('loss-of-confidentiality').value),
            parseInt(document.getElementById('loss-of-integrity').value),
            parseInt(document.getElementById('loss-of-availability').value),
            parseInt(document.getElementById('loss-of-accountability').value)
        ];
        const technicalImpactScore = technicalImpactFactors.reduce((a, b) => a + b, 0) / technicalImpactFactors.length;

        // Calculate Business Impact Factors
        const businessImpactFactors = [
            parseInt(document.getElementById('financial-damage').value),
            parseInt(document.getElementById('reputation-damage').value),
            parseInt(document.getElementById('non-compliance').value),
            parseInt(document.getElementById('privacy-violation').value)
        ];
        const businessImpactScore = businessImpactFactors.reduce((a, b) => a + b, 0) / businessImpactFactors.length;

        // Calculate Likelihood and Impact
        const likelihood = (threatAgentScore + vulnerabilityScore) / 2;
        const impact = (technicalImpactScore + businessImpactScore) / 2;
        const overallRisk = likelihood * impact;

        // Update scores in the UI
        document.getElementById('likelihood-score').textContent = likelihood.toFixed(2);
        document.getElementById('impact-score').textContent = impact.toFixed(2);
        document.getElementById('overall-risk-score').textContent = overallRisk.toFixed(2);

        // Update risk level
        const riskLevel = document.getElementById('risk-level');
        if (overallRisk <= 3) {
            riskLevel.textContent = 'Low';
            riskLevel.style.color = '#4CAF50';
        } else if (overallRisk <= 6) {
            riskLevel.textContent = 'Medium';
            riskLevel.style.color = '#FFC107';
        } else {
            riskLevel.textContent = 'High';
            riskLevel.style.color = '#F44336';
        }

        // Update chart
        riskChart.data.datasets[0].data = [
            threatAgentScore,
            vulnerabilityScore,
            technicalImpactScore,
            businessImpactScore
        ];
        riskChart.update();
    }

    // Initial calculation
    calculateRisk();
}); 