// Color palette for different risk levels
const riskColors = {
    note: '#6c757d',
    low: '#28a745',
    medium: '#ffc107',
    high: '#fd7e14',
    critical: '#dc3545'
};

// Chart colors for themes
const chartColors = {
    light: {
        background: 'rgba(255, 255, 255, 0.9)',
        text: '#333',
        grid: '#ddd',
        point: '#2196F3',
        line: 'rgba(33, 150, 243, 0.6)'
    },
    dark: {
        background: 'rgba(26, 26, 26, 0.9)',
        text: '#fff',
        grid: '#444',
        point: '#2196F3',
        line: 'rgba(33, 150, 243, 0.6)'
    }
};

// Add risk level colors at the top of the file
const riskLevelColors = {
    NOTE: { bg: '#90EE90', text: '#000000' },    // Light green
    LOW: { bg: '#FFFF00', text: '#000000' },     // Yellow
    MEDIUM: { bg: '#FFA500', text: '#FFFFFF' },  // Orange
    HIGH: { bg: '#FF0000', text: '#FFFFFF' },    // Red
    CRITICAL: { bg: '#FF69B4', text: '#FFFFFF' } // Pink
};

// --- Helper to get theme-aware chart colors ---
function getChartColors() {
    const style = getComputedStyle(document.documentElement);
    const isDarkMode = document.documentElement.getAttribute('data-theme') === 'dark';
    return {
        primary: style.getPropertyValue('--owasp-primary').trim() || '#00A8E8',
        accent: style.getPropertyValue('--owasp-accent').trim() || '#00E0C7',
        text: style.getPropertyValue('--owasp-text').trim() || '#1A2A3A',
        grid: isDarkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)',
        barLikelihoodBg: isDarkMode ? 'rgba(0, 191, 255, 0.7)' : 'rgba(0, 168, 232, 0.7)',
        barLikelihoodBorder: isDarkMode ? '#00BFFF' : '#00A8E8',
        barImpactBg: isDarkMode ? 'rgba(0, 255, 209, 0.7)' : 'rgba(0, 224, 199, 0.7)',
        barImpactBorder: isDarkMode ? '#00FFD1' : '#00E0C7',
    };
}

let radarChart, likelihoodImpactChart;

// Theme switching functionality
function initializeTheme() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
}

function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeIcon(newTheme);
    
    // Update charts
    updateChartTheme();
    if (typeof updateMatrixChartTheme === 'function') {
        updateMatrixChartTheme();
    }
}

function updateThemeIcon(theme) {
    const icon = document.querySelector('#theme-toggle i');
    if (icon) {
        icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-shield-alt';
    }
}

// Initialize charts when the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeTheme();
    initializeCharts();
    setupEventListeners();
});

function initializeCharts() {
    try {
        initializeRadarChart();
        initializeLikelihoodImpactChart();
        
        // Initialize matrix chart if available
        if (typeof initMatrixChart === 'function') {
            initMatrixChart();
        }
        
        // Initial calculation
        calculateRisk();
    } catch (error) {
        console.error('Error initializing charts:', error);
    }
}

function initializeRadarChart() {
    const radarCtx = document.getElementById('myChart');
    if (!radarCtx) {
        console.error('Radar chart canvas not found');
        return;
    }
    
    let chartColors = getChartColors();
    radarChart = new Chart(radarCtx.getContext('2d'), {
        type: 'radar',
        data: {
            labels: [
                'Skill Level', 'Motive', 'Opportunity', 'Size',
                'Ease of Discovery', 'Ease of Exploit', 'Awareness', 'Intrusion Detection',
                'Loss of Confidentiality', 'Loss of Integrity', 'Loss of Availability', 'Loss of Accountability',
                'Financial Damage', 'Reputation Damage', 'Non-compliance', 'Privacy Violation'
            ],
            datasets: [{
                label: 'Risk Factors',
                data: Array(16).fill(1),
                backgroundColor: 'rgba(0, 168, 232, 0.2)',
                borderColor: chartColors.primary,
                borderWidth: 2,
                pointBackgroundColor: chartColors.primary,
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: chartColors.primary,
                pointRadius: 3,
                pointHoverRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                r: {
                    beginAtZero: true,
                    max: 9,
                    ticks: {
                        stepSize: 1,
                        backdropColor: 'transparent',
                        color: chartColors.text
                    },
                    grid: { color: chartColors.grid },
                    angleLines: { color: chartColors.grid },
                    pointLabels: {
                        font: { size: 12 },
                        color: chartColors.text
                    }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: { callbacks: { label: function(context) { return `Score: ${context.raw}`; } } }
            }
        }
    });
}

function initializeLikelihoodImpactChart() {
    const barCtx = document.getElementById('likelihoodImpactChart');
    if (!barCtx) {
        console.error('Bar chart canvas not found');
        return;
    }
    
    let chartColors = getChartColors();
    likelihoodImpactChart = new Chart(barCtx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['Likelihood', 'Impact'],
            datasets: [{
                label: 'Calculated Score',
                data: [0, 0],
                backgroundColor: [
                    chartColors.barLikelihoodBg,
                    chartColors.barImpactBg
                ],
                borderColor: [
                    chartColors.barLikelihoodBorder,
                    chartColors.barImpactBorder
                ],
                borderWidth: 1,
                borderRadius: 4,
                barThickness: 30
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            indexAxis: 'y',
            scales: {
                x: {
                    beginAtZero: true,
                    max: 9,
                    grid: { color: chartColors.grid },
                    ticks: { color: chartColors.text }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: chartColors.text }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function setupEventListeners() {
    // Add change event listeners to all select elements
    document.querySelectorAll('select').forEach(select => {
        select.addEventListener('change', calculateRisk);
    });

    // Set up theme toggle
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }
}

// Main risk calculation function
async function calculateRisk() {
    try {
        // Get all form values
        const form = document.getElementById('risk-form');
        const formData = new FormData(form);
        
        // Calculate scores
        const likelihood = calculateLikelihoodScore();
        const impact = calculateImpactScore();
        const riskLevel = determineRiskLevel(likelihood, impact);
        
        // Update UI with calculated values
        document.getElementById('likelihood-score').textContent = likelihood.toFixed(1);
        document.getElementById('impact-score').textContent = impact.toFixed(1);
        document.getElementById('risk-level').textContent = riskLevel;
        
        // Get all factor values for suggestions
        const factorValues = {};
        form.querySelectorAll('select').forEach(select => {
            factorValues[select.id] = parseInt(select.value);
        });
        
        // Update charts and suggestions
        updateCharts(likelihood, impact, riskLevel, Array.from(formData.values()).map(Number));
        if (typeof updateSuggestions === 'function') {
            updateSuggestions(factorValues);
        }
        
    } catch (error) {
        console.error('Error calculating risk:', error);
        showError('Error calculating risk. Please try again.');
    }
}

function updateCharts(likelihood, impact, riskLevel, factorValues) {
    // Update radar chart
    if (radarChart) {
        radarChart.data.datasets[0].data = factorValues;
        radarChart.update();
    }

    // Update likelihood vs impact chart
    if (likelihoodImpactChart) {
        likelihoodImpactChart.data.datasets[0].data = [likelihood, impact];
        likelihoodImpactChart.update();
    }

    // Update matrix chart
    if (typeof updateMatrixChart === 'function') {
        updateMatrixChart(likelihood, impact, riskLevel);
    }
}

function showError(message) {
    const errorMessage = document.getElementById('error-message');
    if (errorMessage) {
        errorMessage.textContent = message;
        errorMessage.style.display = 'block';
        setTimeout(() => {
            errorMessage.style.display = 'none';
        }, 5000);
    }
}

// --- Factor ID to Name Mapping (for suggestions) ---
const factorIdToName = {
    'skill-level': 'Skill Level',
    'motive': 'Motive',
    'opportunity': 'Opportunity',
    'size': 'Size',
    'ease-of-discovery': 'Ease of Discovery',
    'ease-of-exploit': 'Ease of Exploit',
    'awareness': 'Awareness',
    'intrusion-detection': 'Intrusion Detection',
    'loss-confidentiality': 'Loss of Confidentiality',
    'loss-integrity': 'Loss of Integrity',
    'loss-availability': 'Loss of Availability',
    'loss-accountability': 'Loss of Accountability',
    'financial-damage': 'Financial Damage',
    'reputation-damage': 'Reputation Damage',
    'non-compliance': 'Non-compliance',
    'privacy-violation': 'Privacy Violation'
};

// --- Mitigation Suggestions Mapping ---
const mitigationSuggestions = {
    // Threat Agent Mitigations (General)
    'skill-level': "Consider threat modeling focusing on sophisticated attackers. Implement multi-factor authentication (MFA) and robust authorization.",
    'motive': "Reduce the potential reward for attackers (e.g., minimize sensitive data storage, implement fraud detection).",
    'opportunity': " Harden system access controls, reduce attack surface, apply patches promptly, implement network segmentation.",
    'size': "Implement stricter controls for larger, less trusted user groups (e.g., public internet access).",
    // Vulnerability Mitigations
    'ease-of-discovery': "Use secure coding practices (OWASP Top 10), conduct regular code reviews and security testing (SAST/DAST/Pentest) to find vulnerabilities before attackers do.",
    'ease-of-exploit': "Prioritize fixing easily exploitable vulnerabilities. Implement input validation, output encoding, and parameterized queries. Use web application firewalls (WAFs).",
    'awareness': "Improve security awareness training. Use tools to identify public disclosures (CVEs, exploits) related to your stack.",
    'intrusion-detection': "Implement robust logging and monitoring (SIEM). Set up alerts for suspicious activities. Use Intrusion Detection/Prevention Systems (IDS/IPS).",
    // Impact Mitigations (Technical)
    'loss-confidentiality': "Encrypt sensitive data at rest and in transit. Implement strong access controls (least privilege). Sanitize data before display/logging.",
    'loss-integrity': "Use data validation, checksums, digital signatures, and version control. Implement secure session management. Perform regular backups.",
    'loss-availability': "Implement redundancy, load balancing, and failover mechanisms. Use DDoS protection services. Perform regular backups and disaster recovery planning.",
    'loss-accountability': "Ensure comprehensive and tamper-proof logging of user actions and system events. Correlate logs across systems.",
    // Impact Mitigations (Business)
    'financial-damage': "Implement fraud detection and prevention measures. Have incident response plans to minimize downtime and recovery costs. Consider cyber insurance.",
    'reputation-damage': "Have a clear communication plan for security incidents. Be transparent with affected parties (within legal bounds). Invest in proactive security to build trust.",
    'non-compliance': "Understand and implement relevant regulatory requirements (GDPR, HIPAA, PCI-DSS, etc.). Conduct regular compliance audits.",
    'privacy-violation': "Implement data minimization principles. Encrypt or anonymize Personally Identifiable Information (PII). Provide clear privacy policies and user controls."
};

// Helper functions for risk calculation
function calculateLikelihoodScore() {
    const threatAgentFactors = [
        parseFloat(document.getElementById('skill-level').value),
        parseFloat(document.getElementById('motive').value),
        parseFloat(document.getElementById('opportunity').value),
        parseFloat(document.getElementById('size').value)
    ];

    const vulnerabilityFactors = [
        parseFloat(document.getElementById('ease-of-discovery').value),
        parseFloat(document.getElementById('ease-of-exploit').value),
        parseFloat(document.getElementById('awareness').value),
        parseFloat(document.getElementById('intrusion-detection').value)
    ];

    const threatAgentScore = threatAgentFactors.reduce((a, b) => a + b, 0) / threatAgentFactors.length;
    const vulnerabilityScore = vulnerabilityFactors.reduce((a, b) => a + b, 0) / vulnerabilityFactors.length;

    return (threatAgentScore + vulnerabilityScore) / 2;
}

function calculateImpactScore() {
    const technicalImpactFactors = [
        parseFloat(document.getElementById('loss-confidentiality').value),
        parseFloat(document.getElementById('loss-integrity').value),
        parseFloat(document.getElementById('loss-availability').value),
        parseFloat(document.getElementById('loss-accountability').value)
    ];

    const businessImpactFactors = [
        parseFloat(document.getElementById('financial-damage').value),
        parseFloat(document.getElementById('reputation-damage').value),
        parseFloat(document.getElementById('non-compliance').value),
        parseFloat(document.getElementById('privacy-violation').value)
    ];

    const technicalScore = technicalImpactFactors.reduce((a, b) => a + b, 0) / technicalImpactFactors.length;
    const businessScore = businessImpactFactors.reduce((a, b) => a + b, 0) / businessImpactFactors.length;

    return (technicalScore + businessScore) / 2;
}

function determineRiskLevel(likelihood, impact) {
    const score = likelihood * impact;
    let level;
    
    if (score <= 3) level = 'NOTE';
    else if (score <= 6) level = 'LOW';
    else if (score <= 12) level = 'MEDIUM';
    else if (score <= 20) level = 'HIGH';
    else level = 'CRITICAL';

    // Update the risk level display with appropriate colors
    const riskLevelElement = document.getElementById('risk-level');
    if (riskLevelElement) {
        riskLevelElement.textContent = level;
        riskLevelElement.style.backgroundColor = riskLevelColors[level].bg;
        riskLevelElement.style.color = riskLevelColors[level].text;
        
        // Remove all existing risk classes
        riskLevelElement.classList.remove('note', 'low', 'medium', 'high', 'critical');
        // Add the current risk class
        riskLevelElement.classList.add(level.toLowerCase());
    }

    return level;
}

function updateChartTheme() {
    const chartColors = getChartColors();
    
    // Update radar chart colors
    radarChart.data.datasets[0].borderColor = chartColors.primary;
    radarChart.data.datasets[0].pointBackgroundColor = chartColors.primary;
    radarChart.data.datasets[0].pointHoverBorderColor = chartColors.primary;
    radarChart.options.scales.r.ticks.color = chartColors.text;
    radarChart.options.scales.r.grid.color = chartColors.grid;
    radarChart.options.scales.r.angleLines.color = chartColors.grid;
    radarChart.options.scales.r.pointLabels.color = chartColors.text;
    radarChart.update();

    // Update bar chart colors
    likelihoodImpactChart.data.datasets[0].backgroundColor = [
        chartColors.barLikelihoodBg,
        chartColors.barImpactBg
    ];
    likelihoodImpactChart.data.datasets[0].borderColor = [
        chartColors.barLikelihoodBorder,
        chartColors.barImpactBorder
    ];
    likelihoodImpactChart.options.scales.x.grid.color = chartColors.grid;
    likelihoodImpactChart.options.scales.x.ticks.color = chartColors.text;
    likelihoodImpactChart.options.scales.y.ticks.color = chartColors.text;
    likelihoodImpactChart.update();
} 