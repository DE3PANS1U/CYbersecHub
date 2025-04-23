// Color palette for different risk levels
const riskColors = {
    note: '#6c757d',
    low: '#28a745',
    medium: '#ffc107',
    high: '#fd7e14',
    critical: '#dc3545'
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
        barLikelihoodBg: isDarkMode ? 'rgba(0, 191, 255, 0.7)' : 'rgba(0, 168, 232, 0.7)', // Primary with alpha
        barLikelihoodBorder: isDarkMode ? '#00BFFF' : '#00A8E8',
        barImpactBg: isDarkMode ? 'rgba(0, 255, 209, 0.7)' : 'rgba(0, 224, 199, 0.7)', // Accent with alpha
        barImpactBorder: isDarkMode ? '#00FFD1' : '#00E0C7',
    };
}

let radarChart, likelihoodImpactChart;

// Initialize charts when the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    try {
        // --- Radar Chart Setup ---
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
                    data: Array(16).fill(0),
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

        // --- Bar Chart Setup ---
        const barCtx = document.getElementById('likelihoodImpactChart');
        if (!barCtx) {
            console.error('Bar chart canvas not found');
            return;
        }
        
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

        // Initialize matrix chart
        if (typeof initMatrixChart === 'function') {
            initMatrixChart();
        }

        // Add event listeners to all select elements
        document.querySelectorAll('select').forEach(select => {
            select.addEventListener('change', calculateRisk);
        });

        // Initial calculation
        calculateRisk();
        
    } catch (error) {
        console.error('Error initializing charts:', error);
    }
});

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
    if (score <= 3) return 'NOTE';
    if (score <= 6) return 'LOW';
    if (score <= 12) return 'MEDIUM';
    if (score <= 20) return 'HIGH';
    return 'CRITICAL';
}

// Main risk calculation function
async function calculateRisk() {
    try {
        // Get all form values
        const formData = {};
        document.querySelectorAll('select').forEach(select => {
            formData[select.id] = parseInt(select.value) || 0;
        });

        // Calculate likelihood factors
        const likelihoodFactors = [
            formData['skill-level'] || 0,
            formData['motive'] || 0,
            formData['opportunity'] || 0,
            formData['size'] || 0,
            formData['ease-of-discovery'] || 0,
            formData['ease-of-exploit'] || 0,
            formData['awareness'] || 0,
            formData['intrusion-detection'] || 0
        ];

        // Calculate impact factors
        const impactFactors = [
            formData['loss-confidentiality'] || 0,
            formData['loss-integrity'] || 0,
            formData['loss-availability'] || 0,
            formData['loss-accountability'] || 0,
            formData['financial-damage'] || 0,
            formData['reputation-damage'] || 0,
            formData['non-compliance'] || 0,
            formData['privacy-violation'] || 0
        ];

        // Calculate average scores
        const likelihoodScore = Math.round(likelihoodFactors.reduce((a, b) => a + b, 0) / likelihoodFactors.length);
        const impactScore = Math.round(impactFactors.reduce((a, b) => a + b, 0) / impactFactors.length);

        // Update radar chart with all factors
        if (radarChart) {
            radarChart.data.datasets[0].data = [
                ...likelihoodFactors,
                ...impactFactors
            ];
            radarChart.update();
        }

        // Update likelihood/impact bar chart
        if (likelihoodImpactChart) {
            likelihoodImpactChart.data.datasets[0].data = [likelihoodScore, impactScore];
            likelihoodImpactChart.update();
        }

        // Determine risk level
        const riskLevel = determineRiskLevel(likelihoodScore, impactScore);

        // Update score displays
        document.getElementById('likelihood-score').textContent = likelihoodScore;
        document.getElementById('impact-score').textContent = impactScore;
        const riskLevelElement = document.getElementById('risk-level');
        if (riskLevelElement) {
            riskLevelElement.textContent = riskLevel.toUpperCase();
            riskLevelElement.className = `risk-level ${riskLevel.toLowerCase()}`;
        }

        // Update matrix chart if available
        if (typeof updateMatrixChart === 'function') {
            updateMatrixChart(likelihoodScore, impactScore, riskLevel);
        }

        // Generate and update mitigation suggestions
        const highRiskFactors = [];
        Object.entries(formData).forEach(([id, value]) => {
            if (value >= 6) { // Consider scores of 6 or higher as high risk
                highRiskFactors.push({
                    name: factorIdToName[id],
                    score: value,
                    suggestion: mitigationSuggestions[id]
                });
            }
        });

        // Update suggestions in the UI
        const suggestionsContainer = document.getElementById('suggestions-list');
        if (suggestionsContainer) {
            if (highRiskFactors.length > 0) {
                const suggestionsList = highRiskFactors.map(factor => `
                    <div class="suggestion-item ${getRiskLevelClass(factor.score)}">
                        <h4>${factor.name} (Score: ${factor.score})</h4>
                        <p>${factor.suggestion}</p>
                    </div>
                `).join('');
                
                suggestionsContainer.innerHTML = suggestionsList;
            } else {
                suggestionsContainer.innerHTML = '<p class="no-suggestions">No high-risk factors identified. Continue monitoring and maintaining current security controls.</p>';
            }
        }

    } catch (error) {
        console.error('Error calculating risk:', error);
        // Show error message to user
        const errorDiv = document.getElementById('error-message');
        if (errorDiv) {
            errorDiv.textContent = 'An error occurred while calculating risk. Please try again.';
            errorDiv.style.display = 'block';
            setTimeout(() => {
                errorDiv.style.display = 'none';
            }, 5000);
        }
    }
}

function getRiskLevelClass(score) {
    if (score >= 8) return 'critical';
    if (score >= 6) return 'high';
    if (score >= 4) return 'medium';
    if (score >= 2) return 'low';
    return 'note';
}

// Theme toggle functionality
document.addEventListener('DOMContentLoaded', function() {
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            html.setAttribute('data-theme', newTheme);
            updateChartTheme();
            updateToggleIcon(newTheme);
        });
    }
});

function updateToggleIcon(theme) {
    const icon = document.querySelector('#theme-toggle i');
    if (icon) {
        icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-shield-alt';
    }
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