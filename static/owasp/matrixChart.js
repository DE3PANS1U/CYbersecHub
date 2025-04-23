// Matrix chart configuration and setup
let matrixChart;

function initMatrixChart() {
    const ctx = document.getElementById('matrixChart');
    if (!ctx) return;

    // Define colors for risk levels
    const colors = {
        note: '#90EE90',    // Light green
        low: '#FFFF00',     // Yellow
        medium: '#FFA500',  // Orange
        high: '#FF0000',    // Red
        critical: '#FF69B4' // Pink for critical
    };

    // Create background data for the matrix cells
    const backgroundData = [];
    const labels = [];
    
    // Matrix data structure (from bottom to top)
    const matrixData = [
        ['Note', 'Low', 'Medium'],      // Low impact
        ['Low', 'Medium', 'High'],      // Medium impact
        ['Medium', 'High', 'Critical']  // High impact
    ];

    // Generate data points for each cell
    for (let i = 0; i < 3; i++) {
        for (let j = 0; j < 3; j++) {
            backgroundData.push({
                x: j + 0.5,
                y: i + 0.5,
                risk: matrixData[2-i][j]
            });
            labels.push(matrixData[2-i][j]);
        }
    }

    // Chart configuration
    matrixChart = new Chart(ctx, {
        type: 'scatter',
        data: {
            datasets: [
                {
                    // Background cells
                    label: 'Risk Zones',
                    data: backgroundData,
                    backgroundColor: function(context) {
                        if (!context.raw) return colors.note;
                        const risk = context.raw.risk.toLowerCase();
                        return colors[risk] || colors.note;
                    },
                    pointRadius: 40,
                    pointStyle: 'rect',
                },
                {
                    // Current position marker
                    label: 'Current Risk',
                    data: [],
                    backgroundColor: 'rgba(0, 0, 0, 0.7)',
                    borderColor: 'white',
                    borderWidth: 2,
                    pointRadius: 8,
                    pointStyle: 'circle',
                    pointHoverRadius: 10
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    min: 0,
                    max: 3,
                    ticks: {
                        stepSize: 1,
                        callback: function(value) {
                            return ['Low', 'Medium', 'High'][value];
                        }
                    },
                    grid: {
                        display: true,
                        color: 'rgba(0, 0, 0, 0.1)'
                    },
                    title: {
                        display: true,
                        text: 'Likelihood',
                        font: { weight: 'bold' }
                    }
                },
                y: {
                    min: 0,
                    max: 3,
                    ticks: {
                        stepSize: 1,
                        callback: function(value) {
                            return ['Low', 'Medium', 'High'][value];
                        }
                    },
                    grid: {
                        display: true,
                        color: 'rgba(0, 0, 0, 0.1)'
                    },
                    title: {
                        display: true,
                        text: 'Impact',
                        font: { weight: 'bold' }
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            if (!context.raw) return '';
                            return `Risk Level: ${context.raw.risk}`;
                        }
                    }
                }
            }
        }
    });

    // Initial update
    updateMatrixPosition();
}

function updateMatrixPosition() {
    if (!matrixChart) return;

    const likelihood = parseFloat(document.getElementById('likelihood-score').textContent);
    const impact = parseFloat(document.getElementById('impact-score').textContent);
    
    // Convert 0-9 scores to 0-3 matrix positions
    const x = Math.min(Math.floor(likelihood / 3), 2) + 0.5;
    const y = Math.min(Math.floor(impact / 3), 2) + 0.5;
    
    // Update current position marker
    matrixChart.data.datasets[1].data = [{
        x: x,
        y: y
    }];
    
    matrixChart.update('none');
}

// Theme update for matrix chart
function updateMatrixChartTheme() {
    try {
        if (!matrixChart) return;
        
        const isDarkMode = document.documentElement.getAttribute('data-theme') === 'dark';
        const textColor = isDarkMode ? '#C9D1D9' : '#1A2A3A';
        const gridColor = isDarkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
        
        // Update text colors
        matrixChart.options.scales.x.ticks.color = textColor;
        matrixChart.options.scales.y.ticks.color = textColor;
        matrixChart.options.scales.x.title.color = textColor;
        matrixChart.options.scales.y.title.color = textColor;
        
        // Update grid colors
        matrixChart.options.scales.x.grid.color = gridColor;
        matrixChart.options.scales.y.grid.color = gridColor;
        
        matrixChart.update();
    } catch (error) {
        console.error('Error updating matrix chart theme:', error);
    }
}

// Initialize when the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    try {
        initMatrixChart();
    } catch (error) {
        console.error('Error in matrix chart initialization:', error);
    }
}); 