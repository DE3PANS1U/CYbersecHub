// Risk matrix configuration
const riskMatrixConfig = {
    type: 'scatter',
    data: {
        datasets: [
            {
                label: 'Risk Zones',
                data: [
                    {x: 0, y: 0, v: 'NOTE'},
                    {x: 3, y: 3, v: 'LOW'},
                    {x: 6, y: 6, v: 'MEDIUM'},
                    {x: 9, y: 9, v: 'HIGH'}
                ],
                backgroundColor: 'rgba(0, 0, 0, 0.1)',
                borderColor: 'rgba(0, 0, 0, 0.2)',
                borderWidth: 1,
                pointRadius: 0,
                showLine: true,
                fill: false
            },
            {
                label: 'Current Risk',
                data: [],
                backgroundColor: function(context) {
                    if (!context.raw) return 'rgba(0, 0, 0, 1)';
                    const riskLevel = context.raw.v;
                    switch(riskLevel) {
                        case 'CRITICAL': return 'rgba(220, 53, 69, 1)';
                        case 'HIGH': return 'rgba(255, 193, 7, 1)';
                        case 'MEDIUM': return 'rgba(0, 123, 255, 1)';
                        case 'LOW': return 'rgba(40, 167, 69, 1)';
                        case 'NOTE': return 'rgba(108, 117, 125, 1)';
                        default: return 'rgba(0, 0, 0, 1)';
                    }
                },
                borderColor: 'white',
                borderWidth: 2,
                pointRadius: 8,
                pointHoverRadius: 12
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: false
            },
            tooltip: {
                callbacks: {
                    label: function(context) {
                        if (!context.raw) return '';
                        return [
                            `Risk Level: ${context.raw.v}`,
                            `Likelihood: ${context.raw.x.toFixed(1)}`,
                            `Impact: ${context.raw.y.toFixed(1)}`
                        ];
                    }
                }
            }
        },
        scales: {
            x: {
                type: 'linear',
                min: 0,
                max: 9,
                title: {
                    display: true,
                    text: 'Likelihood'
                },
                grid: {
                    display: true,
                    color: 'rgba(0, 0, 0, 0.1)'
                }
            },
            y: {
                type: 'linear',
                min: 0,
                max: 9,
                title: {
                    display: true,
                    text: 'Impact'
                },
                grid: {
                    display: true,
                    color: 'rgba(0, 0, 0, 0.1)'
                }
            }
        }
    }
};

let matrixChart;

// Initialize matrix chart
function initMatrixChart() {
    try {
        console.log('Initializing matrix chart...');
        const ctx = document.getElementById('matrixChart');
        if (!ctx) {
            console.error('Matrix chart canvas not found');
            return;
        }
        
        // Set a fixed size for the canvas container
        const container = ctx.parentElement;
        if (container) {
            container.style.height = '400px';
            container.style.width = '100%';
        }
        
        matrixChart = new Chart(ctx, riskMatrixConfig);
        console.log('Matrix chart initialized successfully');
        
        // Initial update with default values
        updateMatrixChart(1, 1, 'NOTE');
    } catch (error) {
        console.error('Error initializing matrix chart:', error);
    }
}

// Update matrix chart with current risk level
function updateMatrixChart(likelihood, impact, riskLevel) {
    try {
        console.log('Updating matrix chart with:', {likelihood, impact, riskLevel});
        if (!matrixChart) {
            console.warn('Matrix chart not initialized, initializing now...');
            initMatrixChart();
            return;
        }
        
        // Update the current risk point data
        matrixChart.data.datasets[1].data = [{
            x: likelihood,
            y: impact,
            v: riskLevel
        }];
        
        // Update chart
        matrixChart.update('none');
        console.log('Matrix chart updated successfully');
    } catch (error) {
        console.error('Error updating matrix chart:', error);
    }
}

// Theme update for matrix chart
function updateMatrixChartTheme() {
    try {
        console.log('Updating matrix chart theme...');
        if (!matrixChart) {
            console.error('Matrix chart not initialized');
            return;
        }
        
        const isDarkMode = document.documentElement.getAttribute('data-theme') === 'dark';
        const textColor = isDarkMode ? '#C9D1D9' : '#1A2A3A';
        
        matrixChart.options.scales.x.ticks.color = textColor;
        matrixChart.options.scales.y.ticks.color = textColor;
        matrixChart.options.scales.x.title.color = textColor;
        matrixChart.options.scales.y.title.color = textColor;
        matrixChart.options.plugins.legend.labels.color = textColor;
        matrixChart.update();
        console.log('Matrix chart theme updated successfully');
    } catch (error) {
        console.error('Error updating matrix chart theme:', error);
    }
}

// Initialize when the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    try {
        console.log('DOM loaded, initializing matrix chart...');
        initMatrixChart();
    } catch (error) {
        console.error('Error in matrix chart initialization:', error);
    }
}); 