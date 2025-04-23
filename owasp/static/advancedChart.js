// Chart configuration
const chartConfig = {
    type: 'radar',
    data: {
        labels: [
            'Skill Level',
            'Motive',
            'Opportunity',
            'Size',
            'Ease of Discovery',
            'Ease of Exploit',
            'Awareness',
            'Intrusion Detection',
            'Loss of Confidentiality',
            'Loss of Integrity',
            'Loss of Availability',
            'Loss of Accountability',
            'Financial Damage',
            'Reputation Damage',
            'Non-Compliance',
            'Privacy Violation'
        ],
        datasets: [{
            label: 'Risk Factors',
            data: Array(16).fill(0),
            backgroundColor: 'rgba(54, 162, 235, 0.2)',
            borderColor: 'rgba(54, 162, 235, 1)',
            borderWidth: 2,
            pointBackgroundColor: 'rgba(54, 162, 235, 1)',
            pointBorderColor: '#fff',
            pointHoverBackgroundColor: '#fff',
            pointHoverBorderColor: 'rgba(54, 162, 235, 1)'
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            r: {
                beginAtZero: true,
                max: 9,
                ticks: {
                    stepSize: 1,
                    color: '#333333'
                },
                pointLabels: {
                    color: '#333333'
                },
                grid: {
                    color: 'rgba(0, 0, 0, 0.1)'
                },
                angleLines: {
                    color: 'rgba(0, 0, 0, 0.2)'
                }
            }
        },
        plugins: {
            legend: {
                labels: {
                    color: '#333333'
                }
            }
        },
        animation: {
            duration: 500,
            easing: 'easeInOutQuart'
        }
    }
};

// Initialize chart
let chart = new Chart(document.getElementById('riskChart'), chartConfig); 