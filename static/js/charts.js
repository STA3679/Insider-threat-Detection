// Chart.js helper for Sentinel Dashboard
document.addEventListener("DOMContentLoaded", function() {
    initRiskChart();
});

// Store globally to allow updates
window.riskDoughnut = null;

function getRiskDistributionFromDOM() {
    let lowCount = 0;
    let mediumCount = 0;
    let highCount = 0;
    
    // Select all rows in directory table
    const badgeElements = document.querySelectorAll("#employee-list-tbody tr td .badge");
    badgeElements.forEach(badge => {
        const txt = badge.textContent.trim().toLowerCase();
        if (txt === "low") {
            lowCount++;
        } else if (txt === "medium") {
            mediumCount++;
        } else if (txt === "high") {
            highCount++;
        }
    });
    
    return [lowCount, mediumCount, highCount];
}

function initRiskChart() {
    const canvas = document.getElementById("riskChart");
    if (!canvas) return; // Exit if not on dashboard
    
    const [low, med, high] = getRiskDistributionFromDOM();
    
    const ctx = canvas.getContext("2d");
    window.riskDoughnut = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Low Risk', 'Medium Risk', 'High Risk'],
            datasets: [{
                data: [low, med, high],
                backgroundColor: [
                    'rgba(0, 230, 118, 0.65)',  // Electric Green
                    'rgba(255, 179, 0, 0.65)',  // Warning Amber
                    'rgba(255, 23, 68, 0.65)'    // Alert Crimson
                ],
                borderColor: [
                    '#00e676',
                    '#ffb300',
                    '#ff1744'
                ],
                borderWidth: 1.5,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#9ca3af',
                        padding: 15,
                        font: {
                            family: "'Inter', sans-serif",
                            size: 11
                        }
                    }
                }
            },
            cutout: '65%'
        }
    });
}

// Function to refresh chart data
window.updateRiskChart = function() {
    if (!window.riskDoughnut) return;
    
    const [low, med, high] = getRiskDistributionFromDOM();
    window.riskDoughnut.data.datasets[0].data = [low, med, high];
    window.riskDoughnut.update();
};
