// Sentinel Live Event Simulator Interaction Logic
document.addEventListener("DOMContentLoaded", function() {
    initSimulator();
});

let simIntervalId = null;

function initSimulator() {
    const btnStart = document.getElementById("btn-start-sim");
    const btnStop = document.getElementById("btn-stop-sim");
    const btnInject = document.getElementById("btn-inject-threat");
    
    if (!btnStart) return; // Exit if not on dashboard page
    
    btnStart.addEventListener("click", startSimulation);
    btnStop.addEventListener("click", stopSimulation);
    btnInject.addEventListener("click", injectThreat);
}

function startSimulation() {
    document.getElementById("btn-start-sim").disabled = true;
    document.getElementById("btn-stop-sim").disabled = false;
    
    writeToConsole("[SYSTEM] Stream initialized. Polling logs at 2.5s interval...", "system");
    
    // Poll every 2.5 seconds
    simIntervalId = setInterval(fetchSimEvent, 2500);
}

function stopSimulation() {
    document.getElementById("btn-start-sim").disabled = false;
    document.getElementById("btn-stop-sim").disabled = true;
    
    writeToConsole("[SYSTEM] Stream paused by administrator.", "system");
    
    if (simIntervalId) {
        clearInterval(simIntervalId);
        simIntervalId = null;
    }
}

function writeToConsole(message, type = "normal") {
    const consoleBox = document.getElementById("sim-console");
    if (!consoleBox) return;
    
    const timeStr = new Date().toLocaleTimeString();
    const entry = document.createElement("div");
    entry.className = "console-entry";
    
    if (type === "warn" || type === "Suspicious") {
        entry.className += " warn";
    } else if (type === "err" || type === "Threat") {
        entry.className += " err";
    }
    
    entry.innerText = `[${timeStr}] ${message}`;
    consoleBox.appendChild(entry);
    
    // Scroll to bottom
    consoleBox.scrollTop = consoleBox.scrollHeight;
}

function fetchSimEvent() {
    fetch("/api/sim_event")
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                writeToConsole(`[ERROR] ${data.error}`, "err");
                return;
            }
            
            // Format log message
            const logMsg = `${data.employee_id} (${data.name}) - ${data.detail_desc} -> Prediction: ${data.prediction} (${data.confidence}%)`;
            writeToConsole(logMsg, data.prediction);
            
            // Process threat alerts
            if (data.prediction !== "Normal") {
                triggerAlert(data);
            }
            
            // Update employees table and risk badges in DOM
            updateEmployeeRow(data.employee_id, data.dev_score, data.prediction);
        })
        .catch(err => {
            writeToConsole(`[ERROR] Network anomaly: ${err.message}`, "err");
        });
}

function injectThreat() {
    const btnInject = document.getElementById("btn-inject-threat");
    btnInject.disabled = true;
    
    writeToConsole("[SYSTEM] Manually injecting high-severity threat signature...", "err");
    
    fetch("/api/inject_threat", { method: "POST" })
        .then(response => response.json())
        .then(data => {
            btnInject.disabled = false;
            
            if (data.error) {
                writeToConsole(`[ERROR] Injection failed: ${data.error}`, "err");
                return;
            }
            
            const logMsg = `[INJECTED] ${data.employee_id} (${data.name}) - ${data.detail_desc} -> Prediction: ${data.prediction} (${data.confidence}%)`;
            writeToConsole(logMsg, "Threat");
            
            // Inject threat triggers alert
            triggerAlert(data);
            
            // Update table
            updateEmployeeRow(data.employee_id, data.dev_score, data.prediction);
        })
        .catch(err => {
            btnInject.disabled = false;
            writeToConsole(`[ERROR] Connection failed: ${err.message}`, "err");
        });
}

function triggerAlert(alertData) {
    const alertsContainer = document.getElementById("dashboard-alerts");
    const noAlertsMsg = document.getElementById("no-alerts-msg");
    
    if (noAlertsMsg) {
        noAlertsMsg.remove();
    }
    
    // Create new alert node
    const alertItem = document.createElement("div");
    alertItem.className = `alert-item ${alertData.prediction === 'Suspicious' ? 'medium' : ''}`;
    
    const iconClass = alertData.prediction === 'Suspicious' ? 'fa-eye-slash' : 'fa-triangle-exclamation';
    const iconColor = alertData.prediction === 'Suspicious' ? 'var(--color-medium)' : 'var(--color-high)';
    
    const alertType = alertData.prediction === 'Suspicious' ? 'Suspicious Behavior' : 'Insider Threat';
    const nowStr = new Date().toLocaleString();
    
    alertItem.innerHTML = `
        <div style="font-size: 1.25rem; color: ${iconColor}; margin-top: 2px;">
            <i class="fa-solid ${iconClass}"></i>
        </div>
        <div class="alert-content">
            <div style="display: flex; justify-content: space-between; font-weight: 600;">
                <span>${alertData.employee_id} (Score: ${alertData.dev_score})</span>
                <span style="font-size: 0.75rem; color: var(--text-muted);">${alertType}</span>
            </div>
            <p style="font-size: 0.85rem; margin-top: 0.25rem; color: var(--text-primary);">${alertData.explanation}</p>
            <div class="alert-meta">Incident Logged at: ${nowStr}</div>
        </div>
    `;
    
    // Prepend to alerts log
    alertsContainer.insertBefore(alertItem, alertsContainer.firstChild);
    
    // Update summary counts in KPI boxes
    updateAlertCounts(alertData.prediction);
}

function updateAlertCounts(prediction) {
    if (prediction === "Threat") {
        const countEl = document.getElementById("high-threat-count");
        if (countEl) {
            let cnt = parseInt(countEl.innerText);
            countEl.innerText = cnt + 1;
        }
    } else if (prediction === "Suspicious") {
        const countEl = document.getElementById("medium-threat-count");
        if (countEl) {
            let cnt = parseInt(countEl.innerText);
            countEl.innerText = cnt + 1;
        }
    }
}

function updateEmployeeRow(empId, score, prediction) {
    // Find the row in table by checking column 1 value
    const tableRows = document.querySelectorAll("#employee-list-tbody tr");
    let rowFound = null;
    
    tableRows.forEach(row => {
        const firstCol = row.querySelector("td strong");
        if (firstCol && firstCol.textContent.trim() === empId) {
            rowFound = row;
        }
    });
    
    if (rowFound) {
        // Update Score Column (Index 3, 0-indexed: ID=0, Name=1, Dept=2, Score=3, Level=4)
        const cells = rowFound.querySelectorAll("td");
        if (cells.length >= 5) {
            cells[3].querySelector("span").innerText = score;
            
            // Map prediction to Risk level text and badge class
            let riskLvl = "Low";
            let badgeClass = "badge badge-low";
            
            if (prediction === "Threat") {
                riskLvl = "High";
                badgeClass = "badge badge-high";
            } else if (prediction === "Suspicious") {
                riskLvl = "Medium";
                badgeClass = "badge badge-medium";
            }
            
            // Update badge cell
            const badgeContainer = cells[4];
            badgeContainer.innerHTML = `<span class="${badgeClass}">${riskLvl}</span>`;
            
            // Trigger visual highlight row flash
            rowFound.style.transition = "background-color 0.5s ease";
            rowFound.style.backgroundColor = prediction === "Threat" ? "rgba(255, 23, 68, 0.15)" : prediction === "Suspicious" ? "rgba(255, 179, 0, 0.15)" : "rgba(0, 230, 118, 0.1)";
            setTimeout(() => {
                rowFound.style.backgroundColor = "";
            }, 1000);
            
            // Refresh risk Chart distribution
            if (window.updateRiskChart) {
                window.updateRiskChart();
            }
        }
    }
}
