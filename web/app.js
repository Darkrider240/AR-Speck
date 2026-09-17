// AR-SPECK Web Presentation Dashboard JavaScript

let pollingInterval = null;
let lastLogCount = 0;

document.addEventListener("DOMContentLoaded", () => {
    initBitmapGrid();
    startPolling();
});

// Tab Switching
function switchTab(tabName) {
    document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(content => content.classList.remove("active"));

    if (tabName === "simulation") {
        document.querySelectorAll(".tab-btn")[0].classList.add("active");
        document.getElementById("tab-simulation").classList.add("active");
    } else {
        document.querySelectorAll(".tab-btn")[1].classList.add("active");
        document.getElementById("tab-explainer").classList.add("active");
    }
}

// Initialize 64 Bit Grid
function initBitmapGrid() {
    const grid = document.getElementById("bitmap-grid");
    grid.innerHTML = "";
    for (let i = 0; i < 64; i++) {
        const cell = document.createElement("div");
        cell.className = "bit-cell";
        cell.id = `bit-cell-${i}`;
        cell.innerText = i;
        grid.appendChild(cell);
    }
}

// Start Live Polling (500ms)
function startPolling() {
    fetchStatus();
    fetchLogs();
    pollingInterval = setInterval(() => {
        fetchStatus();
        fetchLogs();
    }, 500);
}

// Fetch Server Status & Bitmap State
async function fetchStatus() {
    try {
        const res = await fetch("/api/status");
        if (!res.ok) return;
        const data = await res.json();

        document.getElementById("kpi-total").innerText = data.total_packets.toLocaleString();
        document.getElementById("kpi-accepted").innerText = data.accepted.toLocaleString();
        document.getElementById("kpi-bad-mac").innerText = data.bad_mac_drops.toLocaleString();
        document.getElementById("kpi-replay").innerText = (data.replay_drops + data.too_old_drops).toLocaleString();

        // Update Sliding Window Grid
        const windows = data.windows;
        const clientAddrs = Object.keys(windows);
        if (clientAddrs.length > 0) {
            const firstWin = windows[clientAddrs[0]];
            const maxSeq = firstWin.max_seq;
            const binStr = firstWin.bitmap_bin; // 64-character binary string MSB to LSB

            document.getElementById("window-range-text").innerText = 
                `Max Seq: ${maxSeq} | Window Range: [${Math.max(0, maxSeq - 63)} .. ${maxSeq}]`;

            // Update 64 bit cells
            for (let i = 0; i < 64; i++) {
                const cell = document.getElementById(`bit-cell-${i}`);
                const bitVal = binStr[i]; // '1' or '0'
                if (bitVal === '1') {
                    cell.classList.add("set");
                } else {
                    cell.classList.remove("set");
                }
            }
        } else {
            document.getElementById("window-range-text").innerText = "Range: [Uninitialized]";
            for (let i = 0; i < 64; i++) {
                const cell = document.getElementById(`bit-cell-${i}`);
                if (cell) cell.classList.remove("set");
            }
        }
    } catch (e) {
        console.error("Error fetching status:", e);
    }
}

// Fetch Real-Time Server Logs
async function fetchLogs() {
    try {
        const res = await fetch("/api/logs");
        if (!res.ok) return;
        const data = await res.json();
        const logs = data.logs;

        if (logs.length !== lastLogCount) {
            lastLogCount = logs.length;
            renderLogs(logs);
        }
    } catch (e) {
        console.error("Error fetching logs:", e);
    }
}

function renderLogs(logs) {
    const term = document.getElementById("terminal-log");
    term.innerHTML = "";

    // Show latest 50 logs
    const slice = logs.slice(-50);
    slice.forEach(entry => {
        const line = document.createElement("div");
        const isAccept = entry.event === "accept";
        const reason = entry.reason;
        
        line.className = `log-line ${isAccept ? 'accept' : reason}`;
        
        const timeStr = new Date(entry.timestamp * 1000).toLocaleTimeString();
        const tag = isAccept ? "ACCEPT" : `DROP: ${reason.toUpperCase()}`;
        
        line.innerText = `[${timeStr}] [${tag}] Seq ${entry.seq_no} | Tier: ${entry.tier || 'N/A'} | Client: ${entry.client}`;
        term.appendChild(line);
    });

    // Auto-scroll terminal
    term.scrollTop = term.scrollHeight;
}

// Actions
async function sendPacket(pktType) {
    try {
        await fetch("/api/send", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ packet_type: pktType })
        });
    } catch (e) {
        console.error("Send packet error:", e);
    }
}

async function triggerAttack(attackType) {
    try {
        await fetch("/api/attack", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ attack_type: attackType })
        });
    } catch (e) {
        console.error("Trigger attack error:", e);
    }
}

async function sendBurst() {
    try {
        await fetch("/api/burst", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ count: 20 })
        });
    } catch (e) {
        console.error("Burst error:", e);
    }
}

async function resetServer() {
    try {
        await fetch("/api/reset", { method: "POST" });
        lastLogCount = 0;
        document.getElementById("terminal-log").innerHTML = 
            '<div class="log-line info">[SYSTEM] Server state reset...</div>';
    } catch (e) {
        console.error("Reset error:", e);
    }
}

function clearConsole() {
    document.getElementById("terminal-log").innerHTML = "";
}
