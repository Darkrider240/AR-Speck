// AR-SPECK Presentation Dashboard JavaScript Engine

let pollingTimer = null;
let lastLogLen = 0;

document.addEventListener("DOMContentLoaded", () => {
    buildRegisterGrid();
    startPolling();
});

// Section Navigation
function showSection(secId) {
    document.querySelectorAll(".sec-view").forEach(el => el.classList.remove("active"));
    document.querySelectorAll(".nav-btn").forEach(el => el.classList.remove("active"));

    if (secId === 'demo') {
        document.getElementById("sec-demo").classList.add("active");
        document.getElementById("btn-nav-demo").classList.add("active");
    } else if (secId === 'benchmarks') {
        document.getElementById("sec-benchmarks").classList.add("active");
        document.getElementById("btn-nav-bench").classList.add("active");
    } else if (secId === 'viva') {
        document.getElementById("sec-viva").classList.add("active");
        document.getElementById("btn-nav-viva").classList.add("active");
    }
}

// Build 64-Bit Register Grid MSB (63) down to LSB (0)
function buildRegisterGrid() {
    const grid = document.getElementById("register-grid");
    grid.innerHTML = "";
    // Render bits 63 down to 0
    for (let i = 63; i >= 0; i--) {
        const cell = document.createElement("div");
        cell.className = "reg-cell";
        cell.id = `reg-cell-${i}`;
        cell.innerText = i;
        cell.title = `Bit offset ${i}`;
        grid.appendChild(cell);
    }
}

// Polling Interval (500ms)
function startPolling() {
    pollStatus();
    pollLogs();
    pollingTimer = setInterval(() => {
        pollStatus();
        pollLogs();
    }, 500);
}

// Poll /api/status for stats and sliding window state
async function pollStatus() {
    try {
        const res = await fetch("/api/status");
        if (!res.ok) return;
        const data = await res.json();

        const total = data.total_packets || 0;
        const accepts = data.accepted || 0;
        const badMacs = data.bad_mac_drops || 0;
        const replays = (data.replay_drops || 0) + (data.too_old_drops || 0);

        document.getElementById("stat-total").innerText = total.toLocaleString();
        document.getElementById("stat-accepted").innerText = accepts.toLocaleString();
        document.getElementById("stat-mac-drops").innerText = badMacs.toLocaleString();
        document.getElementById("stat-replay-drops").innerText = replays.toLocaleString();

        const pct = total > 0 ? ((accepts / total) * 100).toFixed(1) : "0.0";
        document.getElementById("stat-accepted-pct").innerText = `${pct}% Pass Rate`;

        // Update 64-Bit Register View
        const windows = data.windows || {};
        const addrs = Object.keys(windows);
        
        if (addrs.length > 0) {
            const win = windows[addrs[0]];
            const maxSeq = win.max_seq;
            const binStr = win.bitmap_bin; // 64-char binary string 'b63...b0'

            document.getElementById("window-range-info").innerText = 
                `Highest Seq (max_seq): ${maxSeq} | Range: [${Math.max(0, maxSeq - 63)} .. ${maxSeq}]`;

            for (let i = 63; i >= 0; i--) {
                const cell = document.getElementById(`reg-cell-${i}`);
                if (!cell) continue;
                
                // binStr index 0 is bit 63, index 63 is bit 0
                const charIdx = 63 - i;
                const isBitSet = binStr[charIdx] === '1';

                cell.classList.remove("set", "max-seq");
                if (isBitSet) {
                    if (i === 0) {
                        cell.classList.add("max-seq");
                    } else {
                        cell.classList.add("set");
                    }
                }
            }
        } else {
            document.getElementById("window-range-info").innerText = "Highest Seq (max_seq): None";
            for (let i = 63; i >= 0; i--) {
                const cell = document.getElementById(`reg-cell-${i}`);
                if (cell) cell.classList.remove("set", "max-seq");
            }
        }
    } catch (err) {
        console.error("Status polling error:", err);
    }
}

// Poll /api/logs for server event stream
async function pollLogs() {
    try {
        const res = await fetch("/api/logs");
        if (!res.ok) return;
        const data = await res.json();
        const logs = data.logs || [];

        if (logs.length !== lastLogLen) {
            lastLogLen = logs.length;
            renderConsole(logs);
        }
    } catch (err) {
        console.error("Logs polling error:", err);
    }
}

function renderConsole(logs) {
    const consoleBox = document.getElementById("console-output");
    consoleBox.innerHTML = "";

    const recent = logs.slice(-60);
    recent.forEach(entry => {
        const line = document.createElement("div");
        const isAccept = entry.event === "accept";
        const reason = entry.reason;

        line.className = `c-line ${isAccept ? 'c-accept' : 'c-' + reason}`;

        const timeStr = new Date(entry.timestamp * 1000).toLocaleTimeString();
        const statusTag = isAccept ? "ACCEPT" : `DROP: ${reason.toUpperCase()}`;
        const tierTag = entry.tier ? `[${entry.tier}]` : "";

        line.innerText = `[${timeStr}] [${statusTag}] ${tierTag} Seq: ${entry.seq_no} | Client: ${entry.client}`;
        consoleBox.appendChild(line);
    });

    consoleBox.scrollTop = consoleBox.scrollHeight;
}

// Interactive Trigger Actions
async function sendPacket(pktType) {
    try {
        const res = await fetch("/api/send", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ packet_type: pktType })
        });
        const data = await res.json();
        if (data.wire_hex) {
            updateWireInspector(data.wire_hex, pktType, data.seq_no);
        }
    } catch (err) {
        console.error("Send packet error:", err);
    }
}

async function triggerAttack(attackType) {
    try {
        await fetch("/api/attack", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ attack_type: attackType })
        });
    } catch (err) {
        console.error("Trigger attack error:", err);
    }
}

async function sendBurst() {
    try {
        await fetch("/api/burst", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ count: 20 })
        });
    } catch (err) {
        console.error("Burst error:", err);
    }
}

async function resetState() {
    try {
        await fetch("/api/reset", { method: "POST" });
        lastLogLen = 0;
        document.getElementById("console-output").innerHTML = 
            '<div class="c-line c-info">[SYSTEM] Server state and sliding window reset...</div>';
    } catch (err) {
        console.error("Reset error:", err);
    }
}

function clearConsole() {
    document.getElementById("console-output").innerHTML = "";
}

// Update 21-Byte Wire Inspector Fields
function updateWireInspector(wireHex, pktType, seqNo) {
    if (!wireHex || wireHex.length < 42) return;

    const tierHex = "0x" + wireHex.substring(0, 2);
    const ctHex = wireHex.substring(2, 18).match(/.{1,2}/g).join(" ");
    const seqHex = "0x" + wireHex.substring(18, 26);
    const macHex = wireHex.substring(26, 42).match(/.{1,2}/g).join(" ");

    document.getElementById("inp-tier-hex").innerText = tierHex;
    document.getElementById("inp-tier-desc").innerText = `1 Byte (${pktType.toUpperCase()})`;

    document.getElementById("inp-ct-hex").innerText = ctHex;
    document.getElementById("inp-seq-hex").innerText = seqHex;
    document.getElementById("inp-seq-desc").innerText = `Seq: ${seqNo}`;

    document.getElementById("inp-mac-hex").innerText = macHex;
}
