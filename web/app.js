// AR-SPECK Technical Instrumentation Panel JavaScript Engine (Defensive & Crash-Proof)

let pollingTimer = null;
let lastLogLen = 0;

document.addEventListener("DOMContentLoaded", () => {
    buildRegisterGrid();
    startPolling();
    updateComparisonAnalyzer(8);
});

// Helper for safe DOM text updates
function safeText(id, text) {
    const el = document.getElementById(id);
    if (el) el.innerText = text;
}

// Section Navigation
function showSection(secId) {
    const sections = document.querySelectorAll(".sec-view");
    const navBtns = document.querySelectorAll(".nav-btn");

    sections.forEach(el => {
        el.classList.remove("active");
        el.style.setProperty("display", "none", "important");
    });
    navBtns.forEach(el => el.classList.remove("active"));

    if (secId === 'demo') {
        const target = document.getElementById("sec-demo");
        const btn = document.getElementById("btn-nav-demo");
        if (target) {
            target.classList.add("active");
            target.style.setProperty("display", "block", "important");
        }
        if (btn) btn.classList.add("active");
    } else if (secId === 'justification') {
        const target = document.getElementById("sec-justification");
        const btn = document.getElementById("btn-nav-justification");
        if (target) {
            target.classList.add("active");
            target.style.setProperty("display", "block", "important");
        }
        if (btn) btn.classList.add("active");
    } else if (secId === 'benchmarks') {
        const target = document.getElementById("sec-benchmarks");
        const btn = document.getElementById("btn-nav-bench");
        if (target) {
            target.classList.add("active");
            target.style.setProperty("display", "block", "important");
        }
        if (btn) btn.classList.add("active");
    }
}

// Build 64-Bit Register Grid MSB (63) down to LSB (0)
function buildRegisterGrid() {
    const grid = document.getElementById("register-grid");
    if (!grid) return;
    grid.innerHTML = "";
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
    if (!pollingTimer) {
        pollingTimer = setInterval(() => {
            pollStatus();
            pollLogs();
        }, 500);
    }
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

        safeText("stat-total", total.toLocaleString());
        safeText("stat-accepted", accepts.toLocaleString());
        safeText("stat-mac-drops", badMacs.toLocaleString());
        safeText("stat-replay-drops", replays.toLocaleString());

        const pct = total > 0 ? ((accepts / total) * 100).toFixed(1) : "0.0";
        safeText("stat-accepted-pct", `${pct}% Pass Rate`);

        // Server & Client toggle badge sync
        const serverRunning = data.server_running !== false;
        const clientStreaming = !!data.client_streaming;

        const serverBadge = document.getElementById("server-badge");
        const serverBtn = document.getElementById("btn-server-toggle");
        if (serverBadge && serverBtn) {
            if (serverRunning) {
                serverBadge.textContent = "RUNNING";
                serverBadge.className = "status-badge";
                serverBtn.textContent = "Stop Server";
                serverBtn.className = "power-btn btn-stop";
            } else {
                serverBadge.textContent = "STOPPED";
                serverBadge.className = "status-badge badge-off";
                serverBtn.textContent = "Start Server";
                serverBtn.className = "power-btn btn-start";
            }
        }

        const clientBadge = document.getElementById("client-badge");
        const clientBtn = document.getElementById("btn-client-toggle");
        if (clientBadge && clientBtn) {
            if (clientStreaming) {
                clientBadge.textContent = "STREAMING";
                clientBadge.className = "status-badge";
                clientBtn.textContent = "Stop Stream";
                clientBtn.className = "power-btn btn-stop";
            } else {
                clientBadge.textContent = "IDLE";
                clientBadge.className = "status-badge badge-off";
                clientBtn.textContent = "Start Stream";
                clientBtn.className = "power-btn btn-start";
            }
        }

        // Update 64-Bit Register View
        const windows = data.windows || {};
        const addrs = Object.keys(windows);
        
        if (addrs.length > 0) {
            const win = windows[addrs[0]];
            const maxSeq = win.max_seq;
            const binStr = win.bitmap_bin; // 64-char binary string 'b63...b0'

            safeText("window-range-info", `Highest Seq (max_seq): ${maxSeq} | Range: [${Math.max(0, maxSeq - 63)} .. ${maxSeq}]`);

            for (let i = 63; i >= 0; i--) {
                const cell = document.getElementById(`reg-cell-${i}`);
                if (!cell) continue;
                
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
            safeText("window-range-info", "Highest Seq (max_seq): None");
            for (let i = 63; i >= 0; i--) {
                const cell = document.getElementById(`reg-cell-${i}`);
                if (cell) cell.classList.remove("set", "max-seq");
            }
        }

        // Render Live Diagnostic Canvases
        if (data.rolling_latencies) {
            renderLatencyChart(data.rolling_latencies);
        }
        if (data.byte_distribution) {
            renderHistogram(data.byte_distribution);
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
    if (!consoleBox) return;
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
        const consoleBox = document.getElementById("console-output");
        if (consoleBox) {
            consoleBox.innerHTML = '<div class="c-line c-info">[SYSTEM] Server state and sliding window reset...</div>';
        }
    } catch (err) {
        console.error("Reset error:", err);
    }
}

function clearConsole() {
    const consoleBox = document.getElementById("console-output");
    if (consoleBox) consoleBox.innerHTML = "";
}

// Update 21-Byte Wire Inspector Fields
function updateWireInspector(wireHex, pktType, seqNo) {
    if (!wireHex || wireHex.length < 42) return;

    const tierHex = "0x" + wireHex.substring(0, 2);
    const ctHex = wireHex.substring(2, 18).match(/.{1,2}/g).join(" ");
    const seqHex = "0x" + wireHex.substring(18, 26);
    const macHex = wireHex.substring(26, 42).match(/.{1,2}/g).join(" ");

    safeText("inp-tier-hex", tierHex);
    safeText("inp-tier-desc", `1 Byte (${pktType.toUpperCase()})`);
    safeText("inp-ct-hex", ctHex);
    safeText("inp-seq-hex", seqHex);
    safeText("inp-seq-desc", `Seq: ${seqNo}`);
    safeText("inp-mac-hex", macHex);
}

// System Power Controls
async function toggleServer() {
    try {
        await fetch("/api/server_toggle", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: "toggle" })
        });
        await pollStatus();
    } catch (err) {
        console.error("Server toggle error:", err);
    }
}

async function toggleClientStream() {
    try {
        await fetch("/api/client_toggle", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: "toggle" })
        });
        await pollStatus();
    } catch (err) {
        console.error("Client stream toggle error:", err);
    }
}

// Render Live Rolling Latency Line Chart (Canvas)
function renderLatencyChart(latencies) {
    const canvas = document.getElementById("canvas-latency");
    if (!canvas) return;

    canvas.width = 400;
    canvas.height = 110;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const w = canvas.width;
    const h = canvas.height;

    // Background fill
    ctx.fillStyle = "#05080e";
    ctx.fillRect(0, 0, w, h);

    // Draw grid lines
    ctx.strokeStyle = "rgba(255, 255, 255, 0.08)";
    ctx.lineWidth = 1;
    for (let y = 20; y < h; y += 25) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
    }

    if (!latencies || latencies.length === 0) return;

    const lastVal = latencies[latencies.length - 1];
    safeText("stat-latency-val", `${lastVal.toFixed(1)} µs`);

    const maxVal = Math.max(...latencies, 50);
    const minVal = Math.min(...latencies, 0);
    const range = Math.max(maxVal - minVal, 10);
    const step = w / Math.max(latencies.length - 1, 1);

    // Fill area under line
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, "rgba(6, 182, 212, 0.35)");
    grad.addColorStop(1, "rgba(6, 182, 212, 0.02)");

    ctx.beginPath();
    latencies.forEach((val, idx) => {
        const x = idx * step;
        const y = h - ((val - minVal) / range) * (h - 20) - 10;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.lineTo((latencies.length - 1) * step, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Line stroke
    ctx.beginPath();
    latencies.forEach((val, idx) => {
        const x = idx * step;
        const y = h - ((val - minVal) / range) * (h - 20) - 10;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = "#06b6d4";
    ctx.lineWidth = 2;
    ctx.stroke();
}

// Render Live Ciphertext Byte Histogram (Canvas)
function renderHistogram(buckets) {
    const canvas = document.getElementById("canvas-histogram");
    if (!canvas) return;

    canvas.width = 400;
    canvas.height = 110;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const w = canvas.width;
    const h = canvas.height;

    // Background fill
    ctx.fillStyle = "#05080e";
    ctx.fillRect(0, 0, w, h);

    // Grid lines
    ctx.strokeStyle = "rgba(255, 255, 255, 0.08)";
    ctx.lineWidth = 1;
    for (let y = 20; y < h; y += 25) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
    }

    if (!buckets || buckets.length === 0) return;

    const maxVal = Math.max(...buckets, 1);
    const barGap = 3;
    const barWidth = (w - (buckets.length - 1) * barGap - 10) / buckets.length;

    buckets.forEach((val, idx) => {
        const barHeight = (val / maxVal) * (h - 24);
        const x = 5 + idx * (barWidth + barGap);
        const y = h - barHeight - 4;

        ctx.fillStyle = "#10b981";
        ctx.fillRect(x, y, barWidth, barHeight);
    });
}

// Dynamic Side-by-Side Wire Overhead & Padding Analyzer (Python API Integrated)
async function updateComparisonAnalyzer(valStr) {
    const val = parseInt(valStr, 10) || 8;
    
    // Label hint update
    let descHint = "Custom Payload";
    if (val === 8) descHint = "Position Vector (x,y,z + rot)";
    else if (val === 4) descHint = "Input Command Mask";
    else if (val === 16) descHint = "Trade / Inventory Transaction";
    else if (val === 32) descHint = "Player Profile State";
    
    safeText("payload-slider-val", `${val} Bytes (${descHint})`);

    try {
        const res = await fetch(`/api/analyze?size=${val}`);
        if (res.ok) {
            const data = await res.json();
            const speck = data.speck;
            const aes = data.aes;

            safeText("speck-pad-val", `${speck.pad_bytes} Bytes (${speck.pad_pct}% Waste)`);
            safeText("speck-ct-val", `${speck.ct_bytes} Bytes`);
            safeText("speck-wire-val", `${speck.wire_bytes} Bytes`);
            safeText("speck-bw-val", `${speck.bw_wasted_kb} KB / sec`);

            safeText("aes-pad-val", `${aes.pad_bytes} Bytes (${aes.pad_pct}% Waste!)`);
            safeText("aes-ct-val", `${aes.ct_bytes} Bytes`);
            safeText("aes-wire-val", `${aes.wire_bytes} Bytes (+${aes.expansion_pct}% Expansion)`);
            safeText("aes-bw-val", `${aes.bw_wasted_kb} KB / sec (~${aes.bw_wasted_mb} MB/s Waste!)`);
            return;
        }
    } catch (err) {
        // Fallback to local calculation if server is unreachable
    }

    // SPECK64 (8-byte block) local fallback
    const speckCT = Math.ceil(val / 8) * 8;
    const speckPad = speckCT - val;
    const speckPadPct = ((speckPad / val) * 100).toFixed(0);
    const speckWire = 1 + speckCT + 4 + 8;
    const speckBwKb = Math.round((speckPad * 1000 * 120) / 1024);

    safeText("speck-pad-val", `${speckPad} Bytes (${speckPadPct}% Waste)`);
    safeText("speck-ct-val", `${speckCT} Bytes`);
    safeText("speck-wire-val", `${speckWire} Bytes`);
    safeText("speck-bw-val", `${speckBwKb} KB / sec`);

    // AES-128 (16-byte block) local fallback
    const aesCT = (Math.floor(val / 16) + 1) * 16;
    const aesPad = aesCT - val;
    const aesPadPct = ((aesPad / val) * 100).toFixed(0);
    const aesWire = 1 + aesCT + 4 + 16;
    const aesExpansion = (((aesWire - speckWire) / speckWire) * 100).toFixed(0);
    const aesBwKb = Math.round((aesPad * 1000 * 120) / 1024);

    safeText("aes-pad-val", `${aesPad} Bytes (${aesPadPct}% Waste!)`);
    safeText("aes-ct-val", `${aesCT} Bytes`);
    safeText("aes-wire-val", `${aesWire} Bytes (+${aesExpansion}% Expansion)`);
    safeText("aes-bw-val", `${aesBwKb} KB / sec (~${(aesBwKb / 1024).toFixed(1)} MB/s Waste!)`);
}
