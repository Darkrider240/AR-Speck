// AR-SPECK Technical Instrumentation Panel JavaScript Engine (Defensive & Crash-Proof)

let pollingTimer = null;
let lastLogLen = 0;

document.addEventListener("DOMContentLoaded", () => {
    buildRegisterGrid();
    startPolling();
    updateComparisonAnalyzer(8);
    initGameArena();
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

    const target = document.getElementById(`sec-${secId}`);
    const btn = document.getElementById(`btn-nav-${secId}`);
    if (target) {
        target.classList.add("active");
        target.style.setProperty("display", "block", "important");
    }
    if (btn) btn.classList.add("active");

    if (secId === 'avalanche') {
        if (!currentAvalancheTrace || currentAvalancheTrace.length === 0) {
            loadAvalancheTrace();
        }
    } else if (secId === 'scale') {
        updateScaleSim();
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

let isStatusPolling = false;
let isLogsPolling = false;

// Poll /api/status for stats and sliding window state
async function pollStatus() {
    if (isStatusPolling) return;
    isStatusPolling = true;
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

        // Idea 1 & 2: Entropy Engine Telemetry + Threat Escalation indicator
        if (data.entropy_last !== undefined) {
            safeText("entropy-val", `${data.entropy_last.toFixed(3)} bits`);
        }
        if (data.entropy_rounds_last !== undefined) {
            let roundsStr = `T = ${data.entropy_rounds_last}`;
            if (data.threat) {
                if (data.threat.threat_level === "CRITICAL") {
                    roundsStr += " (CRITICAL Forced T=27)";
                } else if (data.threat.threat_level === "ELEVATED") {
                    roundsStr += " (ELEVATED +4 Floor)";
                }
            }
            safeText("entropy-rounds-val", roundsStr);
        }

        // Idea 2: Threat Automaton Telemetry
        if (data.threat) {
            const threatBadge = document.getElementById("threat-level-badge");
            if (threatBadge) {
                const lvl = data.threat.threat_level || "NOMINAL";
                threatBadge.textContent = lvl;
                if (lvl === "CRITICAL") {
                    threatBadge.className = "status-badge badge-critical";
                } else if (lvl === "ELEVATED") {
                    threatBadge.className = "status-badge badge-elevated";
                } else {
                    threatBadge.className = "status-badge";
                }
            }

            safeText("threat-window-replay", (data.threat.window_replay_count || 0).toString());
            safeText("threat-window-badmac", (data.threat.window_bad_mac_count || 0).toString());

            const expStr = data.threat.escalation_active
                ? `${data.threat.escalation_expires_in}s remaining`
                : "Inactive";
            safeText("threat-escalation-expires", expStr);
        }

        // Idea 3: Markov Predictor Telemetry
        if (data.markov_next) {
            safeText("markov-pred-type", data.markov_next[0] || "--");
            const probPct = (data.markov_next[1] * 100).toFixed(0);
            safeText("markov-pred-prob", `${probPct}%`);
        }
        if (data.markov_prefetch_rounds !== undefined) {
            safeText("markov-prefetch-rounds", `T = ${data.markov_prefetch_rounds}`);
        }

    } catch (err) {
        // Silently skip if connection closed or aborted
    } finally {
        isStatusPolling = false;
    }
}

// Poll /api/logs for server event stream
async function pollLogs() {
    if (isLogsPolling) return;
    isLogsPolling = true;
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
        // Silently skip if connection closed or aborted
    } finally {
        isLogsPolling = false;
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
        const res = await fetch("/api/attack", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ attack_type: attackType })
        });
        const data = await res.json();
        if (data.wire_hex) {
            updateWireInspector(data.wire_hex, `ATTACK: ${attackType}`, data.seq_no);
        }
        // Immediately poll status and logs so attack results show instantly
        await pollStatus();
        await pollLogs();
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

// =============================================================================
// IDEA A1: BIT-LEVEL AVALANCHE DIFFUSION STEPPER LOGIC
// =============================================================================
let currentAvalancheTrace = [];
let avalancheTimer = null;

async function loadAvalancheTrace() {
    const bitInput = document.getElementById("avalanche-bit-input");
    const bitIdx = bitInput ? (parseInt(bitInput.value, 10) || 0) : 0;
    safeText("av-input-bit-label", `Bit offset: ${bitIdx} in Byte ${Math.floor(bitIdx / 8)}`);

    try {
        const res = await fetch(`/api/avalanche_trace?bit=${bitIdx}`);
        if (!res.ok) return;
        const data = await res.json();
        currentAvalancheTrace = data.trace || [];
        
        // Update summary KPI metrics
        if (currentAvalancheTrace.length >= 28) {
            const t8 = currentAvalancheTrace[8];
            const t12 = currentAvalancheTrace[12];
            const t27 = currentAvalancheTrace[27];
            
            safeText("av-t8-val", `${t8.flipped_bits} / 64 (${t8.pct}%)`);
            safeText("av-t12-val", `${t12.flipped_bits} / 64 (${t12.pct}%)`);
            safeText("av-t27-val", `${t27.flipped_bits} / 64 (${t27.pct}%)`);
        }

        buildTimelineStrip(currentAvalancheTrace);

        const slider = document.getElementById("avalanche-slider");
        const currVal = slider ? parseInt(slider.value, 10) : 0;
        renderAvalancheRound(currVal);

    } catch (err) {
        console.error("Failed to load avalanche trace:", err);
    }
}

function renderAvalancheRound(roundIdx) {
    if (!currentAvalancheTrace || currentAvalancheTrace.length <= roundIdx) return;
    const step = currentAvalancheTrace[roundIdx];

    const slider = document.getElementById("avalanche-slider");
    if (slider) slider.value = roundIdx;

    let titleText = `Round ${step.round}`;
    if (step.round === 0) titleText += " (Initial 1-Bit Plaintext Delta)";
    else if (step.round === 8) titleText += " (HEARTBEAT Tier - Avalanche Floor)";
    else if (step.round === 12) titleText += " (LOW Tier - Routine Position Vector)";
    else if (step.round === 16) titleText += " (CAMERA Tier - Orientation Stream)";
    else if (step.round === 20) titleText += " (COMBAT Tier - Health Event)";
    else if (step.round === 24) titleText += " (TRADE Tier - Transaction Draft)";
    else if (step.round === 27) titleText += " (HIGH Tier - Full Cryptographic Margin)";

    safeText("av-current-round-title", titleText);
    safeText("av-scrubber-stat", `${step.flipped_bits} / 64 bits flipped (${step.pct}%)`);
    safeText("av-diff-hex", step.diff_hex);

    // Build or update 64-bit cells
    const grid = document.getElementById("avalanche-bit-grid");
    if (grid) {
        grid.innerHTML = "";
        const bits = step.bits || [];
        // MSB 63 down to 0
        for (let i = 0; i < 64; i++) {
            const cell = document.createElement("div");
            const isFlipped = bits[i] === 1;
            cell.className = `bit-cell ${isFlipped ? 'flipped' : 'unchanged'}`;
            cell.innerText = (63 - i);
            cell.title = `Bit ${63 - i}: ${isFlipped ? 'FLIPPED (1)' : 'UNCHANGED (0)'}`;
            grid.appendChild(cell);
        }
    }

    // Highlight timeline card
    const allCards = document.querySelectorAll(".timeline-step-card");
    allCards.forEach((c, idx) => {
        if (idx === roundIdx) c.classList.add("active-step");
        else c.classList.remove("active-step");
    });
}

function buildTimelineStrip(trace) {
    const container = document.getElementById("avalanche-timeline-grid");
    if (!container) return;
    container.innerHTML = "";

    trace.forEach((step, idx) => {
        const card = document.createElement("div");
        card.className = "timeline-step-card";
        card.onclick = () => renderAvalancheRound(idx);

        const isIdeal = step.pct >= 45.0 && step.pct <= 55.0;
        card.innerHTML = `
            <div class="timeline-step-top mono-text">
                <span>R${step.round}</span>
                <span class="${isIdeal ? 'text-green' : ''}">${step.pct}%</span>
            </div>
            <div class="timeline-step-bar">
                <div class="timeline-step-fill ${isIdeal ? 'ideal' : ''}" style="width: ${step.pct}%;"></div>
            </div>
        `;
        container.appendChild(card);
    });
}

function toggleAvalancheAnimation() {
    const btn = document.getElementById("btn-avalanche-auto");
    if (avalancheTimer) {
        clearInterval(avalancheTimer);
        avalancheTimer = null;
        if (btn) btn.innerText = "Auto-Step Play";
    } else {
        if (btn) btn.innerText = "Pause Step";
        const slider = document.getElementById("avalanche-slider");
        let cur = slider ? parseInt(slider.value, 10) : 0;
        avalancheTimer = setInterval(() => {
            cur = (cur + 1) % 28;
            renderAvalancheRound(cur);
            if (cur === 27) {
                setTimeout(() => {
                    if (avalancheTimer) {
                        clearInterval(avalancheTimer);
                        avalancheTimer = null;
                        if (btn) btn.innerText = "Auto-Step Play";
                    }
                }, 1000);
            }
        }, 350);
    }
}

// =============================================================================
// IDEA B2 & B1: 120HZ GAME SERVER SCALE & BANDWIDTH SIMULATOR LOGIC
// =============================================================================
async function updateScaleSim() {
    const playersSlider = document.getElementById("slider-scale-players");
    const tickSlider = document.getElementById("slider-scale-tick");

    const players = playersSlider ? parseInt(playersSlider.value, 10) : 1000;
    const tickRate = tickSlider ? parseInt(tickSlider.value, 10) : 120;

    safeText("lbl-scale-players", players.toLocaleString());
    safeText("lbl-scale-tick", `${tickRate} Hz`);

    try {
        const res = await fetch(`/api/scale_sim?players=${players}&tick_rate=${tickRate}`);
        if (!res.ok) return;
        const data = await res.json();

        safeText("scale-total-pkts", `${data.packets_per_sec.toLocaleString()} / sec`);
        safeText("scale-speck-bw", `${data.speck_bw_mbs.toFixed(2)} MB/s`);
        safeText("scale-aes-bw", `${data.aes_bw_mbs.toFixed(2)} MB/s`);
        safeText("scale-saved-bw", `${data.bw_saved_vs_aes_mbs.toFixed(2)} MB/s`);
        safeText("scale-saved-pct", `${data.bw_saved_pct}% traffic reduction vs AES`);

        safeText("scale-cpu-speck", `${data.speck_cpu_seconds.toFixed(3)} CPU cores`);
        safeText("scale-cpu-aes-soft", `${data.aes_cpu_software_only.toFixed(3)} CPU cores (${data.aes_cpu_software_only > 1.0 ? 'Server Overload!' : 'Within Budget'})`);

        const barSpeck = document.getElementById("bar-cpu-speck");
        if (barSpeck) {
            const pct = Math.min((data.speck_cpu_seconds / 4.0) * 100, 100);
            barSpeck.style.width = `${pct}%`;
        }

        const barAes = document.getElementById("bar-cpu-aes-soft");
        if (barAes) {
            const pct = Math.min((data.aes_cpu_software_only / 4.0) * 100, 100);
            barAes.style.width = `${pct}%`;
        }

    } catch (err) {
        console.error("Scale sim API error:", err);
    }
}

// =============================================================================
// PROPOSAL 1: REAL 2D PLAYABLE AUTHORITATIVE UDP ARENA LOGIC
// =============================================================================
let arenaPlayer = { x: 200, y: 150, vx: 0, vy: 0, speed: 4 };
let serverPlayer = { x: 200, y: 150, score: 0 };
let arenaKeys = {};
let arenaActiveTamper = false;
let arenaLoopRunning = false;
let arenaTickTimer = null;
let lastMoveTime = 0;

function initGameArena() {
    window.addEventListener("keydown", (e) => {
        if (["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "w", "a", "s", "d", "W", "A", "S", "D"].includes(e.key)) {
            arenaKeys[e.key.toLowerCase()] = true;
            // Prevent scrolling on arrow keys while playing
            if (["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(e.key)) {
                e.preventDefault();
            }
        }
    });

    window.addEventListener("keyup", (e) => {
        if (arenaKeys[e.key.toLowerCase()]) {
            delete arenaKeys[e.key.toLowerCase()];
        }
    });

    if (!arenaLoopRunning) {
        arenaLoopRunning = true;
        requestAnimationFrame(gameArenaRenderLoop);
        // Transmit UDP position updates at 30 Hz tick-rate
        arenaTickTimer = setInterval(transmitPlayerUdpTick, 33);
    }
}

function toggleArenaTamper(val) {
    arenaActiveTamper = Boolean(val);
    const box = document.getElementById("arena-defense-box");
    const icon = document.getElementById("arena-defense-icon");
    const title = document.getElementById("arena-defense-title");
    const desc = document.getElementById("arena-defense-desc");

    if (arenaActiveTamper) {
        if (box) box.className = "arena-defense-box alert-tamper";
        if (icon) { icon.className = "def-icon-warn"; icon.innerText = "!"; }
        if (title) title.innerText = "ACTIVE MitM TAMPERING IN PROGRESS";
        if (desc) desc.innerText = "Every outgoing player coordinate packet has byte offset 4 corrupted in transit. Server VERIFY-THEN-DECRYPT detects bad HMAC and DROPS without decrypting!";
    } else {
        if (box) box.className = "arena-defense-box";
        if (icon) { icon.className = "def-icon-ok"; icon.innerText = "•"; }
        if (title) title.innerText = "ENCRYPTED UDP STREAM NORMAL";
        if (desc) desc.innerText = "Player coordinate vectors are being encrypted with dynamic SPECK rounds in real time. Sliding window sequences accepted.";
    }
}

let isGameMoveInFlight = false;
let arenaIdleTickCount = 0;

async function transmitPlayerUdpTick() {
    let vx = 0;
    let vy = 0;

    if (arenaKeys["w"] || arenaKeys["arrowup"]) vy -= arenaPlayer.speed;
    if (arenaKeys["s"] || arenaKeys["arrowdown"]) vy += arenaPlayer.speed;
    if (arenaKeys["a"] || arenaKeys["arrowleft"]) vx -= arenaPlayer.speed;
    if (arenaKeys["d"] || arenaKeys["arrowright"]) vx += arenaPlayer.speed;

    arenaPlayer.vx = vx;
    arenaPlayer.vy = vy;

    // Local client prediction
    arenaPlayer.x = Math.max(16, Math.min(484, arenaPlayer.x + vx));
    arenaPlayer.y = Math.max(16, Math.min(324, arenaPlayer.y + vy));

    safeText("hud-pos", `(${Math.round(arenaPlayer.x)}, ${Math.round(arenaPlayer.y)})`);

    const isMoving = (vx !== 0 || vy !== 0);
    arenaIdleTickCount++;

    // When idle and no tamper toggle, transmit at 2 Hz heartbeat to conserve HTTP bandwidth;
    // When actively moving or tampering, transmit every tick (30 Hz)
    if (!isMoving && !arenaActiveTamper && arenaIdleTickCount % 15 !== 0) {
        return;
    }

    if (isGameMoveInFlight) return;
    isGameMoveInFlight = true;

    // Transmit over real OS socket
    try {
        const res = await fetch("/api/game_move", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                x: Math.round(arenaPlayer.x),
                y: Math.round(arenaPlayer.y),
                vx: Math.round(vx),
                vy: Math.round(vy),
                tamper: arenaActiveTamper
            })
        });

        if (!res.ok) return;
        const data = await res.json();

        // Update HUD
        safeText("hud-lat", `${data.latency_us.toFixed(2)} µs`);
        safeText("hud-tier", `T=${data.rounds}`);
        if (data.server_entity) {
            serverPlayer = data.server_entity;
            safeText("hud-score", serverPlayer.score || 0);
        }

        // Update wire frame inspector
        if (data.wire_hex) {
            const hex = data.wire_hex;
            safeText("arena-ct-hex", `0x${hex.substring(2, 18).toUpperCase()}`);
            safeText("arena-mac-hex", `0x${hex.substring(26, 42).toUpperCase()}`);
            safeText("arena-pt-hex", `<V, X:${Math.round(arenaPlayer.x)}, Y:${Math.round(arenaPlayer.y)}, vx:${vx}, vy:${vy}>`);
            safeText("arena-entropy-val", `${data.entropy.toFixed(3)} bits (T=${data.rounds})`);
        }

        const badge = document.getElementById("arena-status-badge");
        if (badge) {
            if (data.tampered) {
                badge.innerHTML = '<span class="status-fail">REJECTED (DROP: bad_mac)</span>';
            } else {
                badge.innerHTML = '<span class="status-pass">ACCEPTED (VERIFIED OK)</span>';
            }
        }

    } catch (err) {
        // Silently ignore aborted/cancelled requests
    } finally {
        isGameMoveInFlight = false;
    }
}

function gameArenaRenderLoop() {
    const canvas = document.getElementById("canvas-game-arena");
    if (!canvas) {
        requestAnimationFrame(gameArenaRenderLoop);
        return;
    }

    const ctx = canvas.getContext("2d");
    const w = canvas.width;
    const h = canvas.height;

    // Clear background
    ctx.fillStyle = "#05080e";
    ctx.fillRect(0, 0, w, h);

    // Draw arena grid
    ctx.strokeStyle = "rgba(14, 165, 233, 0.08)";
    ctx.lineWidth = 1;
    for (let x = 0; x < w; x += 30) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
        ctx.stroke();
    }
    for (let y = 0; y < h; y += 30) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
    }

    // Draw Authoritative Server Position Shadow (Orange)
    if (serverPlayer && serverPlayer.x) {
        ctx.beginPath();
        ctx.arc(serverPlayer.x, serverPlayer.y, 14, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(16, 185, 129, 0.25)";
        ctx.fill();
        ctx.strokeStyle = "#10b981";
        ctx.lineWidth = 1.5;
        ctx.setLineDash([2, 2]);
        ctx.stroke();
        ctx.setLineDash([]);
        
        ctx.fillStyle = "#10b981";
        ctx.font = "9px 'IBM Plex Mono', monospace";
        ctx.fillText("SERVER VERIFIED", serverPlayer.x - 42, serverPlayer.y - 18);
    }

    // Draw Local Client Ship (Cyan or Red if tampered)
    const px = arenaPlayer.x;
    const py = arenaPlayer.y;

    ctx.save();
    ctx.translate(px, py);

    // Ship glow
    const shipColor = arenaActiveTamper ? "#f43f5e" : "#0ea5e9";
    ctx.shadowColor = shipColor;
    ctx.shadowBlur = arenaActiveTamper ? 15 : 10;

    // Draw triangular starship
    ctx.beginPath();
    ctx.moveTo(0, -12);
    ctx.lineTo(10, 10);
    ctx.lineTo(0, 6);
    ctx.lineTo(-10, 10);
    ctx.closePath();

    ctx.fillStyle = shipColor;
    ctx.fill();
    ctx.strokeStyle = "#ffffff";
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Thrust flame if moving
    if (arenaPlayer.vx !== 0 || arenaPlayer.vy !== 0) {
        ctx.beginPath();
        ctx.moveTo(-4, 7);
        ctx.lineTo(0, 14 + Math.random() * 4);
        ctx.lineTo(4, 7);
        ctx.closePath();
        ctx.fillStyle = "#f59e0b";
        ctx.fill();
    }

    ctx.restore();

    requestAnimationFrame(gameArenaRenderLoop);
}

async function injectReplayBurst() {
    try {
        await fetch("/api/attack", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ attack_type: "replay" })
        });
        await pollStatus();
        await pollLogs();
    } catch (err) {
        console.error("Replay burst error:", err);
    }
}

function resetArenaPosition() {
    arenaPlayer.x = 200;
    arenaPlayer.y = 150;
    arenaPlayer.vx = 0;
    arenaPlayer.vy = 0;
}


