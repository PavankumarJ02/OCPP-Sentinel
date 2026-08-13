// =============================================================================
// app.js — Apple-Style OCPP Sentinel Frontend Logic
// =============================================================================

const PRESET_MESSAGES = {
    benign_authorize: {
        message_type_id: 2,
        unique_id: "auth-001",
        action: "Authorize",
        payload: { idTag: "RFID-A1B2C3" },
        charge_point_id: "CP-NORTH-01",
        received_at: new Date().toISOString(),
        context: {
            authorized_id_tags: ["RFID-A1B2C3", "RFID-D4E5F6"],
            known_message_ids: [],
            recent_message_count: 3,
            time_window_seconds: 60
        }
    },
    malicious_spoofing: {
        message_type_id: 2,
        unique_id: "remote-start-666",
        action: "RemoteStartTransaction",
        payload: { idTag: "FAKE-TAG-999", connectorId: 1 },
        charge_point_id: "CP-NORTH-01",
        received_at: new Date().toISOString(),
        context: {
            authorized_id_tags: ["RFID-A1B2C3", "RFID-D4E5F6"],
            known_message_ids: [],
            recent_message_count: 2,
            time_window_seconds: 60
        }
    },
    malicious_tampering: {
        message_type_id: 2,
        unique_id: "meter-tamper-001",
        action: "MeterValues",
        payload: {
            connectorId: 1,
            transactionId: 1002,
            meterValue: [
                { timestamp: "2024-01-15T12:00:00Z", sampledValue: [{ value: "1000", unit: "Wh" }] },
                { timestamp: "2024-01-15T14:00:00Z", sampledValue: [{ value: "1050", unit: "Wh" }] }
            ]
        },
        charge_point_id: "CP-EAST-03",
        received_at: new Date().toISOString(),
        context: { authorized_id_tags: [], known_message_ids: [], recent_message_count: 4, time_window_seconds: 60 }
    },
    malicious_repudiation: {
        message_type_id: 2,
        unique_id: "auth-001",
        action: "Authorize",
        payload: { idTag: "RFID-A1B2C3" },
        charge_point_id: "CP-SOUTH-02",
        received_at: new Date().toISOString(),
        context: {
            authorized_id_tags: ["RFID-A1B2C3"],
            known_message_ids: ["auth-001", "start-001"],
            recent_message_count: 2,
            time_window_seconds: 60
        }
    },
    malicious_info_disclosure: {
        message_type_id: 2,
        unique_id: "status-leak-001",
        action: "StatusNotification",
        payload: {
            connectorId: 1,
            errorCode: "OtherError",
            status: "Faulted",
            timestamp: "2024-01-15T16:00:00Z",
            info: "Auth fail: idTag=RFID-A1B2C3, token=sk_live_abc123",
            vendorId: "debug-session-token:eyJhbGciOiJIUzI1NiJ9"
        },
        charge_point_id: "CP-WEST-04",
        received_at: new Date().toISOString(),
        context: { authorized_id_tags: ["RFID-A1B2C3"], known_message_ids: [], recent_message_count: 3, time_window_seconds: 60 }
    },
    malicious_dos: {
        message_type_id: 2,
        unique_id: "status-flood-150",
        action: "StatusNotification",
        payload: { connectorId: 1, errorCode: "NoError", status: "Available" },
        charge_point_id: "CP-NORTH-01",
        received_at: new Date().toISOString(),
        context: { authorized_id_tags: [], known_message_ids: [], recent_message_count: 150, time_window_seconds: 60 }
    }
};

let currentAnalysisData = null;

document.addEventListener("DOMContentLoaded", () => {
    startClock();
    checkHealth();
    initCursorLight();
    fetchStats();
    initKeyboardShortcut();
});

// =============================================================================
// CURSOR LIGHT
// =============================================================================
function initCursorLight() {
    const light = document.getElementById("cursor-light");
    if (!light) return;
    window.addEventListener("mousemove", (e) => {
        light.style.transform = `translate(${e.clientX}px, ${e.clientY}px)`;
    });
}

// =============================================================================
// LIVE CLOCK
// =============================================================================
function startClock() {
    const el = document.getElementById("live-clock");
    const update = () => {
        if (el) el.textContent = new Date().toLocaleTimeString();
    };
    update();
    setInterval(update, 1000);
}

// =============================================================================
// KEYBOARD SHORTCUT — Ctrl+Enter to analyze
// =============================================================================
function initKeyboardShortcut() {
    document.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            e.preventDefault();
            analyzeMessage();
        }
    });
}

// =============================================================================
// TOAST NOTIFICATIONS (replaces alert())
// =============================================================================
function showToast(message, type = "info", durationMs = 4000) {
    const container = document.getElementById("toast-container");
    if (!container) return;

    const icons = {
        error: `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
        success: `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
        info: `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
    };

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.innerHTML = (icons[type] || icons.info) + `<span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add("toast-fade-out");
        toast.addEventListener("animationend", () => toast.remove());
    }, durationMs);
}

// =============================================================================
// HEALTH CHECK
// =============================================================================
async function checkHealth() {
    try {
        const res = await fetch("/health");
        const data = await res.json();
        if (data.status === "ok") {
            document.getElementById("kb-count").textContent = data.kb_chunks + " vectors";
        }
    } catch (e) {
        document.getElementById("kb-count").textContent = "offline";
    }
}

// =============================================================================
// STATS DASHBOARD
// =============================================================================
async function fetchStats() {
    try {
        const res = await fetch("/stats");
        if (!res.ok) return;
        const data = await res.json();
        updateStatCards(data);
    } catch (_) {
        // Fail silently — stats strip remains with placeholders
    }
}

function updateStatCards(data) {
    const total = document.getElementById("stat-total");
    const threats = document.getElementById("stat-threats");
    const normal = document.getElementById("stat-normal");
    const latency = document.getElementById("stat-latency");

    if (total) total.textContent = data.total_analyzed ?? "—";
    if (threats) threats.textContent = data.threats_detected ?? "—";
    if (normal) normal.textContent = data.normal_count ?? "—";
    if (latency) latency.textContent = data.avg_latency_ms != null ? data.avg_latency_ms.toFixed(1) : "—";
}

// =============================================================================
// SCENARIO SELECTOR
// =============================================================================
function loadSample(key) {
    // Update active chip
    document.querySelectorAll("[data-chip]").forEach(c => c.classList.remove("active-chip"));
    if (window.event && window.event.currentTarget) {
        window.event.currentTarget.classList.add("active-chip");
    }

    const data = PRESET_MESSAGES[key];
    if (data) {
        const sample = JSON.parse(JSON.stringify(data));
        sample.received_at = new Date().toISOString();
        document.getElementById("json-input").value = JSON.stringify(sample, null, 2);
    }
}

// =============================================================================
// JSON EDITOR UTILITIES
// =============================================================================
function formatJson() {
    const el = document.getElementById("json-input");
    try {
        el.value = JSON.stringify(JSON.parse(el.value), null, 2);
    } catch (e) {
        showToast("Invalid JSON — cannot format.", "error");
    }
}

function copyJson() {
    const el = document.getElementById("json-input");
    if (!el.value.trim()) return;
    navigator.clipboard.writeText(el.value).then(() => {
        showToast("JSON copied to clipboard.", "success", 2500);
    });
}

function clearEditor() {
    document.getElementById("json-input").value = "";
    document.getElementById("results-placeholder").classList.remove("hidden");
    document.getElementById("results-container").classList.add("hidden");
}

// =============================================================================
// ANALYZE — Main analysis flow with shimmer loading state
// =============================================================================
async function analyzeMessage() {
    const raw = document.getElementById("json-input").value.trim();
    if (!raw) {
        showToast("Paste or select a message first.", "info");
        return;
    }

    let json;
    try { json = JSON.parse(raw); } catch (e) {
        showToast("Invalid JSON — please check your input.", "error");
        return;
    }

    const btnText = document.getElementById("btn-text");
    const placeholder = document.getElementById("results-placeholder");
    const container = document.getElementById("results-container");

    btnText.textContent = "Analyzing…";

    // Show shimmer loading state
    placeholder.classList.add("hidden");
    container.classList.remove("hidden");
    container.classList.add("shimmer");

    try {
        const res = await fetch("/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: json })
        });
        const data = await res.json();

        container.classList.remove("shimmer");

        if (res.ok && data.success) {
            currentAnalysisData = data;
            renderResults(data, json);
            appendAuditRow(data, json);
            // Refresh stats strip after analysis
            fetchStats();
            const isThreat = data.analysis.verdict.toLowerCase() === "suspicious";
            showToast(
                isThreat
                    ? `⚠ Threat detected: ${data.analysis.matched_attack_category}`
                    : `✓ Message cleared — no threats detected`,
                isThreat ? "error" : "success"
            );
        } else {
            showToast("Error: " + (data.detail || "Unknown server error"), "error");
        }
    } catch (e) {
        container.classList.remove("shimmer");
        showToast("Network error: " + e.message, "error");
    } finally {
        btnText.textContent = "Analyze Message";
    }
}

// =============================================================================
// RESULTS RENDERING
// =============================================================================
function renderResults(data, req) {
    document.getElementById("results-placeholder").classList.add("hidden");
    const container = document.getElementById("results-container");
    container.classList.remove("hidden");

    const a = data.analysis;
    const isThreat = a.verdict.toLowerCase() === "suspicious";
    const card = document.getElementById("verdict-card");

    card.className = "verdict-card " + (isThreat ? "is-threat" : "is-safe");

    document.getElementById("verdict-title").textContent = isThreat ? "Suspicious" : "Normal";
    document.getElementById("verdict-category").textContent = "STRIDE: " + a.matched_attack_category;

    const pct = Math.round(a.confidence * 100);
    document.getElementById("gauge-pct").textContent = pct + "%";
    document.getElementById("gauge-fill").setAttribute("stroke-dasharray", pct + ",100");

    document.getElementById("reason-text").textContent = a.plain_english_reason;
    document.getElementById("citation-text").textContent = a.source_reference;
    document.getElementById("metric-time").textContent = data.processing_time_ms + " ms";
    document.getElementById("metric-rule").textContent = a.rule_detected ? "Deterministic" : "AI RAG";
    document.getElementById("metric-cp").textContent = req.charge_point_id || "—";

    updateFleet(req.charge_point_id, isThreat);
}

function updateFleet(cpId, isThreat) {
    if (!cpId) return;
    const key = cpId.toLowerCase().replace("cp-", "").split("-")[0];
    const card = document.getElementById("cp-" + key);
    if (!card) return;
    const dot = card.querySelector(".fleet-dot");
    if (dot) dot.className = "fleet-dot " + (isThreat ? "red" : "green");
}

// =============================================================================
// AUDIT TABLE
// =============================================================================
function appendAuditRow(data, req) {
    const tbody = document.getElementById("audit-table-body");
    const empty = tbody.querySelector(".empty-row");
    if (empty) empty.remove();

    const a = data.analysis;
    const isThreat = a.verdict.toLowerCase() === "suspicious";
    const tr = document.createElement("tr");
    tr.innerHTML = `
        <td>${new Date().toLocaleTimeString()}</td>
        <td><strong>${req.charge_point_id || "—"}</strong></td>
        <td><code>${req.action || "—"}</code></td>
        <td><span class="badge-verdict ${isThreat ? "suspicious" : "normal"}">${a.verdict}</span></td>
        <td>${a.matched_attack_category}</td>
        <td>${data.processing_time_ms} ms</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${a.plain_english_reason}</td>
    `;
    tbody.insertBefore(tr, tbody.firstChild);
}

async function loadAuditHistory() {
    showToast("Loading audit history from server…", "info", 2000);
    try {
        const res = await fetch("/audit?limit=50");
        if (!res.ok) { showToast("Failed to load audit history.", "error"); return; }
        const data = await res.json();

        if (!data.entries || data.entries.length === 0) {
            showToast("No past audit entries found on server.", "info");
            return;
        }

        const tbody = document.getElementById("audit-table-body");
        tbody.innerHTML = ""; // Clear placeholder

        data.entries.forEach(entry => {
            const isThreat = entry.verdict.toLowerCase() === "suspicious";
            const tr = document.createElement("tr");
            // Format timestamp as local time
            const ts = entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : "—";
            tr.innerHTML = `
                <td>${ts}</td>
                <td><strong>${entry.charge_point_id || "—"}</strong></td>
                <td><code>${entry.action || "—"}</code></td>
                <td><span class="badge-verdict ${isThreat ? "suspicious" : "normal"}">${entry.verdict}</span></td>
                <td>${entry.attack_category}</td>
                <td>${entry.processing_time_ms} ms</td>
                <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${entry.details}</td>
            `;
            tbody.appendChild(tr);
        });

        showToast(`Loaded ${data.total_returned} audit entries from server.`, "success");
    } catch (e) {
        showToast("Network error loading audit history: " + e.message, "error");
    }
}

function filterAuditTable() {
    const q = document.getElementById("table-search").value.toLowerCase();
    document.querySelectorAll("#audit-table-body tr").forEach(r => {
        r.style.display = r.textContent.toLowerCase().includes(q) ? "" : "none";
    });
}

function exportAuditCsv() {
    const rows = document.querySelectorAll("#audit-table-body tr");
    if (!rows.length || rows[0].classList.contains("empty-row")) {
        showToast("No data to export.", "info");
        return;
    }

    let csv = "data:text/csv;charset=utf-8,Time,Station,Action,Verdict,Category,Latency,Summary\n";
    rows.forEach(r => {
        const cols = Array.from(r.querySelectorAll("td")).map(t => '"' + t.textContent.replace(/"/g, '""') + '"');
        csv += cols.join(",") + "\n";
    });

    const a = document.createElement("a");
    a.href = encodeURI(csv);
    a.download = "ocpp_sentinel_audit_" + Date.now() + ".csv";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    showToast("CSV exported successfully.", "success", 2500);
}

// =============================================================================
// RAG MODAL
// =============================================================================
function openRagModal() {
    if (!currentAnalysisData) return;
    document.getElementById("modal-source-tag").textContent = currentAnalysisData.analysis.source_reference;
    document.getElementById("modal-content-box").textContent =
        "VERDICT: " + currentAnalysisData.analysis.verdict +
        "\n\nREASON:\n" + currentAnalysisData.analysis.plain_english_reason +
        "\n\nSOURCE:\n" + currentAnalysisData.analysis.source_reference;
    document.getElementById("rag-modal").classList.remove("hidden");
}

function closeRagModal(e) {
    document.getElementById("rag-modal").classList.add("hidden");
}


const PRESET_MESSAGES = {
    benign_authorize: {
        message_type_id: 2,
        unique_id: "auth-001",
        action: "Authorize",
        payload: { idTag: "RFID-A1B2C3" },
        charge_point_id: "CP-NORTH-01",
        received_at: new Date().toISOString(),
        context: {
            authorized_id_tags: ["RFID-A1B2C3", "RFID-D4E5F6"],
            known_message_ids: [],
            recent_message_count: 3,
            time_window_seconds: 60
        }
    },
    malicious_spoofing: {
        message_type_id: 2,
        unique_id: "remote-start-666",
        action: "RemoteStartTransaction",
        payload: { idTag: "FAKE-TAG-999", connectorId: 1 },
        charge_point_id: "CP-NORTH-01",
        received_at: new Date().toISOString(),
        context: {
            authorized_id_tags: ["RFID-A1B2C3", "RFID-D4E5F6"],
            known_message_ids: [],
            recent_message_count: 2,
            time_window_seconds: 60
        }
    },
    malicious_tampering: {
        message_type_id: 2,
        unique_id: "meter-tamper-001",
        action: "MeterValues",
        payload: {
            connectorId: 1,
            transactionId: 1002,
            meterValue: [
                { timestamp: "2024-01-15T12:00:00Z", sampledValue: [{ value: "1000", unit: "Wh" }] },
                { timestamp: "2024-01-15T14:00:00Z", sampledValue: [{ value: "1050", unit: "Wh" }] }
            ]
        },
        charge_point_id: "CP-EAST-03",
        received_at: new Date().toISOString(),
        context: { authorized_id_tags: [], known_message_ids: [], recent_message_count: 4, time_window_seconds: 60 }
    },
    malicious_repudiation: {
        message_type_id: 2,
        unique_id: "auth-001",
        action: "Authorize",
        payload: { idTag: "RFID-A1B2C3" },
        charge_point_id: "CP-SOUTH-02",
        received_at: new Date().toISOString(),
        context: {
            authorized_id_tags: ["RFID-A1B2C3"],
            known_message_ids: ["auth-001", "start-001"],
            recent_message_count: 2,
            time_window_seconds: 60
        }
    },
    malicious_info_disclosure: {
        message_type_id: 2,
        unique_id: "status-leak-001",
        action: "StatusNotification",
        payload: {
            connectorId: 1,
            errorCode: "OtherError",
            status: "Faulted",
            timestamp: "2024-01-15T16:00:00Z",
            info: "Auth fail: idTag=RFID-A1B2C3, token=sk_live_abc123",
            vendorId: "debug-session-token:eyJhbGciOiJIUzI1NiJ9"
        },
        charge_point_id: "CP-WEST-04",
        received_at: new Date().toISOString(),
        context: { authorized_id_tags: ["RFID-A1B2C3"], known_message_ids: [], recent_message_count: 3, time_window_seconds: 60 }
    },
    malicious_dos: {
        message_type_id: 2,
        unique_id: "status-flood-150",
        action: "StatusNotification",
        payload: { connectorId: 1, errorCode: "NoError", status: "Available" },
        charge_point_id: "CP-NORTH-01",
        received_at: new Date().toISOString(),
        context: { authorized_id_tags: [], known_message_ids: [], recent_message_count: 150, time_window_seconds: 60 }
    }
};

let currentAnalysisData = null;

document.addEventListener("DOMContentLoaded", () => {
    startClock();
    checkHealth();
    initCursorLight();
});

function initCursorLight() {
    const light = document.getElementById("cursor-light");
    if (!light) return;
    window.addEventListener("mousemove", (e) => {
        light.style.transform = `translate(${e.clientX}px, ${e.clientY}px)`;
    });
}

function startClock() {
    const el = document.getElementById("live-clock");
    const update = () => {
        if (el) {
            const now = new Date();
            el.textContent = now.toLocaleTimeString();
        }
    };
    update();
    setInterval(update, 1000);
}

async function checkHealth() {
    try {
        const res = await fetch("/health");
        const data = await res.json();
        if (data.status === "ok") {
            document.getElementById("kb-count").textContent = data.kb_chunks + " vectors";
        }
    } catch (e) {
        document.getElementById("kb-count").textContent = "offline";
    }
}

function loadSample(key) {
    // Update active chip
    document.querySelectorAll("[data-chip]").forEach(c => c.classList.remove("active-chip"));
    if (window.event && window.event.currentTarget) {
        window.event.currentTarget.classList.add("active-chip");
    }

    const data = PRESET_MESSAGES[key];
    if (data) {
        const sample = JSON.parse(JSON.stringify(data));
        sample.received_at = new Date().toISOString();
        document.getElementById("json-input").value = JSON.stringify(sample, null, 2);
    }
}

function formatJson() {
    const el = document.getElementById("json-input");
    try {
        el.value = JSON.stringify(JSON.parse(el.value), null, 2);
    } catch (e) {
        alert("Invalid JSON");
    }
}

function copyJson() {
    const el = document.getElementById("json-input");
    if (!el.value.trim()) return;
    navigator.clipboard.writeText(el.value);
}

function clearEditor() {
    document.getElementById("json-input").value = "";
    document.getElementById("results-placeholder").classList.remove("hidden");
    document.getElementById("results-container").classList.add("hidden");
}

async function analyzeMessage() {
    const raw = document.getElementById("json-input").value.trim();
    if (!raw) return alert("Paste or select a message first.");

    let json;
    try { json = JSON.parse(raw); } catch (e) { return alert("Invalid JSON"); }

    document.getElementById("btn-text").textContent = "Analyzing...";

    try {
        const res = await fetch("/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: json })
        });
        const data = await res.json();

        if (res.ok && data.success) {
            currentAnalysisData = data;
            renderResults(data, json);
            appendAuditRow(data, json);
        } else {
            alert("Error: " + (data.detail || "Unknown"));
        }
    } catch (e) {
        alert("Network error: " + e.message);
    } finally {
        document.getElementById("btn-text").textContent = "Analyze Message";
    }
}

function renderResults(data, req) {
    document.getElementById("results-placeholder").classList.add("hidden");
    const container = document.getElementById("results-container");
    container.classList.remove("hidden");

    const a = data.analysis;
    const isThreat = a.verdict.toLowerCase() === "suspicious";
    const card = document.getElementById("verdict-card");

    card.className = "verdict-card " + (isThreat ? "is-threat" : "is-safe");

    document.getElementById("verdict-title").textContent = isThreat ? "Suspicious" : "Normal";
    document.getElementById("verdict-category").textContent = "STRIDE: " + a.matched_attack_category;

    const pct = Math.round(a.confidence * 100);
    document.getElementById("gauge-pct").textContent = pct + "%";
    document.getElementById("gauge-fill").setAttribute("stroke-dasharray", pct + ",100");

    document.getElementById("reason-text").textContent = a.plain_english_reason;
    document.getElementById("citation-text").textContent = a.source_reference;
    document.getElementById("metric-time").textContent = data.processing_time_ms + " ms";
    document.getElementById("metric-rule").textContent = a.rule_detected ? "Deterministic" : "AI RAG";
    document.getElementById("metric-cp").textContent = req.charge_point_id || "—";

    updateFleet(req.charge_point_id, isThreat);
}

function updateFleet(cpId, isThreat) {
    if (!cpId) return;
    const key = cpId.toLowerCase().replace("cp-", "").split("-")[0];
    const dot = document.querySelector("#cp-" + key + " .fleet-dot");
    if (dot) dot.className = "fleet-dot " + (isThreat ? "red" : "green");
}

function appendAuditRow(data, req) {
    const tbody = document.getElementById("audit-table-body");
    const empty = tbody.querySelector(".empty-row");
    if (empty) empty.remove();

    const a = data.analysis;
    const isThreat = a.verdict.toLowerCase() === "suspicious";
    const tr = document.createElement("tr");
    tr.innerHTML = `
        <td>${new Date().toLocaleTimeString()}</td>
        <td><strong>${req.charge_point_id || "—"}</strong></td>
        <td><code>${req.action || "—"}</code></td>
        <td><span class="badge-verdict ${isThreat ? "suspicious" : "normal"}">${a.verdict}</span></td>
        <td>${a.matched_attack_category}</td>
        <td>${data.processing_time_ms} ms</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${a.plain_english_reason}</td>
    `;
    tbody.insertBefore(tr, tbody.firstChild);
}

function filterAuditTable() {
    const q = document.getElementById("table-search").value.toLowerCase();
    document.querySelectorAll("#audit-table-body tr").forEach(r => {
        r.style.display = r.textContent.toLowerCase().includes(q) ? "" : "none";
    });
}

function exportAuditCsv() {
    const rows = document.querySelectorAll("#audit-table-body tr");
    if (!rows.length || rows[0].classList.contains("empty-row")) return alert("No data");

    let csv = "data:text/csv;charset=utf-8,Time,Station,Action,Verdict,Category,Latency,Summary\n";
    rows.forEach(r => {
        const cols = Array.from(r.querySelectorAll("td")).map(t => '"' + t.textContent.replace(/"/g, '""') + '"');
        csv += cols.join(",") + "\n";
    });

    const a = document.createElement("a");
    a.href = encodeURI(csv);
    a.download = "ocpp_sentinel_audit_" + Date.now() + ".csv";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

function openRagModal() {
    if (!currentAnalysisData) return;
    document.getElementById("modal-source-tag").textContent = currentAnalysisData.analysis.source_reference;
    document.getElementById("modal-content-box").textContent =
        "VERDICT: " + currentAnalysisData.analysis.verdict +
        "\n\nREASON:\n" + currentAnalysisData.analysis.plain_english_reason +
        "\n\nSOURCE:\n" + currentAnalysisData.analysis.source_reference;
    document.getElementById("rag-modal").classList.remove("hidden");
}

function closeRagModal(e) {
    document.getElementById("rag-modal").classList.add("hidden");
}
