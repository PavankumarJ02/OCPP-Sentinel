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
