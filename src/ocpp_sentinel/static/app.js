// =============================================================================
// app.js — Frontend Application Logic for OCPP Sentinel UI
// =============================================================================

// Preset Sample Messages mapped to sample filenames
const PRESET_MESSAGES = {
    benign_authorize: {
        message_type_id: 2,
        unique_id: "auth-001",
        action: "Authorize",
        payload: { idTag: "RFID-A1B2C3" },
        charge_point_id: "CP-NORTH-01",
        received_at: "2024-01-15T10:30:00Z",
        context: {
            authorized_id_tags: ["RFID-A1B2C3", "RFID-D4E5F6"],
            known_message_ids: [],
            recent_message_count: 3,
            time_window_seconds: 60
        }
    },
    benign_meter_values: {
        message_type_id: 2,
        unique_id: "meter-001",
        action: "MeterValues",
        payload: {
            connectorId: 1,
            transactionId: 1001,
            meterValue: [
                { timestamp: "2024-01-15T10:30:00Z", sampledValue: [{ value: "100", unit: "Wh" }] },
                { timestamp: "2024-01-15T11:30:00Z", sampledValue: [{ value: "7600", unit: "Wh" }] }
            ]
        },
        charge_point_id: "CP-NORTH-01",
        received_at: "2024-01-15T11:30:05Z",
        context: { authorized_id_tags: [], known_message_ids: [], recent_message_count: 5, time_window_seconds: 60 }
    },
    malicious_spoofing: {
        message_type_id: 2,
        unique_id: "remote-start-666",
        action: "RemoteStartTransaction",
        payload: { idTag: "FAKE-TAG-999", connectorId: 1 },
        charge_point_id: "CP-NORTH-01",
        received_at: "2024-01-15T14:00:00Z",
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
        received_at: "2024-01-15T14:00:05Z",
        context: { authorized_id_tags: [], known_message_ids: [], recent_message_count: 4, time_window_seconds: 60 }
    },
    malicious_repudiation: {
        message_type_id: 2,
        unique_id: "auth-001",
        action: "Authorize",
        payload: { idTag: "RFID-A1B2C3" },
        charge_point_id: "CP-SOUTH-02",
        received_at: "2024-01-15T15:45:00Z",
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
        received_at: "2024-01-15T16:00:03Z",
        context: { authorized_id_tags: ["RFID-A1B2C3"], known_message_ids: [], recent_message_count: 3, time_window_seconds: 60 }
    },
    malicious_dos: {
        message_type_id: 2,
        unique_id: "status-flood-150",
        action: "StatusNotification",
        payload: { connectorId: 1, errorCode: "NoError", status: "Available" },
        charge_point_id: "CP-NORTH-01",
        received_at: "2024-01-15T17:00:01Z",
        context: { authorized_id_tags: [], known_message_ids: [], recent_message_count: 150, time_window_seconds: 60 }
    }
};

// Check Health on Page Load
document.addEventListener("DOMContentLoaded", checkHealth);

async function checkHealth() {
    const badge = document.getElementById("health-text");
    try {
        const res = await fetch("/health");
        const data = await res.json();
        if (data.status === "ok") {
            badge.innerText = `Online (v${data.version} | ${data.kb_chunks} KB Chunks)`;
        } else {
            badge.innerText = "Offline";
        }
    } catch (e) {
        badge.innerText = "API Connection Error";
    }
}

function loadSample(key) {
    const data = PRESET_MESSAGES[key];
    if (data) {
        document.getElementById("json-input").value = JSON.stringify(data, null, 2);
    }
}

function clearEditor() {
    document.getElementById("json-input").value = "";
    document.getElementById("results-placeholder").classList.remove("hidden");
    document.getElementById("results-container").classList.add("hidden");
}

async function analyzeMessage() {
    const rawInput = document.getElementById("json-input").value.trim();
    if (!rawInput) {
        alert("Please paste an OCPP JSON message or select a preset scenario.");
        return;
    }

    let parsedJson;
    try {
        parsedJson = JSON.parse(rawInput);
    } catch (e) {
        alert("Invalid JSON format. Please check syntax.");
        return;
    }

    const btnText = document.getElementById("btn-text");
    btnText.innerText = "⏳ Analyzing...";

    try {
        const res = await fetch("/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: parsedJson })
        });

        const data = await res.json();

        if (res.ok && data.success) {
            renderResults(data);
        } else {
            alert(`Analysis failed: ${data.detail || "Unknown error"}`);
        }
    } catch (e) {
        alert(`Network Error: ${e.message}`);
    } finally {
        btnText.innerText = "⚡ Analyze Message";
    }
}

function renderResults(data) {
    document.getElementById("results-placeholder").classList.add("hidden");
    const container = document.getElementById("results-container");
    container.classList.remove("hidden");

    const analysis = data.analysis;
    const banner = document.getElementById("verdict-banner");
    const icon = document.getElementById("verdict-icon");
    const title = document.getElementById("verdict-title");
    const category = document.getElementById("verdict-category");
    const confidence = document.getElementById("confidence-badge");

    const isSuspicious = analysis.verdict.toLowerCase() === "suspicious";

    banner.className = `verdict-banner ${isSuspicious ? "suspicious" : "normal"}`;
    icon.innerText = isSuspicious ? "🚨" : "🛡️";
    title.innerText = isSuspicious ? "SUSPICIOUS MESSAGE DETECTED" : "NORMAL OPERATIONAL MESSAGE";
    category.innerText = `Attack Category: ${analysis.matched_attack_category}`;
    confidence.innerText = `${(analysis.confidence * 100).toFixed(0)}% Confidence`;

    document.getElementById("reason-text").innerText = analysis.plain_english_reason;
    document.getElementById("citation-text").innerText = analysis.source_reference;
    document.getElementById("metric-time").innerText = `${data.processing_time_ms} ms`;
    document.getElementById("metric-rule").innerText = analysis.rule_detected ? "Yes (Deterministic Rule)" : "No (RAG Analysis)";
}
