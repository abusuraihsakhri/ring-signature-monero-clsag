"use strict";

// Browser-only demonstration of the repository's threshold rules.
// This is not Monero CLSAG validation and never creates cryptographic audit records.
(function () {
  const el = (id) => document.getElementById(id);
  let lastDossier = null;
  let processed = 0;
  let signed = 0;

  function evaluateLocally(payload) {
    const alerts = [];
    function add(worker, urgency, summary, details) {
      alerts.push({
        origin_worker: worker,
        urgency: urgency,
        summary: summary,
        technical_details: details,
      });
    }
    if (payload.primary_metric > 25) {
      add("InvariantQCWorker", "ELEVATED_RISK", "Primary Metric Threshold Exceeded",
        "Primary metric exceeds the demonstration threshold of 25.");
    }
    if (payload.is_critical_flag || payload.secondary_metric > 12) {
      add("SafetyEscalationWorker",
        payload.is_critical_flag ? "CRITICAL_STAT_PANIC" : "ELEVATED_RISK",
        "Safety Threshold Triggered",
        "Secondary metric exceeds 12 or the critical flag is enabled.");
    }
    if (["DISCORDANT", "ANOMALY", "MUTANT", "VIOLATION", "FAIL", "REJECT"].some(
      (term) => payload.status_descriptor.toUpperCase().includes(term)
    )) {
      add("ProtocolConformanceWorker", "ELEVATED_RISK",
        "Descriptor Flag Detected", "Descriptor contains an alert keyword.");
    }
    const critical = alerts.filter((a) => a.urgency === "CRITICAL_STAT_PANIC").length;
    const elevated = alerts.some((a) => a.urgency === "ELEVATED_RISK");
    const urgency = critical ? "CRITICAL_STAT_PANIC" :
      (elevated ? "ELEVATED_RISK" : "ROUTINE");
    return {
      mode: "local-threshold-demonstration",
      task_id: payload.task_id,
      target_identifier: payload.target_identifier,
      overall_urgency: urgency,
      integrity_status: critical ? "RECALIBRATION_REQUIRED" :
        (elevated ? "DISCORDANT_ANOMALY" : "VALIDATED_OPTIMAL"),
      total_alerts: alerts.length,
      critical_alerts_count: critical,
      alerts: alerts,
      audit_hash: null,
      note: "Local threshold demonstration only. No CLSAG signing, verification, key-image checks or cryptographic audit log.",
    };
  }

  function readPayload() {
    const task = el("task_id").value.trim();
    const target = el("target_id").value.trim();
    const primary = Number(el("primary_metric").value);
    const secondary = Number(el("secondary_metric").value);
    if (!task || !target || !el("primary_metric").value || !el("secondary_metric").value ||
        !Number.isFinite(primary) || !Number.isFinite(secondary)) {
      throw new Error("Provide identifiers and two finite numeric metrics.");
    }
    return {
      task_id: task,
      target_identifier: target,
      primary_metric: primary,
      secondary_metric: secondary,
      status_descriptor: el("status_descriptor").value.trim() || "NOMINAL",
      is_critical_flag: el("is_critical").checked,
    };
  }

  function isLocalBackend() {
    return (location.protocol === "http:" || location.protocol === "https:") &&
      ["localhost", "127.0.0.1", "::1"].includes(location.hostname);
  }

  async function runAudit() {
    const terminal = el("outputConsole");
    const button = el("run-audit");
    button.disabled = true;
    terminal.textContent = "Evaluating input...";
    lastDossier = null;
    el("export-json").disabled = true;
    try {
      const payload = readPayload();
      const browserDemo = !isLocalBackend();
      let result;
      if (browserDemo) {
        result = evaluateLocally(payload);
      } else {
        const response = await fetch("/api/audit", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        if (!response.ok) {
          throw new Error("Backend HTTP " + response.status +
            ". Check API availability and input validation.");
        }
        result = await response.json();
        if (!result || typeof result !== "object") {
          throw new Error("Unexpected API response.");
        }
        result.mode = "backend-api";
      }
      lastDossier = result;
      processed += 1;
      if (result.audit_hash && result.mode === "backend-api") signed += 1;
      el("m-tasks").textContent = String(processed);
      el("m-audit").textContent = String(signed);
      el("m-status").textContent = result.overall_urgency || "UNKNOWN";
      terminal.textContent = JSON.stringify(result, null, 2);
      el("export-json").disabled = false;
    } catch (error) {
      el("m-status").textContent = "ERROR";
      terminal.textContent = "Evaluation failed: " + error.message +
        "\nNo successful audit was recorded.";
    } finally {
      button.disabled = false;
    }
  }

  function exportJson() {
    if (!lastDossier) return;
    const blob = new Blob([JSON.stringify(lastDossier, null, 2) + "\n"],
      { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "threshold-evaluation.json";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  el("run-audit").addEventListener("click", runAudit);
  el("export-json").addEventListener("click", exportJson);
  const demo = !isLocalBackend();
  el("mode-badge").textContent = demo ? "Local demonstration" : "Backend API";
  el("outputConsole").textContent = demo ?
    "Local threshold demonstration ready. Inputs are processed in this browser; no CLSAG cryptography is performed." :
    "Backend API mode. Start the local FastAPI server before evaluating.";
})();
