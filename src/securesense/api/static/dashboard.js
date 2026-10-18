"use strict";

const $ = (selector) => document.querySelector(selector);

function setText(selector, value) {
  $(selector).textContent = value;
}

function showNotice(selector, message, type = "error") {
  const element = $(selector);
  element.textContent = message;
  element.className = `notice ${type === "error" ? "notice-error" : "notice-success"}`;
  element.hidden = false;
}

function hideNotice(selector) {
  $(selector).hidden = true;
}

let apiToken = "";

$("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  apiToken = $("#api-token").value.trim();
  await refreshDashboard();
});

function safeDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(apiToken ? { Authorization: `Bearer ${apiToken}` } : {}),
      ...(options.headers || {}),
    },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = typeof body.detail === "string" ? body.detail : `HTTP ${response.status}`;
    throw new Error(detail);
  }
  return body;
}

function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined && text !== null) element.textContent = String(text);
  return element;
}

function appendField(parent, label, value) {
  const line = makeElement("p");
  line.append(makeElement("strong", "", `${label}: `), document.createTextNode(value ?? "—"));
  parent.append(line);
}

function renderEventResults(container, results) {
  if (!Array.isArray(results) || results.length === 0) {
    container.append(makeElement("p", "muted", "No event results were returned."));
    return;
  }

  results.forEach((item, index) => {
    const card = makeElement("article", "evidence-card");
    const finding = item.finding;
    const incident = item.incident;
    card.append(makeElement("h3", "", `Event ${index + 1} · ${finding?.rule_id || "No finding"}`));
    const decision = makeElement("span", `pill ${item.allowed ? "pill-safe" : "pill-danger"}`,
      item.allowed ? "POLICY ALLOWED" : "POLICY VIOLATION");
    card.append(decision);
    appendField(card, "Decision", item.decision_reason || "—");

    if (finding) {
      appendField(card, "Finding", `${finding.title} (${finding.severity})`);
      appendField(card, "Description", finding.description);
      appendField(card, "Evidence", JSON.stringify(finding.evidence || {}));
      appendField(card, "Recommendation", finding.recommendation);
      appendField(card, "Observed at", safeDate(finding.observed_at));
    } else {
      appendField(card, "Finding", "No finding generated");
    }

    if (item.risk_assessment) {
      appendField(card, "Risk", `${item.risk_assessment.score} · ${item.risk_assessment.band}`);
      appendField(card, "Risk rationale", item.risk_assessment.rationale);
    }
    if (incident) {
      appendField(card, "Incident", `${incident.incident_id} · ${incident.status}`);
      appendField(card, "Incident risk score", incident.risk_score);
    }
    container.append(card);
  });
}

function renderPaths(container, paths) {
  container.append(makeElement("h3", "", "Candidate attack paths"));
  if (!Array.isArray(paths) || paths.length === 0) {
    container.append(makeElement("p", "muted", "No candidate attack paths were identified."));
    return;
  }

  paths.forEach((path, index) => {
    const card = makeElement("article", "evidence-card");
    card.append(makeElement("h3", "", `Candidate path ${index + 1}`));
    card.append(makeElement("span", "pill", path.classification || "Candidate"));
    appendField(card, "Shared IPs", (path.shared_ips || []).join(", ") || "None");
    appendField(card, "Rationale", path.rationale);
    appendField(card, "Observed window", `${safeDate(path.observed_start)} — ${safeDate(path.observed_end)}`);
    appendField(card, "Linked incidents", (path.incident_ids || []).join(", ") || "None");
    card.append(makeElement("p", "muted", "Requires analyst validation; this is not a confirmed attack path."));
    container.append(card);
  });
}

function renderInvestigationResult(result, savedRecord = null) {
  const panel = $("#result-panel");
  const container = $("#result-content");
  container.replaceChildren();

  setText("#result-summary",
    `${result.investigation_id || savedRecord?.investigation_id || "Investigation"} · ${result.events_investigated ?? 0} event(s)`);

  const metrics = makeElement("div", "result-metrics");
  [
    ["Events", result.events_investigated ?? 0],
    ["Findings", result.findings_count ?? 0],
    ["Incidents", result.incidents_count ?? 0],
    ["Candidate paths", result.candidate_attack_paths_count ?? 0],
  ].forEach(([label, value]) => {
    const metric = makeElement("div", "result-metric");
    metric.append(makeElement("strong", "", value), makeElement("span", "", label));
    metrics.append(metric);
  });
  container.append(metrics);
  renderEventResults(container, result.event_results);
  renderPaths(container, result.candidate_attack_paths);
  container.append(makeElement("p", "muted", result.response_execution || "No response actions were executed."));
  panel.hidden = false;
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function loadHealth() {
  try {
    const data = await api("/health");
    setText("#api-status", "Online");
    setText("#api-detail", data.service || "API responding");
    setText("#sidebar-status", "API connected");
    $("#sidebar-dot").className = "status-dot ok";
  } catch (error) {
    setText("#api-status", "Offline");
    setText("#api-detail", error.message);
    setText("#sidebar-status", "API unavailable");
    $("#sidebar-dot").className = "status-dot bad";
  }
}

async function loadDevices() {
  const data = await api("/devices");
  setText("#device-count", data.count ?? data.devices?.length ?? 0);
}

async function loadHistory() {
  const loading = $("#history-loading");
  const empty = $("#history-empty");
  const errorBox = $("#history-error");
  const wrap = $("#history-table-wrap");
  const rows = $("#history-rows");

  loading.hidden = false;
  empty.hidden = true;
  errorBox.hidden = true;
  wrap.hidden = true;
  rows.replaceChildren();

  try {
    const data = await api("/investigations");
    const investigations = Array.isArray(data.investigations) ? data.investigations : [];
    setText("#investigation-count", data.count ?? investigations.length);
    setText("#history-count", `${investigations.length} record(s)`);
    let totalPaths = 0;

    investigations.forEach((record) => {
      const result = record.result || {};
      totalPaths += Number(result.candidate_attack_paths_count || 0);
      const row = makeElement("tr");
      row.append(
        makeElement("td", "mono", record.investigation_id || "—"),
        makeElement("td", "", safeDate(record.created_at)),
        makeElement("td", "", result.events_investigated ?? record.events?.length ?? 0),
        makeElement("td", "", result.findings_count ?? 0),
        makeElement("td", "", result.incidents_count ?? 0),
      );
      const actionCell = makeElement("td");
      const button = makeElement("button", "text-link", "View evidence");
      button.type = "button";
      button.addEventListener("click", () => loadSavedInvestigation(record.investigation_id));
      actionCell.append(button);
      row.append(actionCell);
      rows.append(row);
    });

    setText("#path-count", totalPaths);
    loading.hidden = true;
    if (investigations.length === 0) empty.hidden = false;
    else wrap.hidden = false;
  } catch (error) {
    loading.hidden = true;
    errorBox.textContent = `Could not load investigation history: ${error.message}`;
    errorBox.hidden = false;
    setText("#investigation-count", "—");
    setText("#path-count", "—");
    setText("#history-count", "Unavailable");
  }
}

async function loadSavedInvestigation(id) {
  try {
    const record = await api(`/investigations/${encodeURIComponent(id)}`);
    renderInvestigationResult(
      { ...record.result, investigation_id: record.investigation_id },
      record,
    );
  } catch (error) {
    showNotice("#global-error", `Could not load investigation: ${error.message}`);
  }
}

function renderTelemetry(readings) {
  const grid = $("#telemetry-grid");
  grid.replaceChildren();

  for (const reading of readings) {
    const card = makeElement("article", "telemetry-card");
    const heading = makeElement("div", "telemetry-card-heading");
    heading.append(
      makeElement("span", "telemetry-device", reading.device_id),
      makeElement("span", "telemetry-metric", reading.metric),
    );

    card.append(
      heading,
      makeElement("div", "telemetry-value", `${reading.value} ${reading.unit}`),
      makeElement("p", "telemetry-timestamp", `Sensor time: ${safeDate(reading.timestamp)}`),
      makeElement("p", "telemetry-timestamp", `Received: ${safeDate(reading.received_at)}`),
    );
    grid.append(card);
  }

  $("#telemetry-loading").hidden = true;
  $("#telemetry-empty").hidden = readings.length > 0;
}

async function loadTelemetry() {
  try {
    const data = await api("/telemetry/latest");
    const readings = Array.isArray(data.readings) ? data.readings : [];
    renderTelemetry(readings);
    hideNotice("#telemetry-error");
    setText("#telemetry-updated", `Updated ${new Date().toLocaleTimeString()}`);
  } catch (error) {
    $("#telemetry-loading").hidden = true;
    showNotice("#telemetry-error", `Could not load sensor telemetry: ${error.message}`);
    setText("#telemetry-updated", "Refresh failed");
  }
}

async function refreshDashboard() {
  hideNotice("#global-error");
  await loadHealth();

  try {
    await loadDevices();
  } catch (error) {
    setText("#device-count", "—");
    showNotice("#global-error", `Device data unavailable: ${error.message}`);
  }

  await loadHistory();
  await loadTelemetry();
}

function setTimestampDefault() {
  const now = new Date();
  now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
  $("#event-timestamp").value = now.toISOString().slice(0, 19);
}

$("#refresh-button").addEventListener("click", refreshDashboard);
$("#telemetry-refresh").addEventListener("click", loadTelemetry);
window.setInterval(() => {
  if (apiToken) loadTelemetry();
}, 10000);
$("#hide-result").addEventListener("click", () => { $("#result-panel").hidden = true; });

$("#event-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#submit-event");
  const form = event.currentTarget;
  const values = new FormData(form);
  const payload = {
    events: [{
      device_id: String(values.get("device_id")).trim(),
      source_ip: String(values.get("source_ip")).trim(),
      destination: String(values.get("destination")).trim(),
      destination_ip: String(values.get("destination_ip")).trim(),
      protocol: values.get("protocol"),
      destination_port: Number(values.get("destination_port")),
      network_zone: String(values.get("network_zone")).trim(),
      timestamp: new Date(String(values.get("timestamp"))).toISOString(),
    }],
  };

  button.disabled = true;
  button.textContent = "Investigating…";
  hideNotice("#form-message");

  try {
    const result = await api("/investigations", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    showNotice("#form-message", "Investigation completed and saved.", "success");
    renderInvestigationResult(result);
    await refreshDashboard();
  } catch (error) {
    showNotice("#form-message", `Investigation failed: ${error.message}`);
  } finally {
    button.disabled = false;
    button.textContent = "Run investigation →";
  }
});

setTimestampDefault();
refreshDashboard();
