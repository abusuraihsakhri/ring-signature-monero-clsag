"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

function element(values = {}) {
  return {
    value: "",
    textContent: "",
    checked: false,
    disabled: false,
    listeners: {},
    addEventListener(event, callback) { this.listeners[event] = callback; },
    ...values,
  };
}
const fields = {
  "task_id": element({ value: "DEMO-01" }),
  "target_id": element({ value: "KEY-01" }),
  "primary_metric": element({ value: "30" }),
  "secondary_metric": element({ value: "14" }),
  "status_descriptor": element({ value: "DISCORDANT" }),
  "is_critical": element({ checked: true }),
  "run-audit": element(),
  "export-json": element(),
  "m-tasks": element({ textContent: "0" }),
  "m-audit": element({ textContent: "0" }),
  "m-status": element(),
  "outputConsole": element(),
  "mode-badge": element(),
};
const context = {
  document: { getElementById(id) { assert.ok(fields[id], id); return fields[id]; } },
  location: { hostname: "example.github.io", protocol: "https:" },
  console,
};
vm.runInNewContext(fs.readFileSync("web/app.js", "utf8"), context);

(async function () {
  await fields["run-audit"].listeners.click();
  let dossier = JSON.parse(fields.outputConsole.textContent);
  assert.equal(dossier.mode, "local-threshold-demonstration");
  assert.equal(dossier.overall_urgency, "CRITICAL_STAT_PANIC");
  assert.equal(dossier.total_alerts, 3);
  assert.equal(dossier.audit_hash, null);
  assert.equal(fields["m-tasks"].textContent, "1");
  assert.equal(fields["m-audit"].textContent, "0");
  assert.equal(fields["export-json"].disabled, false);

  fields["primary_metric"].value = "2";
  fields["secondary_metric"].value = "2";
  fields["status_descriptor"].value = "NOMINAL";
  fields["is_critical"].checked = false;
  await fields["run-audit"].listeners.click();
  dossier = JSON.parse(fields.outputConsole.textContent);
  assert.equal(dossier.overall_urgency, "ROUTINE");
  assert.equal(dossier.total_alerts, 0);

  fields["primary_metric"].value = "";
  await fields["run-audit"].listeners.click();
  assert.match(fields.outputConsole.textContent, /failed/i);
  assert.equal(fields["m-tasks"].textContent, "2");
  console.log("Browser demo smoke tests passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
