import { api, downloadFile } from "./client.js";

function incidentParams(filters = {}) {
  const params = new URLSearchParams();
  if (filters.page) params.set("page", filters.page);
  if (filters.perPage) params.set("per_page", filters.perPage);
  if (filters.status) params.set("status", filters.status);
  if (filters.type) params.set("type", filters.type);
  if (filters.q) params.set("q", filters.q);
  if (filters.from) params.set("from", filters.from);
  if (filters.to) params.set("to", filters.to);
  return params.toString();
}

export function getAbuseStatus() {
  return api.get("/abuse/status");
}

export function listIncidents(filters) {
  return api.get(`/abuse/incidents?${incidentParams(filters)}`);
}

export function exportIncidents(filters) {
  const { page, perPage, ...rest } = filters || {};
  return downloadFile(`/abuse/incidents/export.csv?${incidentParams(rest)}`, "incidentes-abuse.csv");
}

export function getIncident(id) {
  return api.get(`/abuse/incidents/${id}`);
}

export function updateIncident(id, payload) {
  return api.patch(`/abuse/incidents/${id}`, payload);
}

export function discardIncidents(ids, reason) {
  return api.post("/abuse/incidents/discard", { ids, reason });
}

export function restoreIncidents(ids, reason) {
  return api.post("/abuse/incidents/restore", { ids, reason });
}

export function listMessages({ page = 1, status = "", q = "" } = {}) {
  const params = new URLSearchParams({ page });
  if (status) params.set("status", status);
  if (q) params.set("q", q);
  return api.get(`/abuse/messages?${params.toString()}`);
}

export function getMessage(id) {
  return api.get(`/abuse/messages/${id}`);
}

export function downloadRawMessage(id) {
  return downloadFile(`/abuse/messages/${id}/raw`, `abuse-${id}.eml`);
}

export function reprocessMessage(id) {
  return api.post(`/abuse/messages/${id}/reprocess`);
}

export function listCgnatRules() {
  return api.get("/abuse/cgnat-rules");
}

export function importCgnatFiles({ files, validFrom, validTo, notes, dryRun }) {
  const formData = new FormData();
  formData.append("valid_from", validFrom);
  if (validTo) formData.append("valid_to", validTo);
  if (notes) formData.append("notes", notes);
  if (dryRun) formData.append("dry_run", "1");
  for (const file of files) formData.append("files", file);
  return api.postForm("/abuse/cgnat-rules/import", formData);
}

export function createCgnatRule(payload) {
  return api.post("/abuse/cgnat-rules", payload);
}

export function deleteCgnatGroup(group) {
  return api.delete(`/abuse/cgnat-rules/groups/${group}`);
}

export function getAbuseSettings() {
  return api.get("/abuse/settings");
}

export function updateAbuseSettings(payload) {
  return api.put("/abuse/settings", payload);
}

export function setAbuseAccess(userId, abuseAccess) {
  return api.post(`/abuse/users/${userId}/access`, { abuse_access: abuseAccess });
}

export function listAudit({ page = 1, action = "", user = "", incident = "", message = "", from = "", to = "" } = {}) {
  const params = new URLSearchParams({ page });
  if (action) params.set("action", action);
  if (user) params.set("user", user);
  if (incident) params.set("incident", incident);
  if (message) params.set("message", message);
  if (from) params.set("from", from);
  if (to) params.set("to", to);
  return api.get(`/abuse/audit?${params.toString()}`);
}

export function reprocessMessages({ statuses = ["unrecognized"], afterId = 0 } = {}) {
  return api.post("/abuse/messages/reprocess", { statuses, after_id: afterId });
}
