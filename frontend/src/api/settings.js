import { api } from "./client.js";

export function getCompanySettings() {
  return api.get("/company-settings");
}

export function updateCompanySettings(payload) {
  return api.put("/company-settings", payload);
}

export function getParameterSettings() {
  return api.get("/parameter-settings");
}

export function updateParameterSettings(payload) {
  return api.put("/parameter-settings", payload);
}

export function getCommunicationsConfig() {
  return api.get("/communications-config");
}

export function testSmtpSettings(payload) {
  return api.post("/parameter-settings/smtp-test", payload);
}

export function testImapSettings(payload) {
  return api.post("/parameter-settings/imap-test", payload);
}
