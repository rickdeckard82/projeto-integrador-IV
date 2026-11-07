import { api } from "./client.js";

const CONFIRM_PHRASE = "RESTAURAR";

export function restoreDatabase(file) {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("confirm_phrase", CONFIRM_PHRASE);
  return api.postForm("/backup/database/restore", formData);
}

export function restoreFiles(file) {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("confirm_phrase", CONFIRM_PHRASE);
  return api.postForm("/backup/files/restore", formData);
}

export function getBackupSchedule() {
  return api.get("/backup/schedule");
}

export function updateBackupSchedule(payload) {
  return api.put("/backup/schedule", payload);
}

export function testBackupSchedule(payload) {
  return api.post("/backup/schedule/test", payload);
}

export function runBackupNow() {
  return api.post("/backup/schedule/run");
}
