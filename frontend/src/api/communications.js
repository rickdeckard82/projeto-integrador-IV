import { api } from "./client.js";

export function sendCommunication({ officeId, recipients, subject, body, attachZone, attachIps, files }) {
  // multipart/form-data: leva também os arquivos escolhidos no computador.
  const formData = new FormData();
  if (officeId) formData.append("office_id", officeId);
  formData.append("recipients", recipients);
  formData.append("subject", subject);
  formData.append("body", body);
  if (attachZone) formData.append("attach_zone", "true");
  if (attachIps) formData.append("attach_ips", "true");
  for (const file of files) formData.append("attachments", file);
  return api.postForm("/communications/send", formData);
}

export function listSentEmails({ page = 1, perPage = 10 } = {}) {
  const params = new URLSearchParams({ page, per_page: perPage });
  return api.get(`/communications/emails?${params.toString()}`);
}
