import { api } from "./client.js";

export function listOffices({ page = 1, perPage = 20, q = "" } = {}) {
  const params = new URLSearchParams({ page, per_page: perPage });
  if (q) params.set("q", q);
  return api.get(`/offices?${params.toString()}`);
}

export function getOffice(id) {
  return api.get(`/offices/${id}`);
}

export function createOffice({ officeNumber, processNumber, seiNumbers, expeditionDate, intimationFile }) {
  if (intimationFile) {
    const formData = new FormData();
    if (officeNumber) formData.append("office_number", officeNumber);
    formData.append("process_number", processNumber);
    if (seiNumbers) formData.append("sei_numbers", seiNumbers);
    if (expeditionDate) formData.append("expedition_date", expeditionDate);
    formData.append("intimation_pdf", intimationFile);
    return api.postForm("/offices", formData);
  }

  return api.post("/offices", {
    office_number: officeNumber,
    process_number: processNumber,
    sei_numbers: seiNumbers,
    expedition_date: expeditionDate || undefined,
  });
}

export function updateOfficeNumber(id, officeNumber) {
  return api.patch(`/offices/${id}`, { office_number: officeNumber });
}

export function deleteOffice(id, confirmOfficeNumber) {
  return api.delete(`/offices/${id}`, { confirm_office_number: confirmOfficeNumber });
}

export function addOfficeDomainFiles(id, files, removalDate, redirectTarget) {
  const formData = new FormData();
  for (const file of files) formData.append("domain_files", file);
  if (removalDate) formData.append("removal_date", removalDate);
  if (redirectTarget) formData.append("redirect_target", redirectTarget);
  return api.postForm(`/offices/${id}/domains/files`, formData);
}

export function addOfficeManualDomains(id, domainsText, removalDate, redirectTarget) {
  return api.post(`/offices/${id}/domains/manual`, {
    domains: domainsText,
    removal_date: removalDate || undefined,
    redirect_target: redirectTarget || undefined,
  });
}

export function addOfficeIpFiles(id, files, removalDate) {
  const formData = new FormData();
  for (const file of files) formData.append("ip_files", file);
  if (removalDate) formData.append("removal_date", removalDate);
  return api.postForm(`/offices/${id}/ips/files`, formData);
}

export function addOfficeManualIps(id, ipsText, removalDate) {
  return api.post(`/offices/${id}/ips/manual`, {
    ips: ipsText,
    removal_date: removalDate || undefined,
  });
}

export function updateOfficeDomainsRemovalDate(id, removalDate) {
  return api.patch(`/offices/${id}/domains/removal-date`, { removal_date: removalDate || "" });
}

export function updateOfficeIpsRemovalDate(id, removalDate) {
  return api.patch(`/offices/${id}/ips/removal-date`, { removal_date: removalDate || "" });
}

export function toggleOfficeDomains(id) {
  return api.post(`/offices/${id}/disable-domains`);
}

export function toggleOfficeIps(id) {
  return api.post(`/offices/${id}/toggle-ips`);
}

export function deployOfficeIpRoutes(id) {
  return api.post(`/offices/${id}/deploy-ips`, { confirm: true });
}

export function deployOfficeExpiredIpsDelete(id) {
  return api.post(`/offices/${id}/deploy-expired-ips-delete`, { confirm: true });
}

export function setOfficeNotification(id, sent) {
  return api.put(`/offices/${id}/notification`, { sent });
}
