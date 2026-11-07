export const INCIDENT_STATUS_LABELS = {
  new: "Novo",
  review: "Revisar",
  identified: "Identificado",
  handled: "Tratado",
  discarded: "Descartado",
};

export const INCIDENT_STATUS_VARIANTS = {
  new: "warning",
  review: "error",
  identified: "running",
  handled: "success",
  discarded: "running",
};

export const INCIDENT_TYPE_LABELS = {
  scan: "Varredura",
  "brute-force": "Força bruta",
  ddos: "DDoS",
  botnet: "Botnet",
  phishing: "Phishing",
  spam: "Spam",
  copyright: "Direito autoral",
  "open-service": "Serviço exposto",
  exploit: "Exploração",
  other: "Outro",
};

export const MESSAGE_STATUS_LABELS = {
  processed: "Processada",
  unrecognized: "Não reconhecida",
  error: "Erro",
};

export const MESSAGE_STATUS_VARIANTS = {
  processed: "success",
  unrecognized: "warning",
  error: "error",
};

export const PARSER_LABELS = {
  xarf: "X-ARF",
  arf: "ARF",
  csv: "CSV",
  text: "Texto livre",
};

export const PUBLIC_KIND_LABELS = {
  cgnat: "CGNAT",
  dedicated: "IP público dedicado (fora do CGNAT)",
  ipv6: "IPv6 (sem CGNAT)",
};

export const ALLOCATION_LABELS = {
  interleaved: "Intercalada (A10 use-all-nat-ips)",
  sequential: "Sequencial",
};

// Fuso do navegador, para exibir junto do UTC.
export const LOCAL_TIMEZONE = Intl.DateTimeFormat().resolvedOptions().timeZone;

export function formatUtc(value) {
  if (!value) return "—";
  return new Date(value).toLocaleString("pt-BR", { timeZone: "UTC" }) + " UTC";
}

export function formatLocal(value) {
  if (!value) return "—";
  return new Date(value).toLocaleString("pt-BR");
}

// <input type="datetime-local"> (horário local) -> ISO em UTC para a API.
export function localInputToUtcIso(value) {
  if (!value) return "";
  return new Date(value).toISOString();
}

export const AUDIT_ACTION_LABELS = {
  discard: "Descartou incidente",
  restore: "Restaurou incidente",
  list: "Listou incidentes",
  view: "Abriu incidente",
  update: "Alterou incidente",
  export_csv: "Exportou CSV",
  list_messages: "Listou mensagens",
  view_raw: "Viu e-mail",
  download_raw: "Baixou .eml",
  reprocess: "Reprocessou mensagem",
  rule_change: "Alterou regra de CGNAT",
  settings_change: "Alterou configurações",
  access_grant: "Concedeu acesso",
  access_revoke: "Removeu acesso",
  anonymize: "Anonimizou incidente",
  purge_raw: "Apagou .eml",
  list_audit: "Consultou o log",
};
