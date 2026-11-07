export const DEPLOYMENT_LABELS = {
  rpz: "RPZ",
  router: "Roteador (geral)",
  "router-office": "Roteador (ofício)",
  "router-office-expired-delete": "Roteador (remoção de expirados)",
  "restore-database": "Restauração do banco",
  "restore-files": "Restauração dos arquivos",
  "backup-ftp": "Backup automático (FTP)",
};

export const DEPLOYMENT_TYPE_OPTIONS = [
  { value: "", label: "Todos os tipos" },
  { value: "rpz", label: "RPZ" },
  { value: "router", label: "Roteador (geral)" },
  { value: "router-office", label: "Roteador (ofício)" },
  { value: "router-office-expired-delete", label: "Roteador (remoção de expirados)" },
  { value: "restore-database", label: "Restauração do banco" },
  { value: "restore-files", label: "Restauração dos arquivos" },
  { value: "backup-ftp", label: "Backup automático (FTP)" },
];

export const DEPLOYMENT_STATUS_OPTIONS = [
  { value: "", label: "Todos os status" },
  { value: "success", label: "Sucesso" },
  { value: "error", label: "Erro" },
  { value: "running", label: "Em andamento" },
];
