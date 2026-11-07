# Funções comuns de backup.sh e restore-test.sh. Não executar direto.

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG_FILE="${BACKUP_CONFIG:-/etc/oficios-rpz/backup.env}"

log() { printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$SCRIPT_NAME" "$*"; }
fail() { log "ERRO: $*"; exit 1; }

# Lê uma variável do .env do projeto sem executá-lo (senhas podem ter caracteres especiais).
project_env() {
  local value
  value="$(grep -E "^$1=" "$PROJECT_DIR/.env" | tail -n1 | cut -d= -f2- || true)"
  value="${value%\"}"
  value="${value#\"}"
  printf '%s' "${value:-$2}"
}

load_config() {
  [[ -r "$CONFIG_FILE" ]] || fail "configuração não encontrada: $CONFIG_FILE"
  # shellcheck source=/dev/null
  source "$CONFIG_FILE"
  BACKUP_DIR="${BACKUP_DIR:-/var/backups/oficios-rpz}"
  BACKUP_AGE_IDENTITY="${BACKUP_AGE_IDENTITY:-/etc/oficios-rpz/backup-age.key}"
  BACKUP_KEEP_DAILY="${BACKUP_KEEP_DAILY:-7}"
  BACKUP_KEEP_WEEKLY="${BACKUP_KEEP_WEEKLY:-4}"
  BACKUP_STATUS_DIR="${BACKUP_STATUS_DIR:-/var/lib/oficios-rpz-backup}"
  BACKUP_REMOTE_PORT="${BACKUP_REMOTE_PORT:-22}"
  BACKUP_REMOTE_SSH_KEY="${BACKUP_REMOTE_SSH_KEY:-/etc/oficios-rpz/backup_ssh_key}"
  BACKUP_REMOTE_KNOWN_HOSTS="${BACKUP_REMOTE_KNOWN_HOSTS:-/etc/oficios-rpz/backup_known_hosts}"

  command -v age >/dev/null || fail "age não está instalado (apt install age)"
  [[ -r "$BACKUP_AGE_IDENTITY" ]] || fail "chave age não encontrada: $BACKUP_AGE_IDENTITY"
  install -d -m 700 "$BACKUP_DIR/daily" "$BACKUP_DIR/weekly"
  install -d -m 755 "$BACKUP_STATUS_DIR"
}

compose() {
  docker compose -f "$PROJECT_DIR/docker-compose.yml" --project-directory "$PROJECT_DIR" "$@"
}

# Imprime "tabela<TAB>linhas" de todas as tabelas, ordenado. Recebe o comando mysql a usar.
table_counts() {
  local tables table query=""
  tables="$("$@" -N -B -e "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'")"
  [[ -n "$tables" ]] || fail "nenhuma tabela encontrada no banco"
  for table in $tables; do
    query+="${query:+ UNION ALL }SELECT '$table', COUNT(*) FROM \`$table\`"
  done
  "$@" -N -B -e "$query" | LC_ALL=C sort
}

# Grava o horário (epoch) do último sucesso, para monitoramento (ex.: Zabbix).
mark_success() {
  date +%s > "$BACKUP_STATUS_DIR/$1"
  chmod 644 "$BACKUP_STATUS_DIR/$1"
}
