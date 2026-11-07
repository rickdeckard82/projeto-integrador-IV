#!/usr/bin/env bash
# Backup diário do Ofícios RPZ: banco + anexos + configuração (.env e ssh/), criptografado
# com age, com rotação local (diários/semanais) e cópia para o servidor remoto.
# Configuração em /etc/oficios-rpz/backup.env (ver backup.env.example e README).
set -euo pipefail
SCRIPT_NAME=backup
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
load_config
umask 077

[[ -n "${BACKUP_REMOTE_TARGET:-}" ]] || fail "BACKUP_REMOTE_TARGET não configurado: o backup precisa sair do servidor"

db_name="$(project_env MYSQL_DATABASE oficios_rpz)"
db_user="$(project_env MYSQL_USER)"
db_password="$(project_env MYSQL_PASSWORD)"
[[ -n "$db_user" && -n "$db_password" ]] || fail "MYSQL_USER/MYSQL_PASSWORD não encontrados no .env do projeto"
upload_path="$(project_env HOST_UPLOAD_PATH ./uploads)"
[[ "$upload_path" == /* ]] || upload_path="$PROJECT_DIR/${upload_path#./}"
[[ -d "$upload_path" ]] || fail "pasta de anexos não encontrada: $upload_path"

prod_mysql() { compose exec -T -e MYSQL_PWD="$db_password" db mysql -u"$db_user" -D"$db_name" "$@"; }

stamp="$(date +%Y%m%d-%H%M%S)"
name="oficios-rpz-$stamp"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
stage="$work/$name"
mkdir "$stage"

log "iniciando $name"

# Contagem antes e depois do dump: o teste de restauração aceita valores nesse intervalo.
table_counts prod_mysql > "$work/before.tsv"
compose exec -T -e MYSQL_PWD="$db_password" db \
  mysqldump -u"$db_user" --single-transaction --routines --triggers --no-tablespaces "$db_name" \
  | gzip > "$stage/database.sql.gz"
table_counts prod_mysql > "$work/after.tsv"
gzip -dc "$stage/database.sql.gz" | tail -n1 | grep -q '^-- Dump completed' \
  || fail "dump do banco incompleto"
LC_ALL=C join -t $'\t' "$work/before.tsv" "$work/after.tsv" \
  | awk -F'\t' '{ lo = ($2 < $3) ? $2 : $3; hi = ($2 < $3) ? $3 : $2; print $1 "\t" lo "\t" hi }' \
  > "$stage/row-counts.tsv"
log "banco: $(wc -l < "$stage/row-counts.tsv") tabelas, $(du -h "$stage/database.sql.gz" | cut -f1)"

tar -C "$upload_path" -czf "$stage/uploads.tar.gz" .
tar -tzf "$stage/uploads.tar.gz" | grep -vc '/$' > "$stage/upload-file-count" || true
log "anexos: $(cat "$stage/upload-file-count") arquivos, $(du -h "$stage/uploads.tar.gz" | cut -f1)"

tar -C "$PROJECT_DIR" -czf "$stage/config.tar.gz" .env ssh
cp "$PROJECT_DIR/VERSION" "$stage/VERSION"

archive="$BACKUP_DIR/daily/$name.tar.age"
tar -C "$work" -cf - "$name" \
  | age -r "$(age-keygen -y "$BACKUP_AGE_IDENTITY")" -o "$archive.partial"
age -d -i "$BACKUP_AGE_IDENTITY" "$archive.partial" | tar -tf - > /dev/null \
  || fail "arquivo criptografado não pôde ser lido de volta"
mv "$archive.partial" "$archive"
log "gerado $archive ($(du -h "$archive" | cut -f1))"

if [[ "$(date +%u)" == 7 ]]; then
  ln -f "$archive" "$BACKUP_DIR/weekly/$name.tar.age"
  log "cópia semanal registrada"
fi

prune() {
  find "$1" -maxdepth 1 -name 'oficios-rpz-*.tar.age' | sort -r | tail -n +"$(($2 + 1))" | xargs -r rm -f --
}
prune "$BACKUP_DIR/daily" "$BACKUP_KEEP_DAILY"
prune "$BACKUP_DIR/weekly" "$BACKUP_KEEP_WEEKLY"

# Sem --delete: o destino guarda o histórico e cuida da própria retenção (ver README).
# "host::modulo" usa o rsync daemon (os arquivos já saem criptografados); o resto vai por ssh.
rsync_opts=(-a --ignore-existing)
if [[ "$BACKUP_REMOTE_TARGET" == *::* || "$BACKUP_REMOTE_TARGET" == rsync://* ]]; then
  [[ -z "${BACKUP_RSYNC_PASSWORD_FILE:-}" ]] || rsync_opts+=(--password-file="$BACKUP_RSYNC_PASSWORD_FILE")
else
  rsync_opts+=(-e "ssh -p $BACKUP_REMOTE_PORT -i $BACKUP_REMOTE_SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$BACKUP_REMOTE_KNOWN_HOSTS")
fi
rsync "${rsync_opts[@]}" "$BACKUP_DIR/daily" "$BACKUP_DIR/weekly" "$BACKUP_REMOTE_TARGET"
log "copiado para $BACKUP_REMOTE_TARGET"

mark_success backup_last_success
log "concluído"
