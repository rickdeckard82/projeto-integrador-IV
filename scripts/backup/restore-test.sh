#!/usr/bin/env bash
# Teste de restauração: descriptografa o backup mais recente (ou o arquivo passado como
# argumento), restaura o banco num MySQL descartável sem rede e confere contagem de linhas,
# anexos e configuração. Não toca no banco nem nos arquivos de produção.
set -euo pipefail
SCRIPT_NAME=restore-test
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
load_config
umask 077

archive="${1:-$(find "$BACKUP_DIR/daily" -maxdepth 1 -name 'oficios-rpz-*.tar.age' | sort | tail -n1)}"
[[ -n "$archive" && -f "$archive" ]] || fail "nenhum backup encontrado em $BACKUP_DIR/daily"

container="oficios-rpz-restore-test-$$"
work="$(mktemp -d)"
cleanup() {
  docker rm -f "$container" > /dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

log "testando $archive"
age -d -i "$BACKUP_AGE_IDENTITY" "$archive" | tar -C "$work" -xf - \
  || fail "não foi possível descriptografar ou extrair $archive"
stage="$(find "$work" -mindepth 1 -maxdepth 1 -type d | head -n1)"
for file in database.sql.gz row-counts.tsv uploads.tar.gz upload-file-count config.tar.gz; do
  [[ -f "$stage/$file" ]] || fail "arquivo ausente no backup: $file"
done

# Mesma imagem do MySQL de produção.
image="$(docker inspect "$(compose ps -q db)" --format '{{.Config.Image}}')"
root_password="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
docker run -d --name "$container" --network none \
  -e MYSQL_ROOT_PASSWORD="$root_password" -e MYSQL_DATABASE=restore_test \
  "$image" > /dev/null

# TCP em vez de socket: o servidor temporário da inicialização da imagem só escuta no socket.
test_mysql() {
  docker exec -i -e MYSQL_PWD="$root_password" "$container" \
    mysql -uroot -h127.0.0.1 --protocol=TCP -Drestore_test "$@"
}
for _ in $(seq 1 90); do
  test_mysql -e 'SELECT 1' > /dev/null 2>&1 && break
  sleep 2
done
test_mysql -e 'SELECT 1' > /dev/null 2>&1 || fail "MySQL descartável não subiu ($image)"

gzip -dc "$stage/database.sql.gz" | test_mysql
log "banco restaurado em container descartável ($image)"

problems=()

table_counts test_mysql > "$work/restored.tsv"
while IFS= read -r line; do
  problems+=("$line")
done < <(awk -F'\t' '
  NR == FNR { lo[$1] = $2 + 0; hi[$1] = $3 + 0; next }
  { seen[$1] = 1; if (($1 in lo) && ($2 + 0 < lo[$1] || $2 + 0 > hi[$1]))
      printf "tabela %s: %s linhas restauradas, esperado entre %s e %s\n", $1, $2, lo[$1], hi[$1] }
  END { for (t in lo) if (!(t in seen)) printf "tabela %s ausente após restauração\n", t }
' "$stage/row-counts.tsv" "$work/restored.tsv")

users="$(test_mysql -N -B -e 'SELECT COUNT(*) FROM user')"
[[ "$users" -gt 0 ]] || problems+=("nenhum usuário na tabela user")

mkdir "$work/uploads"
tar -C "$work/uploads" -xzf "$stage/uploads.tar.gz"
restored_files="$(find "$work/uploads" -type f | wc -l)"
expected_files="$(cat "$stage/upload-file-count")"
[[ "$restored_files" -eq "$expected_files" ]] \
  || problems+=("anexos: $restored_files restaurados, esperado $expected_files")

missing=0
while IFS= read -r stored; do
  if [[ ! -f "$work/uploads/$stored" ]]; then
    missing=$((missing + 1))
    if (( missing <= 10 )); then log "anexo citado no banco e ausente: $stored"; fi
  fi
done < <(
  test_mysql -N -B -e 'SELECT stored_filename FROM office_file UNION SELECT stored_filename FROM ip_batch_file'
  # E-mails brutos do módulo de abuse ainda não expurgados pela retenção
  # (a tabela não existe em backups anteriores ao módulo).
  if [[ "$(test_mysql -N -B -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'abuse_message'")" -gt 0 ]]; then
    test_mysql -N -B -e 'SELECT raw_path FROM abuse_message WHERE raw_path IS NOT NULL AND raw_purged_at IS NULL'
  fi
)
(( missing <= 10 )) || log "... e mais $((missing - 10)) anexo(s) ausentes"
[[ "$missing" -eq 0 ]] || problems+=("$missing anexo(s) citados no banco não estão no backup")

config_files="$(tar -tzf "$stage/config.tar.gz")"
grep -qx '\.env' <<< "$config_files" || problems+=("config.tar.gz sem .env")

if (( ${#problems[@]} )); then
  for problem in "${problems[@]}"; do log "FALHA: $problem"; done
  fail "teste de restauração reprovado ($archive)"
fi

log "OK: $(wc -l < "$work/restored.tsv") tabelas, $users usuário(s), $restored_files anexos"
mark_success restore_test_last_success
