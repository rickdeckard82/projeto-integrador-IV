import React, { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Badge from "./Badge.jsx";
import { getBackupSchedule, runBackupNow, testBackupSchedule, updateBackupSchedule } from "../api/backup.js";
import { useToast } from "./Toast.jsx";

const STATUS = {
  success: { variant: "success", label: "Sucesso" },
  error: { variant: "error", label: "Erro" },
  running: { variant: "running", label: "Em andamento" },
};

function formatDate(value) {
  return value ? new Date(value).toLocaleString("pt-BR") : "—";
}

function formFrom(data) {
  return {
    enabled: data.enabled,
    runTime: data.run_time,
    includeDatabase: data.include_database,
    includeFiles: data.include_files,
    keepCount: String(data.keep_count),
    host: data.ftp_host,
    port: String(data.ftp_port),
    user: data.ftp_user,
    password: "",
    directory: data.ftp_directory,
    tls: data.ftp_tls,
    writeOnly: data.ftp_write_only,
  };
}

function payloadFrom(form) {
  return {
    enabled: form.enabled,
    run_time: form.runTime,
    include_database: form.includeDatabase,
    include_files: form.includeFiles,
    keep_count: form.keepCount,
    ftp_host: form.host,
    ftp_port: form.port,
    ftp_user: form.user,
    ftp_password: form.password,
    ftp_directory: form.directory,
    ftp_tls: form.tls,
    ftp_write_only: form.writeOnly,
  };
}

export default function BackupSchedulePanel() {
  const queryClient = useQueryClient();
  const { notify } = useToast();
  const [form, setForm] = useState(null);
  const [formError, setFormError] = useState("");

  const { data, isError, error } = useQuery({
    queryKey: ["backup-schedule"],
    queryFn: getBackupSchedule,
    // Acompanha a execução pedida em "Executar agora" até o worker terminar.
    refetchInterval: (query) => {
      const current = query.state.data;
      return current && (current.run_requested_at || current.last_status === "running") ? 5000 : false;
    },
  });

  useEffect(() => {
    if (data && form === null) setForm(formFrom(data));
  }, [data, form]);

  const saveMutation = useMutation({
    mutationFn: () => updateBackupSchedule(payloadFrom(form)),
    onSuccess: (saved) => {
      setFormError("");
      queryClient.setQueryData(["backup-schedule"], saved);
      setForm(formFrom(saved));
      notify("Backup automático salvo.", "success");
    },
    onError: (err) => setFormError(err.message),
  });

  const testMutation = useMutation({
    mutationFn: () => testBackupSchedule(payloadFrom(form)),
    onSuccess: (result) => {
      setFormError("");
      notify(result.message, "success");
    },
    onError: (err) => setFormError(err.message),
  });

  const runMutation = useMutation({
    mutationFn: runBackupNow,
    onSuccess: (saved) => {
      queryClient.setQueryData(["backup-schedule"], saved);
      notify("Backup pedido; o envio começa em até 30 segundos.", "success");
    },
    onError: (err) => notify(err.message, "error"),
  });

  function update(field, value) {
    setForm({ ...form, [field]: value });
  }

  if (isError) {
    return (
      <div className="messages">
        <div className="message error">{error.message}</div>
      </div>
    );
  }
  if (!form) return <div className="page-loading">Carregando…</div>;

  const status = STATUS[data.last_status];
  const busy = saveMutation.isPending || testMutation.isPending;

  return (
    <form
      className="upload-panel"
      onSubmit={(event) => {
        event.preventDefault();
        saveMutation.mutate();
      }}
    >
      {formError && (
        <div className="messages">
          <div className="message error">{formError}</div>
        </div>
      )}

      <dl className="meta-list">
        <div>
          <dt>Última execução</dt>
          <dd>
            {formatDate(data.last_attempt_at)} {status && <Badge variant={status.variant}>{status.label}</Badge>}
          </dd>
        </div>
        <div>
          <dt>Próxima execução</dt>
          <dd>{data.run_requested_at ? "Pedida agora, aguardando o worker" : formatDate(data.next_run_at)}</dd>
        </div>
        <div>
          <dt>Último sucesso</dt>
          <dd>{formatDate(data.last_success_at)}</dd>
        </div>
        {data.last_message && (
          <div>
            <dt>Resultado</dt>
            <dd>{data.last_message}</dd>
          </div>
        )}
      </dl>

      <fieldset className="check-group">
        <legend>Agendamento</legend>
        <label className="pill-radio">
          <input type="checkbox" checked={form.enabled} onChange={(event) => update("enabled", event.target.checked)} />
          Ativado
        </label>
        <label className="pill-radio">
          <input
            type="checkbox"
            checked={form.includeDatabase}
            onChange={(event) => update("includeDatabase", event.target.checked)}
          />
          Banco de dados
        </label>
        <label className="pill-radio">
          <input
            type="checkbox"
            checked={form.includeFiles}
            onChange={(event) => update("includeFiles", event.target.checked)}
          />
          Arquivos dos ofícios
        </label>
      </fieldset>

      <div className="form-grid">
        <label>
          Horário diário ({data.timezone})
          <input type="time" required value={form.runTime} onChange={(event) => update("runTime", event.target.value)} />
        </label>
        <label>
          Cópias mantidas no FTP (de cada tipo)
          <input
            type="number"
            min={1}
            max={365}
            required
            disabled={form.writeOnly}
            title={form.writeOnly ? "Destino só de gravação: as cópias antigas ficam a cargo do servidor de backup" : undefined}
            value={form.keepCount}
            onChange={(event) => update("keepCount", event.target.value)}
          />
        </label>
        <label>
          Servidor FTP
          <input value={form.host} placeholder="ftp.exemplo.com.br" onChange={(event) => update("host", event.target.value)} />
        </label>
        <label>
          Porta
          <input
            type="number"
            min={1}
            max={65535}
            required
            value={form.port}
            onChange={(event) => update("port", event.target.value)}
          />
        </label>
        <label>
          Usuário
          <input value={form.user} autoComplete="off" onChange={(event) => update("user", event.target.value)} />
        </label>
        <label>
          Senha
          <input
            type="password"
            value={form.password}
            autoComplete="new-password"
            placeholder={data.ftp_password_set ? "(mantida — preencha para trocar)" : ""}
            onChange={(event) => update("password", event.target.value)}
          />
        </label>
        <label className="full-span">
          Pasta no servidor
          <input
            value={form.directory}
            placeholder="/backups/oficios-rpz"
            onChange={(event) => update("directory", event.target.value)}
          />
        </label>
      </div>

      <label className="pill-radio">
        <input type="checkbox" checked={form.tls} onChange={(event) => update("tls", event.target.checked)} />
        Usar FTPS (TLS explícito)
      </label>
      <label className="pill-radio">
        <input
          type="checkbox"
          checked={form.writeOnly}
          onChange={(event) => update("writeOnly", event.target.checked)}
        />
        Destino só de gravação (Pulse Backup)
      </label>
      <p className="form-note">
        Envia todo dia <code>oficios-rpz-banco-*.sql.gz</code> e <code>oficios-rpz-arquivos-*.zip</code> para a pasta
        (criada se não existir) e apaga as cópias mais antigas além do limite. Nenhuma cópia fica no servidor da
        aplicação: os arquivos são apagados assim que enviados. Sem FTPS, o dump do banco trafega sem
        criptografia. O .sql.gz pode ser restaurado direto em "Restaurar banco de dados".
      </p>
      {form.writeOnly && (
        <p className="form-note">
          Destino só de gravação: cada arquivo é enviado direto com o nome final (sem <code>.part</code>, conferência
          de tamanho ou renomeação) e nada é apagado no FTP. O histórico e a retenção ficam no servidor de backup.
        </p>
      )}

      <div className="form-actions">
        <button type="submit" disabled={busy}>
          {saveMutation.isPending ? "Salvando…" : "Salvar"}
        </button>
        <button type="button" className="ghost" disabled={busy || !form.host} onClick={() => testMutation.mutate()}>
          {testMutation.isPending ? "Testando…" : "Testar conexão"}
        </button>
        <button
          type="button"
          className="ghost"
          disabled={runMutation.isPending || Boolean(data.run_requested_at) || !data.ftp_host}
          title={data.ftp_host ? undefined : "Salve a configuração antes de executar"}
          onClick={() => runMutation.mutate()}
        >
          Executar agora
        </button>
      </div>
    </form>
  );
}
