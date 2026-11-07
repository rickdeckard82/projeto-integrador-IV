import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getAbuseSettings, updateAbuseSettings } from "../api/abuse.js";
import { useToast } from "../components/Toast.jsx";

function timezonesToText(map) {
  return Object.entries(map || {})
    .map(([domain, zone]) => `${domain}=${zone}`)
    .join("\n");
}

function textToTimezones(text) {
  const map = {};
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const [domain, ...rest] = trimmed.split("=");
    map[domain.trim()] = rest.join("=").trim();
  }
  return map;
}

export default function AbuseSettingsPage() {
  const queryClient = useQueryClient();
  const { notify } = useToast();
  const [form, setForm] = useState(null);
  const [formError, setFormError] = useState("");

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["abuse-settings"],
    queryFn: getAbuseSettings,
  });

  useEffect(() => {
    if (data) {
      setForm({
        prefixes: data.own_prefixes.join("\n"),
        timezones: timezonesToText(data.sender_timezones),
        lookupWindow: String(data.lookup_window_minutes),
        recurrenceDays: String(data.recurrence_days),
        retentionDays: data.raw_retention_days == null ? "" : String(data.raw_retention_days),
        anonymizeDays: data.incident_anonymize_days == null ? "" : String(data.incident_anonymize_days),
      });
    }
  }, [data]);

  const mutation = useMutation({
    mutationFn: updateAbuseSettings,
    onSuccess: (saved) => {
      setFormError("");
      queryClient.setQueryData(["abuse-settings"], saved);
      queryClient.invalidateQueries({ queryKey: ["abuse-status"] });
      notify("Configurações salvas.", "success");
    },
    onError: (err) => setFormError(err.message),
  });

  function handleSubmit(event) {
    event.preventDefault();
    mutation.mutate({
      own_prefixes: form.prefixes.split(/[\s,;]+/).filter(Boolean),
      sender_timezones: textToTimezones(form.timezones),
      lookup_window_minutes: form.lookupWindow,
      recurrence_days: form.recurrenceDays,
      raw_retention_days: form.retentionDays === "" ? null : form.retentionDays,
      incident_anonymize_days: form.anonymizeDays === "" ? null : form.anonymizeDays,
    });
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Abuse</h1>
          <p>Parâmetros da leitura das notificações de abuse e da identificação do assinante.</p>
        </div>
        <div className="actions">
          <Link className="button ghost" to="/general">
            Voltar
          </Link>
        </div>
      </div>

      {isError && (
        <div className="messages">
          <div className="message error">{error.message}</div>
        </div>
      )}
      {(isLoading || !form) && !isError && <div className="page-loading">Carregando…</div>}

      {form && (
        <form className="upload-panel" onSubmit={handleSubmit}>
          {formError && (
            <div className="messages">
              <div className="message error">{formError}</div>
            </div>
          )}
          <div className="grid-two">
            <label>
              Prefixos próprios (um por linha, IPv4 ou IPv6)
              <textarea
                className="mono-textarea"
                value={form.prefixes}
                onChange={(event) => setForm({ ...form, prefixes: event.target.value })}
                placeholder={"203.0.113.0/24\n2001:db8::/32"}
              />
              <span className="form-note">
                Só vira incidente um IP dentro destes prefixos. IP do notificador e de terceiros é ignorado.
              </span>
            </label>
            <label>
              Fuso por domínio do remetente (domínio=Fuso, um por linha)
              <textarea
                className="mono-textarea"
                value={form.timezones}
                onChange={(event) => setForm({ ...form, timezones: event.target.value })}
                placeholder={"shadowserver.org=UTC\ncert.br=America/Sao_Paulo"}
              />
              <span className="form-note">
                Usado só quando a notificação traz horário sem fuso; o incidente fica marcado como "fuso assumido" e
                vai para revisão. Vale também para os subdomínios.
              </span>
            </label>
          </div>
          <div className="form-grid">
            <label>
              Janela de consulta (± minutos)
              <input
                type="number"
                min={1}
                max={1440}
                value={form.lookupWindow}
                onChange={(event) => setForm({ ...form, lookupWindow: event.target.value })}
              />
            </label>
            <label>
              Reincidência (± dias)
              <input
                type="number"
                min={1}
                max={3650}
                value={form.recurrenceDays}
                onChange={(event) => setForm({ ...form, recurrenceDays: event.target.value })}
              />
            </label>
            <label>
              Apagar o e-mail bruto após (dias)
              <input
                type="number"
                min={1}
                placeholder="nunca"
                value={form.retentionDays}
                onChange={(event) => setForm({ ...form, retentionDays: event.target.value })}
              />
            </label>
            <label>
              Anonimizar incidente tratado após (dias)
              <input
                type="number"
                min={1}
                placeholder="nunca"
                value={form.anonymizeDays}
                onChange={(event) => setForm({ ...form, anonymizeDays: event.target.value })}
              />
            </label>
          </div>
          <p className="form-note">
            Só incidentes marcados como Tratado são anonimizados, contando a partir do tratamento. O e-mail bruto é
            apagado quando todos os incidentes da mensagem estão tratados há esse prazo; mensagens sem incidente contam
            a partir do recebimento. A retenção roda uma vez por dia
            {data?.last_retention_run_at
              ? `; última execução em ${new Date(data.last_retention_run_at).toLocaleString("pt-BR")}`
              : "; ainda não executada"}
            .
          </p>
          <button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? "Salvando…" : "Salvar"}
          </button>
        </form>
      )}
    </div>
  );
}
