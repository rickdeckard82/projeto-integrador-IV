import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { downloadRawMessage, getIncident, getMessage, updateIncident } from "../api/abuse.js";
import DiscardIncidentsDialog from "../components/DiscardIncidentsDialog.jsx";
import Badge from "../components/Badge.jsx";
import { useToast } from "../components/Toast.jsx";
import {
  ALLOCATION_LABELS,
  INCIDENT_STATUS_LABELS,
  INCIDENT_STATUS_VARIANTS,
  INCIDENT_TYPE_LABELS,
  LOCAL_TIMEZONE,
  PARSER_LABELS,
  PUBLIC_KIND_LABELS,
  formatLocal,
  formatUtc,
} from "../constants/abuse.js";

function Meta({ label, children }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{children ?? "—"}</dd>
    </div>
  );
}

function OperatorForm({ incident, onSaved }) {
  const [form, setForm] = useState({});
  const [formError, setFormError] = useState("");

  useEffect(() => {
    setForm({
      pppoe_login: incident.pppoe_login || "",
      hubsoft_customer_code: incident.hubsoft_customer_code || "",
      action_taken: incident.action_taken || "",
      notes: incident.notes || "",
      status: incident.status,
    });
  }, [incident]);

  const mutation = useMutation({
    mutationFn: (payload) => updateIncident(incident.id, payload),
    onSuccess: (data) => {
      setFormError("");
      onSaved(data);
    },
    onError: (err) => setFormError(err.message),
  });

  function handleSubmit(event) {
    event.preventDefault();
    mutation.mutate(form);
  }

  const locked = Boolean(incident.anonymized_at) || incident.status === "discarded";

  return (
    <form className="detail-panel" onSubmit={handleSubmit}>
      <h2>Identificação e tratamento</h2>
      {formError && (
        <div className="messages">
          <div className="message error">{formError}</div>
        </div>
      )}
      <fieldset className="plain-fieldset" disabled={locked}>
      <div className="form-grid">
        <label>
          Login PPPoE
          <input
            autoComplete="off"
            maxLength={120}
            value={form.pppoe_login || ""}
            onChange={(event) => setForm({ ...form, pppoe_login: event.target.value })}
          />
        </label>
        <label>
          Código do cliente no Hubsoft
          <input
            autoComplete="off"
            maxLength={60}
            value={form.hubsoft_customer_code || ""}
            onChange={(event) => setForm({ ...form, hubsoft_customer_code: event.target.value })}
          />
        </label>
        <label>
          Status
          <select value={form.status || ""} onChange={(event) => setForm({ ...form, status: event.target.value })}>
            {Object.entries(INCIDENT_STATUS_LABELS).filter(([value]) => value !== "discarded" || incident.status === "discarded").map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
      </div>
      <label>
        Ação tomada
        <textarea
          className="short-textarea"
          maxLength={5000}
          value={form.action_taken || ""}
          onChange={(event) => setForm({ ...form, action_taken: event.target.value })}
        />
      </label>
      <label>
        Observações
        <textarea
          className="short-textarea"
          maxLength={5000}
          value={form.notes || ""}
          onChange={(event) => setForm({ ...form, notes: event.target.value })}
        />
      </label>
      </fieldset>
      <p className="form-note">
        {locked
          ? "Incidente anonimizado pela retenção: não pode mais ser alterado."
          : '"Identificado" exige login PPPoE ou código do cliente; "Tratado" exige a ação tomada. Tratados são anonimizados após o prazo de retenção.'}
      </p>
      <dl className="meta-list">
        <Meta label="Identificado por">
          {incident.identified_by
            ? `${incident.identified_by.username} em ${formatLocal(incident.identified_at)}`
            : null}
        </Meta>
        <Meta label={incident.status === "discarded" ? "Descartado por" : "Tratado por"}>
          {incident.handled_by ? `${incident.handled_by.username} em ${formatLocal(incident.handled_at)}` : null}
        </Meta>
      </dl>
      {!locked && (
        <button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Salvando…" : "Salvar"}
        </button>
      )}
    </form>
  );
}

function IncidentLinks({ title, items, empty }) {
  return (
    <div>
      <h3>{title}</h3>
      {items.length === 0 ? (
        <p className="muted">{empty}</p>
      ) : (
        <ul className="plain-list">
          {items.map((item) => (
            <li key={item.id}>
              <Link to={`/abuse/incidents/${item.id}`}>
                #{item.id} · {formatLocal(item.occurred_at || item.created_at)} ·{" "}
                {INCIDENT_TYPE_LABELS[item.incident_type] || item.incident_type} ·{" "}
                {INCIDENT_STATUS_LABELS[item.status] || item.status}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function MessagePanel({ messageId }) {
  const { notify } = useToast();
  const [show, setShow] = useState(false);
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["abuse-message", messageId],
    queryFn: () => getMessage(messageId),
    enabled: show,
  });

  async function handleDownload() {
    try {
      await downloadRawMessage(messageId);
    } catch (err) {
      notify(err.message, "error");
    }
  }

  return (
    <div className="detail-panel">
      <div className="card-head">
        <h2>E-mail original</h2>
        <div className="card-head-actions">
          {!show && (
            <button type="button" className="ghost compact" onClick={() => setShow(true)}>
              Mostrar e-mail
            </button>
          )}
          <button type="button" className="ghost compact" onClick={handleDownload}>
            Baixar .eml
          </button>
        </div>
      </div>
      {show && isLoading && <div className="page-loading">Carregando…</div>}
      {show && isError && <div className="message error">{error.message}</div>}
      {show && data && (
        <>
          <dl className="meta-list">
            {data.headers.map((header, index) => (
              <Meta key={`${header.name}-${index}`} label={header.name}>
                {header.value}
              </Meta>
            ))}
          </dl>
          {data.attachments.length > 0 && (
            <p className="muted">
              Anexos: {data.attachments.map((item) => `${item.filename || item.content_type} (${item.size} bytes)`).join(", ")}
            </p>
          )}
          {/* Sempre texto puro: o HTML do e-mail nunca é renderizado. */}
          <pre className="zone-preview wrap">{data.body_text ?? "O e-mail original não está mais disponível."}</pre>
        </>
      )}
    </div>
  );
}

export default function AbuseIncidentDetailPage() {
  const { incidentId } = useParams();
  const [discardOpen, setDiscardOpen] = useState(false);
  const queryClient = useQueryClient();
  const { notify } = useToast();
  const { data: incident, isLoading, isError, error } = useQuery({
    queryKey: ["abuse-incident", incidentId],
    queryFn: () => getIncident(incidentId),
  });

  function handleSaved(data) {
    queryClient.setQueryData(["abuse-incident", incidentId], data);
    queryClient.invalidateQueries({ queryKey: ["abuse-incidents"] });
    queryClient.invalidateQueries({ queryKey: ["abuse-status"] });
    notify("Incidente atualizado.", "success");
  }

  if (isLoading) return <div className="page-loading">Carregando…</div>;
  if (isError) {
    return (
      <div className="messages">
        <div className="message error">{error.message}</div>
      </div>
    );
  }

  const rule = incident.cgnat_rule;
  const lookup = incident.lookup_window;
  const recurrence = incident.recurrence;

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Incidente #{incident.id}</h1>
          <p>
            <Badge variant={INCIDENT_STATUS_VARIANTS[incident.status]}>
              {INCIDENT_STATUS_LABELS[incident.status] || incident.status}
            </Badge>{" "}
            {INCIDENT_TYPE_LABELS[incident.incident_type] || incident.incident_type}
            {incident.raw_type ? ` (${incident.raw_type})` : ""}
          </p>
        </div>
        <div className="actions">
          {incident.status !== "discarded" && <button type="button" className="danger-button" onClick={() => setDiscardOpen(true)}>Descartar incidente</button>}
          {incident.status === "discarded" && !incident.anonymized_at && <button type="button" onClick={() => setDiscardOpen(true)}>Restaurar para revisão</button>}
          <Link className="button ghost" to="/abuse">
            Voltar
          </Link>
        </div>
      </div>

      {discardOpen && <DiscardIncidentsDialog restore={incident.status === "discarded"} ids={[incident.id]} onClose={() => setDiscardOpen(false)} onDone={() => setDiscardOpen(false)} />}
      {incident.status === "discarded" && <div className="message success">Descartado: {incident.discard?.reason || "Consulte o log de acesso"}. {incident.discard?.by?.username} {formatLocal(incident.discard?.at)}</div>}
      {incident.anonymized_at && (
        <div className="messages">
          <div className="message success">
            Anonimizado em {formatLocal(incident.anonymized_at)}: login, código do cliente, IP privado e porta foram
            removidos e o IP público foi truncado.
          </div>
        </div>
      )}
      {incident.status !== "discarded" && incident.review_reasons.length > 0 && (
        <div className="messages">
          <div className="message error">Revisar: {incident.review_reasons.join(" · ")}</div>
        </div>
      )}
      {recurrence.customer.length > 0 && (
        <div className="messages">
          <div className="message error">
            Reincidência: {recurrence.customer.length} outro(s) incidente(s) do mesmo cliente em ±{recurrence.days} dias.
          </div>
        </div>
      )}

      <div className="detail-grid">
        <div className="detail-panel">
          <h2>Dados extraídos</h2>
          <dl className="meta-list">
            <Meta label="IP público">
              <code>{incident.public_ip}</code>
            </Meta>
            <Meta label="Porta de origem">{incident.source_port}</Meta>
            <Meta label="IP de destino">{incident.destination_ip && <code>{incident.destination_ip}</code>}</Meta>
            <Meta label="Porta de destino">{incident.destination_port}</Meta>
            <Meta label="Ocorrido em (UTC)">{incident.occurred_at ? formatUtc(incident.occurred_at) : null}</Meta>
            <Meta label={`Ocorrido em (${LOCAL_TIMEZONE})`}>
              {incident.occurred_at ? formatLocal(incident.occurred_at) : null}
            </Meta>
            <Meta label="Horário como veio na notificação">{incident.occurred_at_raw}</Meta>
            <Meta label="Fuso">
              {incident.timezone_used}
              {incident.timezone_assumed ? " (assumido pelo remetente)" : ""}
            </Meta>
            <Meta label="Formato">{PARSER_LABELS[incident.message?.parser] || incident.message?.parser}</Meta>
            <Meta label="Remetente">{incident.message?.sender}</Meta>
          </dl>
        </div>

        <div className="detail-panel">
          <h2>Identificação do assinante</h2>
          <dl className="meta-list">
            <Meta label="Tipo de IP">{PUBLIC_KIND_LABELS[incident.public_kind] || incident.public_kind}</Meta>
            <Meta label="IP privado calculado">
              {incident.private_ip ? <code>{incident.private_ip}</code> : null}
            </Meta>
            {incident.port_block && (
              <Meta label="Bloco de portas">
                {incident.port_block.start}–{incident.port_block.end} (bloco {incident.port_block.block})
              </Meta>
            )}
            {rule && (
              <Meta label="Regra de CGNAT">
                {rule.pool_name ? `${rule.pool_name}: ` : ""}
                {rule.public_prefix} ← {rule.private_prefix}, {ALLOCATION_LABELS[rule.allocation] || rule.allocation},
                vigente desde {formatLocal(rule.valid_from)}
              </Meta>
            )}
            {lookup && (
              <>
                <Meta label={`Janela de consulta (±${lookup.minutes} min, UTC)`}>
                  {formatUtc(lookup.start)} até {formatUtc(lookup.end)}
                </Meta>
                <Meta label={`Janela de consulta (${LOCAL_TIMEZONE})`}>
                  {formatLocal(lookup.start)} até {formatLocal(lookup.end)}
                </Meta>
              </>
            )}
          </dl>
          {incident.public_kind === "cgnat" && !incident.private_ip && (
            <p className="form-note">
              Sem IP privado: falta porta de origem ou horário, a porta está fora dos blocos ou não há regra de
              CGNAT vigente no horário.
            </p>
          )}
          {incident.private_ip && incident.session_resolver === "manual" && (
            <p className="form-note">
              Consulte no BNG/RADIUS qual login usava {incident.private_ip} dentro da janela acima e preencha abaixo.
            </p>
          )}
          {incident.sessions.length > 0 && (
            <ul className="plain-list">
              {incident.sessions.map((session) => (
                <li key={`${session.login}-${session.session_start}`}>
                  {session.login} · {formatLocal(session.session_start)} até {formatLocal(session.session_end)}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <div className="detail-grid">
        <OperatorForm incident={incident} onSaved={handleSaved} />
        <div className="detail-panel">
          <h2>Reincidência (±{recurrence.days} dias)</h2>
          <IncidentLinks
            title="Mesmo cliente (login ou código)"
            items={recurrence.customer}
            empty={incident.pppoe_login || incident.hubsoft_customer_code ? "Nenhum." : "Identifique o cliente para ver."}
          />
          <IncidentLinks
            title="Mesmo IP privado (indício fraco: o IP muda a cada sessão PPPoE)"
            items={recurrence.private_ip}
            empty="Nenhum."
          />
          {incident.siblings.length > 0 && (
            <IncidentLinks title="Outros incidentes da mesma notificação" items={incident.siblings} empty="" />
          )}
        </div>
      </div>

      <MessagePanel messageId={incident.abuse_message_id} />
    </div>
  );
}
