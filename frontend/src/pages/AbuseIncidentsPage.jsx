import React, { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { exportIncidents, getAbuseStatus, listIncidents } from "../api/abuse.js";
import Badge from "../components/Badge.jsx";
import DiscardIncidentsDialog from "../components/DiscardIncidentsDialog.jsx";
import Pagination from "../components/Pagination.jsx";
import { useToast } from "../components/Toast.jsx";
import {
  INCIDENT_STATUS_LABELS,
  INCIDENT_STATUS_VARIANTS,
  INCIDENT_TYPE_LABELS,
  formatLocal,
  localInputToUtcIso,
} from "../constants/abuse.js";

const EMPTY_FILTERS = { status: "", type: "", q: "", from: "", to: "" };

function toApiFilters(filters) {
  return {
    ...filters,
    from: localInputToUtcIso(filters.from),
    to: localInputToUtcIso(filters.to),
  };
}

function StatusSummary() {
  const { data } = useQuery({ queryKey: ["abuse-status"], queryFn: getAbuseStatus });
  if (!data) return null;
  const mailbox = data.mailboxes[0];

  return (
    <>
      {!data.own_prefixes_configured && (
        <div className="messages">
          <div className="message error">
            Nenhum prefixo próprio configurado: toda notificação fica como não reconhecida.{" "}
            <Link to="/general/abuse">Configurar prefixos</Link>
          </div>
        </div>
      )}
      {mailbox?.last_error && (
        <div className="messages">
          <div className="message error">Última coleta falhou: {mailbox.last_error}</div>
        </div>
      )}
      <section className="stats">
        {Object.entries(INCIDENT_STATUS_LABELS).map(([status, label]) => (
          <article key={status}>
            <span>{label}</span>
            <strong>{data.incidents[status] ?? 0}</strong>
          </article>
        ))}
        <article>
          <span>Não reconhecidas</span>
          <strong>{data.messages.unrecognized ?? 0}</strong>
        </article>
        <article>
          <span>Com erro</span>
          <strong>{data.messages.error ?? 0}</strong>
        </article>
        <article>
          <span>Última coleta</span>
          <strong className="stats-small">{mailbox ? formatLocal(mailbox.last_run_at) : "nunca"}</strong>
        </article>
      </section>
    </>
  );
}

export default function AbuseIncidentsPage() {
  const [form, setForm] = useState(EMPTY_FILTERS);
  const [filters, setFilters] = useState({ ...EMPTY_FILTERS, page: 1 });
  const [selected, setSelected] = useState([]);
  const [discardOpen, setDiscardOpen] = useState(false);
  const [exporting, setExporting] = useState(false);
  const { notify } = useToast();

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["abuse-incidents", filters],
    queryFn: () => listIncidents(toApiFilters(filters)),
  });

  const restoring = filters.status === "discarded";
  const selectableItems = (data?.items || []).filter((item) =>
    restoring ? item.status === "discarded" && !item.anonymized_at : item.status !== "discarded"
  );

  function applyFilters(event) {
    event.preventDefault();
    setSelected([]);
    setFilters({ ...form, page: 1 });
  }

  async function handleExport() {
    setExporting(true);
    try {
      await exportIncidents(toApiFilters(filters));
    } catch (err) {
      notify(err.message, "error");
    } finally {
      setExporting(false);
    }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Abuse</h1>
          <p>Notificações de abuse recebidas e a identificação do assinante responsável.</p>
        </div>
        <div className="actions">
          <Link className="button ghost" to="/abuse/messages">
            Mensagens
          </Link>
          <Link className="button ghost" to="/abuse/audit">
            Log de acesso
          </Link>
          <button type="button" className="ghost" onClick={handleExport} disabled={exporting}>
            {exporting ? "Exportando…" : "Exportar CSV"}
          </button>
        </div>
      </div>

      <StatusSummary />

      <form className="filters filters-wide" onSubmit={applyFilters}>
        <input
          type="text"
          placeholder="IP público/privado, login ou código do cliente"
          value={form.q}
          onChange={(event) => setForm({ ...form, q: event.target.value })}
        />
        <select value={form.status} onChange={(event) => setForm({ ...form, status: event.target.value })}>
          <option value="">Todos os ativos</option>
          {Object.entries(INCIDENT_STATUS_LABELS).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
        <select value={form.type} onChange={(event) => setForm({ ...form, type: event.target.value })}>
          <option value="">Todos os tipos</option>
          {Object.entries(INCIDENT_TYPE_LABELS).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
        <input
          type="datetime-local"
          title="A partir de"
          value={form.from}
          onChange={(event) => setForm({ ...form, from: event.target.value })}
        />
        <input
          type="datetime-local"
          title="Até"
          value={form.to}
          onChange={(event) => setForm({ ...form, to: event.target.value })}
        />
        <button type="submit">Filtrar</button>
      </form>

      <div className="actions selection-actions">
        <span className="muted">{selected.length} selecionado(s) nesta página</span>
        <button type="button" className={restoring ? undefined : "danger-button"} disabled={!selected.length} onClick={() => setDiscardOpen(true)}>{restoring ? "Restaurar selecionados" : "Descartar selecionados"}</button>
      </div>
      {discardOpen && <DiscardIncidentsDialog restore={restoring} ids={selected} onClose={() => setDiscardOpen(false)} onDone={() => { setDiscardOpen(false); setSelected([]); }} />}

      {isError && (
        <div className="messages">
          <div className="message error">{error.message}</div>
        </div>
      )}

      {isLoading ? (
        <div className="page-loading">Carregando…</div>
      ) : (
        data && (
          <>
            <table>
              <thead>
                <tr>
                  <th className="selection-cell"><input className="selection-checkbox" type="checkbox" aria-label="Selecionar todos desta página" disabled={!selectableItems.length} checked={selectableItems.length > 0 && selectableItems.every((item) => selected.includes(item.id))} onChange={(event) => setSelected(event.target.checked ? selectableItems.map((item) => item.id) : [])} /></th>
                  <th>Ocorrido em</th>
                  <th>Status</th>
                  <th>Tipo</th>
                  <th>IP público : porta</th>
                  <th>IP privado</th>
                  <th>Login / cliente</th>
                  <th>Reincidência</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {data.items.length === 0 && (
                  <tr>
                    <td colSpan={9} className="muted">
                      Nenhum incidente encontrado.
                    </td>
                  </tr>
                )}
                {data.items.map((item) => (
                  <tr key={item.id}>
                    <td className="selection-cell"><input className="selection-checkbox" type="checkbox" aria-label={`Selecionar incidente #${item.id}`} disabled={!selectableItems.some((selectable) => selectable.id === item.id)} checked={selected.includes(item.id)} onChange={(event) => setSelected(event.target.checked ? [...selected, item.id] : selected.filter((id) => id !== item.id))} /></td>
                    <td>
                      {item.occurred_at ? formatLocal(item.occurred_at) : <span className="muted">sem horário</span>}
                      {item.timezone_assumed && <div className="muted">fuso assumido</div>}
                    </td>
                    <td>
                      <Badge variant={INCIDENT_STATUS_VARIANTS[item.status]}>
                        {INCIDENT_STATUS_LABELS[item.status] || item.status}
                      </Badge>
                    </td>
                    <td>{INCIDENT_TYPE_LABELS[item.incident_type] || item.incident_type}</td>
                    <td>
                      <code>
                        {item.public_ip}
                        {item.source_port ? `:${item.source_port}` : ""}
                      </code>
                      {item.anonymized_at && <div className="muted">anonimizado</div>}
                    </td>
                    <td>{item.private_ip ? <code>{item.private_ip}</code> : <span className="muted">—</span>}</td>
                    <td>
                      {item.pppoe_login || item.hubsoft_customer_code ? (
                        [item.pppoe_login, item.hubsoft_customer_code].filter(Boolean).join(" / ")
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td>
                      {item.recurrence?.customer > 0 && (
                        <Badge variant="error">cliente: {item.recurrence.customer}</Badge>
                      )}{" "}
                      {item.recurrence?.private_ip > 0 && (
                        <Badge variant="warning">IP privado: {item.recurrence.private_ip}</Badge>
                      )}
                    </td>
                    <td className="right">
                      <Link className="button ghost compact" to={`/abuse/incidents/${item.id}`}>
                        Abrir
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination
              page={data.page}
              pages={data.pages}
              onChange={(page) => { setSelected([]); setFilters({ ...filters, page }); }}
            />
          </>
        )
      )}
    </div>
  );
}
