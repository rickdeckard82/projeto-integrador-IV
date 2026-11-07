import React, { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { listAudit } from "../api/abuse.js";
import Pagination from "../components/Pagination.jsx";
import { AUDIT_ACTION_LABELS, formatLocal, localInputToUtcIso } from "../constants/abuse.js";

const EMPTY = { action: "", user: "", incident: "", from: "", to: "" };

function summarize(entry) {
  const details = entry.details;
  if (!details) return "";
  if (details.changes) return `campos: ${Object.keys(details.changes).join(", ")}`;
  if (details.filters) {
    const parts = Object.entries(details.filters).map(([key, value]) => `${key}=${value}`);
    return `${parts.join(" ")}${details.count != null ? ` (${details.count})` : ""}`;
  }
  if (details.operation) return `${details.operation}${details.rules ? `: ${details.rules.join(", ")}` : ""}`;
  if (details.username) return details.username;
  if (details.removed) return `removido: ${details.removed.join(", ")}`;
  return "";
}

export default function AbuseAuditPage() {
  const [form, setForm] = useState(EMPTY);
  const [filters, setFilters] = useState({ ...EMPTY, page: 1 });

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["abuse-audit", filters],
    queryFn: () =>
      listAudit({ ...filters, from: localInputToUtcIso(filters.from), to: localInputToUtcIso(filters.to) }),
  });

  function applyFilters(event) {
    event.preventDefault();
    setFilters({ ...form, page: 1 });
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Log de acesso ao abuse</h1>
          <p>Quem visualizou, exportou ou alterou dados do módulo de abuse. Ações sem usuário são da retenção automática.</p>
        </div>
        <div className="actions">
          <Link className="button ghost" to="/abuse">
            Voltar
          </Link>
        </div>
      </div>

      <form className="filters filters-wide" onSubmit={applyFilters}>
        <input
          placeholder='Usuário (ou "sistema")'
          value={form.user}
          onChange={(event) => setForm({ ...form, user: event.target.value })}
        />
        <select value={form.action} onChange={(event) => setForm({ ...form, action: event.target.value })}>
          <option value="">Todas as ações</option>
          {Object.entries(AUDIT_ACTION_LABELS).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
        <input
          type="number"
          min={1}
          placeholder="Incidente #"
          value={form.incident}
          onChange={(event) => setForm({ ...form, incident: event.target.value })}
        />
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
                  <th>Quando</th>
                  <th>Usuário</th>
                  <th>Ação</th>
                  <th>Incidente / mensagem</th>
                  <th>Detalhes</th>
                  <th>Origem</th>
                </tr>
              </thead>
              <tbody>
                {data.items.length === 0 && (
                  <tr>
                    <td colSpan={6} className="muted">
                      Nenhum registro encontrado.
                    </td>
                  </tr>
                )}
                {data.items.map((entry) => (
                  <tr key={entry.id}>
                    <td>{formatLocal(entry.created_at)}</td>
                    <td>{entry.user || <span className="muted">sistema</span>}</td>
                    <td>{AUDIT_ACTION_LABELS[entry.action] || entry.action}</td>
                    <td>
                      {entry.incident_id && <Link to={`/abuse/incidents/${entry.incident_id}`}>#{entry.incident_id}</Link>}
                      {entry.incident_id && entry.abuse_message_id && " · "}
                      {entry.abuse_message_id && (
                        <Link to={`/abuse/messages/${entry.abuse_message_id}`}>msg {entry.abuse_message_id}</Link>
                      )}
                    </td>
                    <td className="muted">{summarize(entry)}</td>
                    <td>{entry.remote_addr ? <code>{entry.remote_addr}</code> : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination page={data.page} pages={data.pages} onChange={(page) => setFilters({ ...filters, page })} />
          </>
        )
      )}
    </div>
  );
}
