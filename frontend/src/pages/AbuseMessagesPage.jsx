import React, { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { listMessages, reprocessMessages } from "../api/abuse.js";
import Badge from "../components/Badge.jsx";
import ConfirmDialog from "../components/ConfirmDialog.jsx";
import Pagination from "../components/Pagination.jsx";
import { useToast } from "../components/Toast.jsx";
import { MESSAGE_STATUS_LABELS, MESSAGE_STATUS_VARIANTS, PARSER_LABELS, formatLocal } from "../constants/abuse.js";

export default function AbuseMessagesPage() {
  const [form, setForm] = useState({ status: "unrecognized,error", q: "" });
  const [filters, setFilters] = useState({ status: "unrecognized,error", q: "", page: 1 });

  const [confirmBulk, setConfirmBulk] = useState(false);
  const [bulkProgress, setBulkProgress] = useState(null);
  const queryClient = useQueryClient();
  const { notify } = useToast();

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["abuse-messages", filters],
    queryFn: () => listMessages(filters),
  });

  async function handleBulkReprocess() {
    setConfirmBulk(false);
    const totals = { processed: 0, recognized: 0, incidents: 0 };
    let afterId = 0;
    setBulkProgress(totals);
    try {
      // Lotes de até 500 no servidor; repete até não sobrar nenhuma.
      for (;;) {
        const result = await reprocessMessages({ afterId });
        totals.processed += result.processed;
        totals.recognized += result.recognized;
        totals.incidents += result.incidents;
        setBulkProgress({ ...totals });
        if (!result.remaining || !result.processed) break;
        afterId = result.last_id;
      }
      notify(
        `${totals.processed} mensagem(ns) reprocessada(s): ${totals.recognized} reconhecida(s), ${totals.incidents} incidente(s) criado(s).`,
        "success"
      );
    } catch (err) {
      notify(err.message, "error");
    } finally {
      setBulkProgress(null);
      for (const key of ["abuse-messages", "abuse-incidents", "abuse-status"]) {
        queryClient.invalidateQueries({ queryKey: [key] });
      }
    }
  }

  function applyFilters(event) {
    event.preventDefault();
    setFilters({ ...form, page: 1 });
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Mensagens de abuse</h1>
          <p>
            E-mails recebidos na caixa de abuse. Os não reconhecidos não citam nenhum IP dos prefixos próprios e
            precisam de leitura manual.
          </p>
        </div>
        <div className="actions">
          <button type="button" className="ghost" onClick={() => setConfirmBulk(true)} disabled={Boolean(bulkProgress)}>
            {bulkProgress ? `Reprocessando… ${bulkProgress.processed}` : "Reprocessar não reconhecidas"}
          </button>
          <Link className="button ghost" to="/abuse">
            Voltar
          </Link>
        </div>
      </div>

      <form className="filters" onSubmit={applyFilters}>
        <input
          type="text"
          placeholder="Remetente ou assunto"
          value={form.q}
          onChange={(event) => setForm({ ...form, q: event.target.value })}
        />
        <select value={form.status} onChange={(event) => setForm({ ...form, status: event.target.value })}>
          <option value="unrecognized,error">Não reconhecidas e com erro</option>
          <option value="unrecognized">Não reconhecidas</option>
          <option value="error">Com erro</option>
          <option value="processed">Processadas</option>
          <option value="">Todas</option>
        </select>
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
                  <th>Recebida em</th>
                  <th>Status</th>
                  <th>Remetente</th>
                  <th>Assunto</th>
                  <th>Formato</th>
                  <th>Incidentes</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {data.items.length === 0 && (
                  <tr>
                    <td colSpan={7} className="muted">
                      Nenhuma mensagem encontrada.
                    </td>
                  </tr>
                )}
                {data.items.map((item) => (
                  <tr key={item.id}>
                    <td>{formatLocal(item.received_at || item.created_at)}</td>
                    <td>
                      <Badge variant={MESSAGE_STATUS_VARIANTS[item.status]}>
                        {MESSAGE_STATUS_LABELS[item.status] || item.status}
                      </Badge>
                    </td>
                    <td>{item.sender || "—"}</td>
                    <td>{item.subject || "—"}</td>
                    <td>{PARSER_LABELS[item.parser] || item.parser || "—"}</td>
                    <td>{item.incident_count}</td>
                    <td className="right">
                      <Link className="button ghost compact" to={`/abuse/messages/${item.id}`}>
                        Abrir
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination page={data.page} pages={data.pages} onChange={(page) => setFilters({ ...filters, page })} />
          </>
        )
      )}

      <ConfirmDialog
        open={confirmBulk}
        title="Reprocessar não reconhecidas"
        message="Ler de novo todas as mensagens não reconhecidas com os prefixos e fusos atuais? Use depois de cadastrar ou corrigir os prefixos próprios."
        confirmLabel="Reprocessar"
        busy={false}
        onConfirm={handleBulkReprocess}
        onCancel={() => setConfirmBulk(false)}
      />
    </div>
  );
}
