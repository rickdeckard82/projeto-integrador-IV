import React from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { downloadRawMessage, getMessage, reprocessMessage } from "../api/abuse.js";
import Badge from "../components/Badge.jsx";
import { useToast } from "../components/Toast.jsx";
import {
  INCIDENT_STATUS_LABELS,
  INCIDENT_TYPE_LABELS,
  MESSAGE_STATUS_LABELS,
  MESSAGE_STATUS_VARIANTS,
  PARSER_LABELS,
  formatLocal,
} from "../constants/abuse.js";

export default function AbuseMessageDetailPage() {
  const { messageId } = useParams();
  const queryClient = useQueryClient();
  const { notify } = useToast();
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["abuse-message", messageId],
    queryFn: () => getMessage(messageId),
  });

  const reprocess = useMutation({
    mutationFn: () => reprocessMessage(messageId),
    onSuccess: (result) => {
      notify(
        result.status === "processed" ? "Mensagem reprocessada: incidentes criados." : "Reprocessada, mas continua sem IP próprio.",
        result.status === "processed" ? "success" : "error"
      );
      queryClient.invalidateQueries({ queryKey: ["abuse-message", messageId] });
      queryClient.invalidateQueries({ queryKey: ["abuse-messages"] });
      queryClient.invalidateQueries({ queryKey: ["abuse-incidents"] });
      queryClient.invalidateQueries({ queryKey: ["abuse-status"] });
    },
    onError: (err) => notify(err.message, "error"),
  });

  async function handleDownload() {
    try {
      await downloadRawMessage(messageId);
    } catch (err) {
      notify(err.message, "error");
    }
  }

  if (isLoading) return <div className="page-loading">Carregando…</div>;
  if (isError) {
    return (
      <div className="messages">
        <div className="message error">{error.message}</div>
      </div>
    );
  }

  const canReprocess = ["unrecognized", "error"].includes(data.status) && data.raw_available;

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Mensagem #{data.id}</h1>
          <p>
            <Badge variant={MESSAGE_STATUS_VARIANTS[data.status]}>
              {MESSAGE_STATUS_LABELS[data.status] || data.status}
            </Badge>{" "}
            {data.subject || "(sem assunto)"}
          </p>
        </div>
        <div className="actions">
          {canReprocess && (
            <button type="button" className="ghost" onClick={() => reprocess.mutate()} disabled={reprocess.isPending}>
              {reprocess.isPending ? "Reprocessando…" : "Reprocessar"}
            </button>
          )}
          {data.raw_available && (
            <button type="button" className="ghost" onClick={handleDownload}>
              Baixar .eml
            </button>
          )}
          <Link className="button ghost" to="/abuse/messages">
            Voltar
          </Link>
        </div>
      </div>

      {data.error && (
        <div className="messages">
          <div className="message error">{data.error}</div>
        </div>
      )}

      <div className="detail-grid">
        <div className="detail-panel">
          <h2>Cabeçalhos</h2>
          <dl className="meta-list">
            {data.headers.map((header, index) => (
              <div key={`${header.name}-${index}`}>
                <dt>{header.name}</dt>
                <dd>{header.value}</dd>
              </div>
            ))}
            <div>
              <dt>Formato reconhecido</dt>
              <dd>{PARSER_LABELS[data.parser] || data.parser || "—"}</dd>
            </div>
            <div>
              <dt>Recebida em</dt>
              <dd>{formatLocal(data.received_at || data.created_at)}</dd>
            </div>
          </dl>
          {data.attachments.length > 0 && (
            <p className="muted">
              Anexos: {data.attachments.map((item) => `${item.filename || item.content_type} (${item.size} bytes)`).join(", ")}
            </p>
          )}
        </div>
        <div className="detail-panel">
          <h2>Incidentes</h2>
          {data.incidents.length === 0 ? (
            <p className="muted">Nenhum incidente extraído desta mensagem.</p>
          ) : (
            <ul className="plain-list">
              {data.incidents.map((item) => (
                <li key={item.id}>
                  <Link to={`/abuse/incidents/${item.id}`}>
                    #{item.id} · {item.public_ip} · {INCIDENT_TYPE_LABELS[item.incident_type] || item.incident_type} ·{" "}
                    {INCIDENT_STATUS_LABELS[item.status] || item.status}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <div className="detail-panel">
        <h2>Conteúdo</h2>
        {/* Sempre texto puro: o HTML do e-mail nunca é renderizado. */}
        <pre className="zone-preview wrap">
          {data.body_text ?? "O e-mail original não está mais disponível (expurgado pela retenção)."}
        </pre>
      </div>
    </div>
  );
}
