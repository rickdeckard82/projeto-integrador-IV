import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { discardIncidents, restoreIncidents } from "../api/abuse.js";
import { useToast } from "./Toast.jsx";

export default function DiscardIncidentsDialog({ ids, onClose, onDone, restore = false }) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const queryClient = useQueryClient();
  const { notify } = useToast();

  async function submit(event) {
    event.preventDefault();
    if (busy || !reason.trim()) return;
    setBusy(true);
    try {
      const result = await (restore ? restoreIncidents : discardIncidents)(ids, reason.trim());
      for (const key of ["abuse-incidents", "abuse-incident", "abuse-status", "abuse-audit", "abuse-message"]) {
        queryClient.invalidateQueries({ queryKey: [key] });
      }
      notify(restore ? `${result.restored} incidente(s) restaurado(s) para revisão.` : `${result.discarded} incidente(s) descartado(s).`, "success");
      onDone();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-overlay">
      <form className="modal-box" role="dialog" aria-modal="true" aria-labelledby="discard-title" onSubmit={submit}>
        <h2 id="discard-title">{restore ? "Restaurar" : "Descartar"} {ids.length} incidente(s)</h2>
        <p>Confirme os registros selecionados: {ids.map((id) => `#${id}`).join(", ")}. {restore ? "Eles voltarão para revisão e aparecerão na lista padrão e na reincidência. Os dados já extraídos serão preservados." : "Eles sairão da lista padrão e da reincidência. O e-mail original será preservado conforme a retenção configurada."}</p>
        <label>
          {restore ? "Motivo da restauração" : "Motivo do descarte"}
          <textarea autoFocus required maxLength={2000} value={reason} disabled={busy} onChange={(event) => setReason(event.target.value)} />
        </label>
        {error && <p className="message error">{error}</p>}
        <div className="actions">
          <button type="button" className="ghost" disabled={busy} onClick={onClose}>Cancelar</button>
          <button type="submit" className={restore ? undefined : "danger-button"} disabled={busy || !reason.trim()}>{busy ? "Aguarde…" : restore ? "Restaurar para revisão" : "Descartar"}</button>
        </div>
      </form>
    </div>
  );
}
