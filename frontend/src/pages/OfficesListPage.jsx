import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createOffice, deleteOffice, listOffices } from "../api/offices.js";
import Badge from "../components/Badge.jsx";
import ConfirmDialog from "../components/ConfirmDialog.jsx";
import Pagination from "../components/Pagination.jsx";
import TrashIcon from "../components/TrashIcon.jsx";
import { useToast } from "../components/Toast.jsx";
import { formatDateOnly } from "../utils/dateOnly.js";

const PROCESS_NUMBER_PATTERN = /^\d{5}\.\d{6}\/\d{4}-\d{2}$/;

function emptyForm() {
  return { officeNumber: "", processNumber: "", seiNumbers: "", expeditionDate: "", intimationFile: null };
}

export default function OfficesListPage() {
  const [qInput, setQInput] = useState("");
  const [filters, setFilters] = useState({ q: "", page: 1 });
  const [form, setForm] = useState(emptyForm());
  const [formError, setFormError] = useState("");
  const [officeToDelete, setOfficeToDelete] = useState(null);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { notify } = useToast();

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["offices", filters],
    queryFn: () => listOffices({ page: filters.page, q: filters.q }),
  });

  const createMutation = useMutation({
    mutationFn: createOffice,
    onSuccess: (office) => {
      notify(`Ofício ${office.office_number} criado.`, "success");
      queryClient.invalidateQueries({ queryKey: ["offices"] });
      navigate(`/offices/${office.id}`);
    },
    onError: (err) => setFormError(err.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (office) => deleteOffice(office.id, office.office_number),
    onSuccess: (_, office) => {
      notify(`Ofício ${office.office_number} removido.`, "success");
      setOfficeToDelete(null);
      queryClient.invalidateQueries({ queryKey: ["offices"] });
    },
    onError: (err) => notify(err.message, "error"),
  });

  function handleSearch(event) {
    event.preventDefault();
    setFilters({ q: qInput, page: 1 });
  }

  function handleCreate(event) {
    event.preventDefault();
    setFormError("");

    if (!form.processNumber.trim()) {
      setFormError("Informe o número do processo.");
      return;
    }
    if (!PROCESS_NUMBER_PATTERN.test(form.processNumber.trim())) {
      setFormError("Número do processo inválido. Use o formato 53500.099328/2024-86.");
      return;
    }
    if (!form.officeNumber.trim() && !form.intimationFile) {
      setFormError("Informe o número do ofício ou envie uma intimação contendo esse número.");
      return;
    }

    createMutation.mutate(form);
  }

  return (
    <div>
      <div className="page-head">
        <h1>Ofícios</h1>
      </div>

      <div className="upload-panel office-create-form">
        <h2>Criar ofício</h2>
        {formError && (
          <div className="messages">
            <div className="message error">{formError}</div>
          </div>
        )}
        <form onSubmit={handleCreate}>
          <div className="form-grid">
            <label>
              Número do ofício
              <input
                type="text"
                value={form.officeNumber}
                onChange={(event) => setForm({ ...form, officeNumber: event.target.value })}
              />
            </label>
            <label>
              Número do processo
              <input
                type="text"
                placeholder="53500.099328/2024-86"
                value={form.processNumber}
                onChange={(event) => setForm({ ...form, processNumber: event.target.value })}
              />
            </label>
            <label>
              SEI (separados por vírgula)
              <input
                type="text"
                value={form.seiNumbers}
                onChange={(event) => setForm({ ...form, seiNumbers: event.target.value })}
              />
            </label>
            <label>
              Data de expedição
              <input
                type="date"
                value={form.expeditionDate}
                onChange={(event) => setForm({ ...form, expeditionDate: event.target.value })}
              />
            </label>
            <label className="full-span">
              Intimação (PDF ou HTML) — opcional, preenche os campos acima automaticamente
              <input
                type="file"
                accept=".pdf,.html,.htm"
                onChange={(event) => setForm({ ...form, intimationFile: event.target.files[0] || null })}
              />
            </label>
          </div>
          <button type="submit" disabled={createMutation.isPending}>
            {createMutation.isPending ? "Criando…" : "Criar ofício"}
          </button>
        </form>
      </div>

      <form className="filters" onSubmit={handleSearch}>
        <input
          type="text"
          placeholder="Buscar por número do ofício ou processo…"
          value={qInput}
          onChange={(event) => setQInput(event.target.value)}
        />
        <button type="submit">Buscar</button>
      </form>

      {isError && (
        <div className="messages">
          <div className="message error">{error.message}</div>
        </div>
      )}

      {isLoading ? (
        <div className="page-loading">Carregando…</div>
      ) : (
        <>
          <table>
            <thead>
              <tr>
                <th>Ofício</th>
                <th>Processo</th>
                <th>SEI</th>
                <th>Domínios</th>
                <th>IPs</th>
                <th>Expedição</th>
                <th>Status</th>
                <th>Notificação</th>
                <th>Criado por</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {data.items.length === 0 && (
                <tr>
                  <td colSpan={10} className="muted">
                    Nenhum ofício encontrado.
                  </td>
                </tr>
              )}
              {data.items.map((office) => (
                <tr key={office.id}>
                  <td>
                    <Link to={`/offices/${office.id}`}>{office.office_number}</Link>
                  </td>
                  <td>{office.process_number || "—"}</td>
                  <td>{office.sei_numbers || "—"}</td>
                  <td>{office.total_found}</td>
                  <td>{office.ip_count}</td>
                  <td>{office.expedition_date ? formatDateOnly(office.expedition_date) : "—"}</td>
                  <td>
                    <Badge variant={office.expired ? "error" : "success"}>
                      {office.expired ? "expirado" : "em prazo"}
                    </Badge>
                  </td>
                  <td>
                    <Badge variant={office.notification_sent_at ? "success" : "warning"}>
                      {office.notification_sent_at ? "enviada" : "pendente"}
                    </Badge>
                  </td>
                  <td>{office.created_by_username || "—"}</td>
                  <td className="right">
                    <button
                      type="button"
                      className="icon-danger"
                      title="Remover ofício"
                      aria-label="Remover ofício"
                      onClick={() => setOfficeToDelete(office)}
                    >
                      <TrashIcon />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination
            page={data.page}
            pages={data.pages}
            onChange={(page) => setFilters((current) => ({ ...current, page }))}
          />
        </>
      )}

      <ConfirmDialog
        open={Boolean(officeToDelete)}
        title="Remover ofício"
        message="Esta ação é irreversível. Domínios e IPs exclusivos deste ofício serão apagados; os compartilhados com outros ofícios serão preservados."
        mode="type"
        expectedText={officeToDelete ? officeToDelete.office_number : ""}
        confirmLabel="Remover ofício"
        danger
        busy={deleteMutation.isPending}
        onConfirm={() => deleteMutation.mutate(officeToDelete)}
        onCancel={() => setOfficeToDelete(null)}
      />
    </div>
  );
}
