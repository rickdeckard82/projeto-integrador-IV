import React, { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { deleteCgnatGroup, importCgnatFiles, listCgnatRules } from "../api/abuse.js";
import Badge from "../components/Badge.jsx";
import ConfirmDialog from "../components/ConfirmDialog.jsx";
import { useToast } from "../components/Toast.jsx";
import { ALLOCATION_LABELS, LOCAL_TIMEZONE, formatLocal, localInputToUtcIso } from "../constants/abuse.js";

function groupRules(rules) {
  const groups = new Map();
  for (const rule of rules) {
    const key = rule.import_group || `rule-${rule.id}`;
    if (!groups.has(key)) groups.set(key, { key, rules: [] });
    groups.get(key).rules.push(rule);
  }
  return [...groups.values()];
}

function RulesTable({ rules, showUsage }) {
  return (
    <table>
      <thead>
        <tr>
          <th>Pool</th>
          <th>Público ← privado</th>
          <th>Alocação</th>
          <th>Portas</th>
          <th>Vigência</th>
          {showUsage && <th>Incidentes</th>}
        </tr>
      </thead>
      <tbody>
        {rules.map((rule) => (
          <tr key={rule.id ?? `${rule.public_prefix}-${rule.private_prefix}`}>
            <td>
              {rule.pool_name || "—"}
              {rule.source_filename && <div className="muted">{rule.source_filename}</div>}
            </td>
            <td>
              <code>
                {rule.public_prefix} ← {rule.private_prefix}
              </code>
            </td>
            <td>{ALLOCATION_LABELS[rule.allocation] || rule.allocation}</td>
            <td>
              a partir de {rule.first_port}, {rule.ports_per_subscriber} por assinante ({rule.blocks_per_ip} por IP)
            </td>
            <td>
              {formatLocal(rule.valid_from)} até {rule.valid_to ? formatLocal(rule.valid_to) : "em aberto"}
            </td>
            {showUsage && <td>{rule.incident_count}</td>}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ImportForm({ onDone }) {
  const { notify } = useToast();
  const [files, setFiles] = useState([]);
  const [validFrom, setValidFrom] = useState("");
  const [notes, setNotes] = useState("");
  const [preview, setPreview] = useState(null);
  const [formError, setFormError] = useState("");

  const payload = () => ({ files, validFrom: localInputToUtcIso(validFrom), notes });

  const previewMutation = useMutation({
    mutationFn: () => importCgnatFiles({ ...payload(), dryRun: true }),
    onSuccess: (data) => {
      setFormError("");
      setPreview(data);
    },
    onError: (err) => {
      setPreview(null);
      setFormError(err.message);
    },
  });

  const importMutation = useMutation({
    mutationFn: () => importCgnatFiles(payload()),
    onSuccess: (data) => {
      notify(
        `${data.rules.length} regra(s) importada(s); ${data.incidents_recalculated} incidente(s) recalculado(s).`,
        "success"
      );
      setFiles([]);
      setValidFrom("");
      setNotes("");
      setPreview(null);
      onDone();
    },
    onError: (err) => setFormError(err.message),
  });

  function handleSubmit(event) {
    event.preventDefault();
    if (!files.length || !validFrom) {
      setFormError("Selecione os arquivos e o início da vigência.");
      return;
    }
    previewMutation.mutate();
  }

  return (
    <form className="upload-panel" onSubmit={handleSubmit}>
      <h2>Importar fixed-nat do A10</h2>
      <p className="muted">
        Envie os arquivos <code>fixed_nat_ip_list_*.txt</code> de uma mesma configuração (um por pool). Cada linha é
        conferida contra a fórmula antes de aceitar. Se um pool já tiver regra em aberto, ela é encerrada no início da
        nova vigência.
      </p>
      {formError && (
        <div className="messages">
          <div className="message error">{formError}</div>
        </div>
      )}
      <div className="form-grid">
        <label>
          Arquivos
          <input
            type="file"
            multiple
            accept=".txt,text/plain"
            onChange={(event) => {
              setFiles([...event.target.files]);
              setPreview(null);
            }}
          />
        </label>
        <label>
          Início da vigência ({LOCAL_TIMEZONE})
          <input
            type="datetime-local"
            value={validFrom}
            onChange={(event) => {
              setValidFrom(event.target.value);
              setPreview(null);
            }}
          />
        </label>
        <label>
          Observação
          <input value={notes} maxLength={2000} onChange={(event) => setNotes(event.target.value)} />
        </label>
      </div>
      <button type="submit" disabled={previewMutation.isPending}>
        {previewMutation.isPending ? "Conferindo…" : "Conferir arquivos"}
      </button>

      {preview && (
        <div className="import-preview">
          <h3>Conferência</h3>
          {preview.pools.map((pool, index) => (
            <p key={index} className="muted">
              {pool.pool_name || "pool"}: {pool.entry_count} linhas conferidas
              {pool.exported_at ? `, exportado em ${pool.exported_at}` : ""}
              {pool.warnings.map((warning) => (
                <span key={warning}>
                  {" "}
                  <Badge variant="warning">{warning}</Badge>
                </span>
              ))}
            </p>
          ))}
          <RulesTable rules={preview.rules} />
          {preview.closings.length > 0 && (
            <p className="form-note">
              Serão encerradas:{" "}
              {preview.closings
                .map((item) => `${item.rule.public_prefix} (em ${formatLocal(item.new_valid_to)})`)
                .join(", ")}
            </p>
          )}
          <button type="button" onClick={() => importMutation.mutate()} disabled={importMutation.isPending}>
            {importMutation.isPending ? "Importando…" : "Confirmar importação"}
          </button>
        </div>
      )}
    </form>
  );
}

export default function CgnatRulesPage() {
  const queryClient = useQueryClient();
  const { notify } = useToast();
  const [groupToDelete, setGroupToDelete] = useState(null);
  const { data, isLoading, isError, error } = useQuery({ queryKey: ["cgnat-rules"], queryFn: listCgnatRules });
  const groups = useMemo(() => groupRules(data?.items || []), [data]);

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["cgnat-rules"] });
    queryClient.invalidateQueries({ queryKey: ["abuse-incidents"] });
    queryClient.invalidateQueries({ queryKey: ["abuse-status"] });
  };

  const deleteMutation = useMutation({
    mutationFn: (group) => deleteCgnatGroup(group.key),
    onSuccess: (result) => {
      notify(`Importação apagada; ${result.incidents_recalculated} incidente(s) recalculado(s).`, "success");
      setGroupToDelete(null);
      refresh();
    },
    onError: (err) => {
      notify(err.message, "error");
      setGroupToDelete(null);
    },
  });

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>CGNAT</h1>
          <p>Regras do CGNAT determinístico usadas para calcular o IP privado a partir do IP público e da porta.</p>
        </div>
        <div className="actions">
          <Link className="button ghost" to="/general">
            Voltar
          </Link>
        </div>
      </div>

      <ImportForm onDone={refresh} />

      {isError && (
        <div className="messages">
          <div className="message error">{error.message}</div>
        </div>
      )}
      {isLoading && <div className="page-loading">Carregando…</div>}
      {data && groups.length === 0 && <p className="muted">Nenhuma regra cadastrada.</p>}

      {groups.map((group) => {
        const first = group.rules[0];
        const open = group.rules.some((rule) => !rule.valid_to);
        return (
          <section className="detail-panel rule-group" key={group.key}>
            <div className="card-head">
              <div>
                <h2>
                  Vigência desde {formatLocal(first.valid_from)}{" "}
                  <Badge variant={open ? "success" : "running"}>{open ? "Vigente" : "Encerrada"}</Badge>
                </h2>
                <p className="muted">
                  Importado por {first.created_by?.username || "—"} em {formatLocal(first.created_at)}
                  {first.notes ? ` · ${first.notes}` : ""}
                </p>
              </div>
              <div className="card-head-actions">
                <button type="button" className="ghost compact" onClick={() => setGroupToDelete(group)}>
                  Apagar importação
                </button>
              </div>
            </div>
            <RulesTable rules={group.rules} showUsage />
          </section>
        );
      })}

      <ConfirmDialog
        open={Boolean(groupToDelete)}
        title="Apagar importação"
        message="As regras desta importação serão apagadas, as regras que ela encerrou voltam a valer e os IPs privados dos incidentes serão recalculados."
        confirmLabel="Apagar"
        danger
        busy={deleteMutation.isPending}
        onConfirm={() => deleteMutation.mutate(groupToDelete)}
        onCancel={() => setGroupToDelete(null)}
      />
    </div>
  );
}
