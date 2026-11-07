import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listSentEmails, sendCommunication } from "../api/communications.js";
import { listOffices } from "../api/offices.js";
import { getCommunicationsConfig } from "../api/settings.js";
import Badge from "../components/Badge.jsx";
import ConfirmDialog from "../components/ConfirmDialog.jsx";
import Pagination from "../components/Pagination.jsx";
import { useToast } from "../components/Toast.jsx";

const DEFAULT_HELP = 'Selecione Bloqueio/Desbloqueio, marque DNS/IP e clique em "Gerar texto".';

function todayFormatted() {
  const today = new Date();
  const day = String(today.getDate()).padStart(2, "0");
  const month = String(today.getMonth() + 1).padStart(2, "0");
  return `${day}/${month}/${today.getFullYear()}`;
}

function formatDate(value) {
  const clean = value.trim();
  const isoMatch = clean.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (isoMatch) {
    return `${isoMatch[3]}/${isoMatch[2]}/${isoMatch[1]}`;
  }
  return clean;
}

function formatList(values) {
  const cleanValues = values.filter((value) => value && value.trim());
  if (cleanValues.length <= 1) {
    return cleanValues.join("");
  }
  if (cleanValues.length === 2) {
    return `${cleanValues[0]} e ${cleanValues[1]}`;
  }
  return `${cleanValues.slice(0, -1).join(", ")} e ${cleanValues[cleanValues.length - 1]}`;
}

function companyShortName(config) {
  return (config.companyName || "").trim().split(/\s+/)[0] || "";
}

function contactText(config) {
  const lines = [
    "Contatos:",
    "",
    "Gerente de NOC:",
    config.contactName || "",
    config.contactPhone || "",
    "",
    ["Plantão NOC", companyShortName(config), "24x7"].filter(Boolean).join(" "),
    config.dutyPhone || "",
  ];

  if (config.dutyEmail) {
    lines.push(config.dutyEmail);
  }

  if (config.companyName || config.companyAddressLines.length) {
    lines.push("", config.companyName || "");
    lines.push(...config.companyAddressLines);
  }

  return lines.join("\n").trimEnd();
}

function communicationText(config, fields) {
  const dateValue = formatDate(fields.date);
  const processNumber = fields.processNumber.trim();
  const officeNumber = fields.officeNumber.trim();
  const fragments = [];

  if (fields.applyDns) {
    const dnsAction = fields.operation === "block" ? "bloqueadas" : "desbloqueadas";
    const dnsServers = formatList(config.dnsServers);
    fragments.push(`as URLs foram ${dnsAction} nos servidores ${dnsServers || "DNS cadastrados"}`);
  }

  if (fields.applyIp) {
    const ipAction = fields.operation === "block" ? "adicionados" : "removidos";
    const borderRouter = config.borderRouter ? ` ${config.borderRouter}` : "";
    fragments.push(
      `os IPs foram ${ipAction} para o redirecionamento de destinos inacessíveis pelo Roteador de Borda${borderRouter}`
    );
  }

  const actionText = fragments.length ? fragments.join(" e ") : "nenhuma operação foi selecionada";

  return `Prezados,

Informamos que ${actionText} no dia ${dateValue}.

Conforme orientação do Processo ${processNumber} (Ofício ${officeNumber}).

${contactText(config)}`;
}

function defaultSubject(fields) {
  const operation = fields.operation === "block" ? "Bloqueio" : "Desbloqueio";
  return fields.officeNumber ? `Retorno ao Ofício ${fields.officeNumber} - ${operation}` : "";
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function emptyFields() {
  return {
    date: todayFormatted(),
    processNumber: "",
    officeId: "",
    officeNumber: "",
    // null = assunto automático (muda com o ofício e a operação) até o usuário editar.
    subject: null,
    recipients: "",
    attachZone: true,
    attachIps: true,
    operation: "block",
    applyDns: true,
    applyIp: true,
  };
}

export default function CommunicationsPage() {
  const [fields, setFields] = useState(emptyFields());
  const [output, setOutput] = useState("");
  const [help, setHelp] = useState(DEFAULT_HELP);
  const [confirmSend, setConfirmSend] = useState(false);
  const [emailPage, setEmailPage] = useState(1);
  const [expandedEmailId, setExpandedEmailId] = useState(null);
  const [files, setFiles] = useState([]);
  const queryClient = useQueryClient();
  const { notify } = useToast();

  const { data: config, isLoading, isError, error } = useQuery({
    queryKey: ["communications-config"],
    queryFn: getCommunicationsConfig,
  });

  const { data: offices } = useQuery({
    queryKey: ["offices", "communications-select"],
    queryFn: () => listOffices({ perPage: 100 }),
  });

  const { data: sentEmails, isError: sentEmailsError, error: sentEmailsErrorValue } = useQuery({
    queryKey: ["sent-emails", emailPage],
    queryFn: () => listSentEmails({ page: emailPage }),
  });

  const sendMutation = useMutation({
    mutationFn: sendCommunication,
    onSuccess: () => {
      notify("E-mail enviado.", "success");
      setConfirmSend(false);
      setFiles([]);
      setHelp("E-mail enviado e ofício marcado como notificado.");
      setEmailPage(1);
      queryClient.invalidateQueries({ queryKey: ["sent-emails"] });
      queryClient.invalidateQueries({ queryKey: ["offices"] });
      queryClient.invalidateQueries({ queryKey: ["office"] });
    },
    onError: (err) => {
      notify(err.message, "error");
      setConfirmSend(false);
      // A tentativa com falha também fica registrada na lista.
      queryClient.invalidateQueries({ queryKey: ["sent-emails"] });
    },
  });

  useEffect(() => {
    if (config) {
      setOutput(communicationText(config, fields));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config]);

  function updateField(name, value) {
    setFields((current) => ({ ...current, [name]: value }));
  }

  function handleSubmit(event) {
    event.preventDefault();
    setOutput(communicationText(config, fields));
    setHelp("Texto pronto para copiar.");
  }

  function handleSelectOffice(event) {
    const office = offices?.items.find((item) => String(item.id) === event.target.value);
    setFields((current) => ({
      ...current,
      officeId: office ? String(office.id) : "",
      officeNumber: office ? office.office_number : "",
      processNumber: office ? office.process_number || "" : "",
    }));
  }

  const subject = fields.subject ?? defaultSubject(fields);
  const attachmentCount = Number(fields.attachZone) + Number(fields.attachIps) + files.length;
  const attachmentSummary = attachmentCount
    ? ` com ${attachmentCount} anexo${attachmentCount > 1 ? "s" : ""}`
    : "";

  function handleSendClick() {
    if (!fields.officeId) {
      notify("Selecione o ofício.", "error");
    } else if (!fields.recipients.trim()) {
      notify("Informe ao menos um destinatário.", "error");
    } else if (!subject.trim()) {
      notify("Informe o assunto.", "error");
    } else if (!output.trim()) {
      notify("Gere o texto antes de enviar.", "error");
    } else {
      setConfirmSend(true);
    }
  }

  function handleAddFiles(event) {
    // Acrescenta à lista (sem repetir o mesmo arquivo) e libera o input para novas escolhas.
    const chosen = Array.from(event.target.files);
    event.target.value = "";
    setFiles((current) => [
      ...current,
      ...chosen.filter(
        (file) => !current.some((item) => item.name === file.name && item.size === file.size)
      ),
    ]);
  }

  function handleClear() {
    setFields(emptyFields());
    setFiles([]);
    setOutput("");
    setHelp(DEFAULT_HELP);
  }

  async function handleCopy() {
    if (!output.trim()) {
      setHelp("Gere o texto antes de copiar.");
      return;
    }
    await navigator.clipboard.writeText(output);
    setHelp("Texto copiado.");
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Comunicados</h1>
          <p>Gere o texto de retorno para enviar à ANATEL.</p>
        </div>
      </div>

      {isError && (
        <div className="messages">
          <div className="message error">{error.message}</div>
        </div>
      )}

      {isLoading ? (
        <div className="page-loading">Carregando…</div>
      ) : (
        <section className="comms-shell">
          <form className="upload-panel" onSubmit={handleSubmit}>
            <h2>Dados do comunicado</h2>
            <div className="comms-form-grid">
              <label>
                Data
                <input
                  inputMode="numeric"
                  required
                  value={fields.date}
                  placeholder="DD/MM/AAAA"
                  onChange={(event) => updateField("date", event.target.value)}
                />
                <small>Formato: DD/MM/AAAA</small>
              </label>

              <label>
                Número do processo
                <input
                  required
                  value={fields.processNumber}
                  placeholder="53500.099328/2024-86"
                  onChange={(event) => updateField("processNumber", event.target.value)}
                />
              </label>

              <label>
                Número do ofício
                <select required value={fields.officeId} onChange={handleSelectOffice}>
                  <option value="">Selecione o ofício…</option>
                  {offices?.items.map((office) => (
                    <option key={office.id} value={office.id}>
                      {office.office_number}
                      {office.notification_sent_at ? " (notificado)" : ""}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            <div className="comms-options">
              <fieldset>
                <legend>Tipo de operação</legend>
                <label className="pill-radio">
                  <input
                    type="radio"
                    name="operation"
                    value="block"
                    checked={fields.operation === "block"}
                    onChange={() => updateField("operation", "block")}
                  />
                  Bloqueio
                </label>
                <label className="pill-radio">
                  <input
                    type="radio"
                    name="operation"
                    value="unblock"
                    checked={fields.operation === "unblock"}
                    onChange={() => updateField("operation", "unblock")}
                  />
                  Desbloqueio
                </label>
              </fieldset>

              <fieldset>
                <legend>Aplicar em</legend>
                <label className="pill-radio">
                  <input
                    type="checkbox"
                    checked={fields.applyDns}
                    onChange={(event) => updateField("applyDns", event.target.checked)}
                  />
                  DNS
                </label>
                <label className="pill-radio">
                  <input
                    type="checkbox"
                    checked={fields.applyIp}
                    onChange={(event) => updateField("applyIp", event.target.checked)}
                  />
                  IP
                </label>
              </fieldset>
            </div>

            <div className="comms-actions">
              <button type="submit">Gerar texto</button>
              <button className="ghost" type="button" onClick={handleClear}>
                Limpar
              </button>
              <button className="ghost" type="button" onClick={handleCopy}>
                Copiar texto
              </button>
            </div>
          </form>

          <section className="upload-panel">
            <div className="comms-output-head">
              <h2>Texto gerado</h2>
              <span>{help}</span>
            </div>
            <textarea spellCheck={false} value={output} onChange={(event) => setOutput(event.target.value)} />
          </section>

          <section className="upload-panel">
            <h2>Enviar por e-mail</h2>
            {!config.smtpConfigured && (
              <div className="messages">
                <div className="message error">
                  SMTP não configurado. Cadastre o servidor e a assinatura em{" "}
                  <Link to="/general/parameters">Geral &gt; Parâmetros</Link>.
                </div>
              </div>
            )}
            <div className="comms-email-grid">
              <label>
                Destinatário(s)
                <input
                  autoComplete="off"
                  value={fields.recipients}
                  placeholder="fulano@exemplo.com.br, ciclano@exemplo.com.br"
                  onChange={(event) => updateField("recipients", event.target.value)}
                />
                <small>Um ou mais e-mails, separados por vírgula ou ponto e vírgula.</small>
              </label>
              <label>
                Assunto
                <input value={subject} onChange={(event) => updateField("subject", event.target.value)} />
              </label>
            </div>
            <fieldset className="comms-attachments">
              <legend>Anexos</legend>
              <label className="pill-radio">
                <input
                  type="checkbox"
                  checked={fields.attachZone}
                  onChange={(event) => updateField("attachZone", event.target.checked)}
                />
                db.rpz.zone do ofício
              </label>
              <label className="pill-radio">
                <input
                  type="checkbox"
                  checked={fields.attachIps}
                  onChange={(event) => updateField("attachIps", event.target.checked)}
                />
                Config de IPs do ofício
              </label>
              <small>Os dois são gerados na hora, a partir dos domínios e IPs ativos do ofício selecionado.</small>
              <label className="comms-file-picker">
                Outros arquivos do computador
                <input type="file" multiple onChange={handleAddFiles} />
              </label>
              {files.length > 0 && (
                <ul className="comms-file-list">
                  {files.map((file) => (
                    <li key={`${file.name}-${file.size}`}>
                      {file.name} <span className="muted">({formatSize(file.size)})</span>{" "}
                      <button
                        type="button"
                        className="ghost compact"
                        onClick={() => setFiles((current) => current.filter((item) => item !== file))}
                      >
                        Remover
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </fieldset>
            {config.emailSignature && (
              <p className="form-note">
                A assinatura cadastrada em Parâmetros será adicionada ao final do e-mail:
                <br />
                <span className="comms-signature">{config.emailSignature}</span>
              </p>
            )}
            <div className="comms-actions">
              <button
                type="button"
                disabled={!config.smtpConfigured || sendMutation.isPending}
                onClick={handleSendClick}
              >
                {sendMutation.isPending ? "Enviando…" : "Enviar e-mail"}
              </button>
            </div>
          </section>

          <section className="upload-panel">
            <h2>E-mails enviados</h2>
            {sentEmailsError && (
              <div className="messages">
                <div className="message error">{sentEmailsErrorValue.message}</div>
              </div>
            )}
            <table>
              <thead>
                <tr>
                  <th>Data</th>
                  <th>Ofício</th>
                  <th>Destinatários</th>
                  <th>Assunto</th>
                  <th>Status</th>
                  <th>Enviado por</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {sentEmails?.items.length === 0 && (
                  <tr>
                    <td colSpan={7} className="muted">
                      Nenhum e-mail enviado.
                    </td>
                  </tr>
                )}
                {sentEmails?.items.map((email) => (
                  <React.Fragment key={email.id}>
                    <tr>
                      <td>{new Date(email.created_at).toLocaleString("pt-BR")}</td>
                      <td>
                        {email.office_id ? (
                          <Link to={`/offices/${email.office_id}`}>{email.office_number}</Link>
                        ) : (
                          email.office_number || "—"
                        )}
                      </td>
                      <td>{email.recipients.join(", ")}</td>
                      <td>
                        {email.subject}
                        {email.attachments.length > 0 && (
                          <span className="muted" title={email.attachments.join("\n")}>
                            {" "}
                            · {email.attachments.length} anexo{email.attachments.length > 1 ? "s" : ""}
                          </span>
                        )}
                      </td>
                      <td>
                        <Badge variant={email.status === "sent" ? "success" : "error"}>
                          {email.status === "sent" ? "enviado" : "falhou"}
                        </Badge>
                      </td>
                      <td>{email.username || "—"}</td>
                      <td className="right">
                        <button
                          type="button"
                          className="ghost compact"
                          onClick={() => setExpandedEmailId(expandedEmailId === email.id ? null : email.id)}
                        >
                          {expandedEmailId === email.id ? "Ocultar" : "Ver texto"}
                        </button>
                      </td>
                    </tr>
                    {expandedEmailId === email.id && (
                      <tr>
                        <td colSpan={7}>
                          {email.error && <div className="message error">{email.error}</div>}
                          {email.attachments.length > 0 && (
                            <p className="form-note">Anexos: {email.attachments.join(", ")}</p>
                          )}
                          <pre className="comms-email-body">{email.body}</pre>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
            <Pagination page={sentEmails?.page} pages={sentEmails?.pages} onChange={setEmailPage} />
          </section>

          <ConfirmDialog
            open={confirmSend}
            title="Enviar comunicado por e-mail"
            message={`Enviar "${subject}" para ${fields.recipients.trim()}${attachmentSummary}? O ofício ${fields.officeNumber} será marcado como notificado.`}
            confirmLabel="Enviar e-mail"
            busy={sendMutation.isPending}
            onConfirm={() =>
              sendMutation.mutate({
                officeId: fields.officeId,
                recipients: fields.recipients,
                subject,
                body: output,
                attachZone: fields.attachZone,
                attachIps: fields.attachIps,
                files,
              })
            }
            onCancel={() => setConfirmSend(false)}
          />
        </section>
      )}
    </div>
  );
}
