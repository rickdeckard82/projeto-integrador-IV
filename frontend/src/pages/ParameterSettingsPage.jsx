import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getParameterSettings, testImapSettings, testSmtpSettings, updateParameterSettings } from "../api/settings.js";
import FieldArray from "../components/FieldArray.jsx";
import SshTargetList from "../components/SshTargetList.jsx";
import { useToast } from "../components/Toast.jsx";

const DEFAULT_ROUTER_COMMAND_IPV4 =
  "set routing-instances BLOQUEADOS routing-options static route {address} discard";
const DEFAULT_ROUTER_COMMAND_IPV6 =
  "set routing-instances BLOQUEADOS routing-options rib BLOQUEADOS.inet6.0 static route {address} discard";

function emptyForm() {
  return {
    dns_primary: "",
    dns_secondary: "",
    extra_dns_servers: [],
    publish_routers: [],
    rpz_servers: [],
    rpz_nameserver: "",
    ssh_strict_host_key_checking: true,
    router_command_ipv4: DEFAULT_ROUTER_COMMAND_IPV4,
    router_command_ipv6: DEFAULT_ROUTER_COMMAND_IPV6,
    smtp_host: "",
    smtp_port: "",
    smtp_security: "starttls",
    smtp_user: "",
    smtp_password: "",
    clear_smtp_password: false,
    smtp_from_email: "",
    smtp_from_name: "",
    email_signature: "",
    imap_host: "",
    imap_port: "",
    imap_user: "",
    imap_password: "",
    clear_imap_password: false,
    imap_mailbox: "",
  };
}

export default function ParameterSettingsPage() {
  const [form, setForm] = useState(null);
  const queryClient = useQueryClient();
  const { notify } = useToast();

  const { data, isError, error } = useQuery({
    queryKey: ["parameter-settings"],
    queryFn: getParameterSettings,
  });

  // Só preenche na primeira carga: um refetch (ex.: ao voltar o foco para a aba) não pode
  // apagar o que está sendo editado. Depois de salvar, o form volta com a resposta.
  useEffect(() => {
    if (data && form === null) {
      setForm({ ...emptyForm(), ...data });
    }
  }, [data, form]);

  const saveMutation = useMutation({
    mutationFn: updateParameterSettings,
    onSuccess: (result) => {
      notify("Parâmetros salvos.", "success");
      queryClient.setQueryData(["parameter-settings"], result);
      setForm({ ...emptyForm(), ...result });
    },
    onError: (err) => notify(err.message, "error"),
  });

  const testSmtpMutation = useMutation({
    mutationFn: () => testSmtpSettings(form),
    onSuccess: (result) => notify(result.message, "success"),
    onError: (err) => notify(err.message, "error"),
  });

  const testImapMutation = useMutation({
    mutationFn: () => testImapSettings(form),
    onSuccess: (result) => notify(result.message, "success"),
    onError: (err) => notify(err.message, "error"),
  });

  function handleChange(name, value) {
    setForm((current) => ({ ...current, [name]: value }));
  }

  function handleSubmit(event) {
    event.preventDefault();
    saveMutation.mutate(form);
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Parâmetros</h1>
          <p>Cadastre os servidores DNS, os servidores BIND e os roteadores usados nas publicações de bloqueio.</p>
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

      {!form ? (
        !isError && <div className="page-loading">Carregando…</div>
      ) : (
        <form className="upload-panel company-form" onSubmit={handleSubmit}>
          <h2>Servidores DNS</h2>
          <div className="form-grid">
            <label>
              DNS primário
              <input
                autoComplete="off"
                value={form.dns_primary}
                onChange={(event) => handleChange("dns_primary", event.target.value)}
              />
            </label>
            <label>
              DNS secundário
              <input
                autoComplete="off"
                value={form.dns_secondary}
                onChange={(event) => handleChange("dns_secondary", event.target.value)}
              />
            </label>
          </div>

          <FieldArray
            title="DNS adicionais"
            addLabel="Adicionar DNS"
            placeholder="Servidor DNS"
            values={form.extra_dns_servers}
            onChange={(values) => handleChange("extra_dns_servers", values)}
          />

          <h2>Zona RPZ (BIND)</h2>
          <p className="form-note">
            A zona é enviada por SSH para todos os servidores BIND da lista, que recarregam o BIND e testam o
            bloqueio. O usuário SSH precisa de sudo para gravar o arquivo da zona e rodar o comando de reload.
          </p>
          <div className="form-grid">
            <label>
              Servidor de nomes da zona (SOA/NS)
              <input
                autoComplete="off"
                placeholder="localhost"
                value={form.rpz_nameserver}
                onChange={(event) => handleChange("rpz_nameserver", event.target.value)}
              />
            </label>
          </div>

          <SshTargetList
            kind="bind"
            title="Servidores BIND"
            addLabel="Adicionar servidor"
            itemLabel="servidor"
            values={form.rpz_servers}
            onChange={(values) => handleChange("rpz_servers", values)}
          />

          <h2>Publicação de bloqueios (SSH)</h2>
          <p className="form-note">
            Roteadores para os quais as rotas discard são publicadas ao bloquear/desbloquear IPs, cada um com
            suas credenciais SSH. O nome do primeiro roteador da lista é usado no texto de comunicado como
            "Roteador de Borda".
          </p>

          <SshTargetList
            kind="router"
            title="Roteadores de publicação"
            addLabel="Adicionar roteador"
            itemLabel="roteador"
            values={form.publish_routers}
            onChange={(values) => handleChange("publish_routers", values)}
          />

          <div className="form-grid">
            <label>
              Comando IPv4 (use {"{address}"} no lugar do IP/prefixo)
              <input
                autoComplete="off"
                value={form.router_command_ipv4}
                onChange={(event) => handleChange("router_command_ipv4", event.target.value)}
              />
            </label>
            <label>
              Comando IPv6 (use {"{address}"} no lugar do IP/prefixo)
              <input
                autoComplete="off"
                value={form.router_command_ipv6}
                onChange={(event) => handleChange("router_command_ipv6", event.target.value)}
              />
            </label>
          </div>
          <p>O comando de remoção é gerado automaticamente trocando "set" por "delete" no início do comando acima.</p>

          <h2>Segurança SSH</h2>
          <label className="pill-radio">
            <input
              type="checkbox"
              checked={form.ssh_strict_host_key_checking}
              onChange={(event) => handleChange("ssh_strict_host_key_checking", event.target.checked)}
            />
            Verificar a chave de host dos servidores BIND e roteadores
          </label>
          <p className="form-note">
            Ligado, só conecta em equipamentos cuja chave está no arquivo known_hosts montado no container (ver
            README). Desligado, qualquer chave é aceita sem verificação (vulnerável a man-in-the-middle).
          </p>

          <h2>E-mail (SMTP)</h2>
          <p className="form-note">
            Servidor usado para enviar os comunicados pela tela Comunicados. A assinatura é adicionada ao final
            de cada e-mail enviado.
          </p>
          <div className="form-grid">
            <label>
              Servidor SMTP
              <input
                autoComplete="off"
                placeholder="smtp.exemplo.com.br"
                value={form.smtp_host}
                onChange={(event) => handleChange("smtp_host", event.target.value)}
              />
            </label>
            <label>
              Porta
              <input
                inputMode="numeric"
                autoComplete="off"
                placeholder="587"
                value={form.smtp_port}
                onChange={(event) => handleChange("smtp_port", event.target.value)}
              />
            </label>
            <label>
              Segurança
              <select
                value={form.smtp_security}
                onChange={(event) => handleChange("smtp_security", event.target.value)}
              >
                <option value="starttls">STARTTLS (porta 587)</option>
                <option value="ssl">SSL/TLS (porta 465)</option>
                <option value="none">Nenhuma (porta 25)</option>
              </select>
            </label>
            <label>
              Usuário
              <input
                autoComplete="off"
                value={form.smtp_user}
                onChange={(event) => handleChange("smtp_user", event.target.value)}
              />
            </label>
            <label>
              Senha
              <input
                type="password"
                autoComplete="new-password"
                value={form.smtp_password}
                placeholder={
                  data.smtp_password_set && !form.clear_smtp_password ? "(mantida — preencha para trocar)" : ""
                }
                onChange={(event) => handleChange("smtp_password", event.target.value)}
              />
              {data.smtp_password_set && (
                <small>
                  <button
                    type="button"
                    className="ghost compact"
                    onClick={() => handleChange("clear_smtp_password", !form.clear_smtp_password)}
                  >
                    {form.clear_smtp_password ? "Manter a senha salva" : "Apagar a senha salva"}
                  </button>
                </small>
              )}
            </label>
            <label>
              E-mail remetente
              <input
                type="email"
                autoComplete="off"
                placeholder="noc@exemplo.com.br"
                value={form.smtp_from_email}
                onChange={(event) => handleChange("smtp_from_email", event.target.value)}
              />
            </label>
            <label>
              Nome do remetente
              <input
                autoComplete="off"
                placeholder="NOC Exemplo"
                value={form.smtp_from_name}
                onChange={(event) => handleChange("smtp_from_name", event.target.value)}
              />
            </label>
            <label className="full-span">
              Assinatura do e-mail
              <textarea
                rows={5}
                value={form.email_signature}
                onChange={(event) => handleChange("email_signature", event.target.value)}
              />
            </label>
          </div>
          <div className="form-actions">
            <button
              type="button"
              className="ghost"
              disabled={!form.smtp_host || testSmtpMutation.isPending}
              onClick={() => testSmtpMutation.mutate()}
            >
              {testSmtpMutation.isPending ? "Testando…" : "Testar conexão SMTP"}
            </button>
          </div>

          <h2>Coleta de abuse (IMAP)</h2>
          <p className="form-note">
            Caixa lida por IMAPS, somente leitura (não marca como lida, não move nem apaga), pelo módulo de
            abuse a cada rodada do worker. Sem servidor, a coleta fica desativada. As mudanças valem na próxima
            rodada, sem reiniciar.
          </p>
          <div className="form-grid">
            <label>
              Servidor IMAP
              <input
                autoComplete="off"
                placeholder="imap.exemplo.com.br"
                value={form.imap_host}
                onChange={(event) => handleChange("imap_host", event.target.value)}
              />
            </label>
            <label>
              Porta
              <input
                inputMode="numeric"
                autoComplete="off"
                placeholder="993"
                value={form.imap_port}
                onChange={(event) => handleChange("imap_port", event.target.value)}
              />
            </label>
            <label>
              Caixa
              <input
                autoComplete="off"
                placeholder="INBOX"
                value={form.imap_mailbox}
                onChange={(event) => handleChange("imap_mailbox", event.target.value)}
              />
            </label>
            <label>
              Usuário
              <input
                autoComplete="off"
                value={form.imap_user}
                onChange={(event) => handleChange("imap_user", event.target.value)}
              />
            </label>
            <label>
              Senha
              <input
                type="password"
                autoComplete="new-password"
                value={form.imap_password}
                placeholder={
                  data.imap_password_set && !form.clear_imap_password ? "(mantida — preencha para trocar)" : ""
                }
                onChange={(event) => handleChange("imap_password", event.target.value)}
              />
              {data.imap_password_set && (
                <small>
                  <button
                    type="button"
                    className="ghost compact"
                    onClick={() => handleChange("clear_imap_password", !form.clear_imap_password)}
                  >
                    {form.clear_imap_password ? "Manter a senha salva" : "Apagar a senha salva"}
                  </button>
                </small>
              )}
            </label>
          </div>
          <div className="form-actions">
            <button
              type="button"
              className="ghost"
              disabled={!form.imap_host || testImapMutation.isPending}
              onClick={() => testImapMutation.mutate()}
            >
              {testImapMutation.isPending ? "Testando…" : "Testar conexão IMAP"}
            </button>
          </div>

          <div className="form-actions">
            <button type="submit" disabled={saveMutation.isPending}>
              {saveMutation.isPending ? "Salvando…" : "Salvar parâmetros"}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
