import React, { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  deleteOffice,
  deployOfficeExpiredIpsDelete,
  deployOfficeIpRoutes,
  getOffice,
  setOfficeNotification,
  toggleOfficeDomains,
  toggleOfficeIps,
  updateOfficeNumber,
} from "../api/offices.js";
import { deployRpz } from "../api/rpz.js";
import Badge from "../components/Badge.jsx";
import ConfirmDialog from "../components/ConfirmDialog.jsx";
import FileList from "../components/FileList.jsx";
import TrashIcon from "../components/TrashIcon.jsx";
import OfficeImportPanels from "./office/OfficeImportPanels.jsx";
import OfficeDomainsIpsLists from "./office/OfficeDomainsIpsLists.jsx";
import { useToast } from "../components/Toast.jsx";
import { useDeploymentStatus } from "../hooks/useDeploymentStatus.js";
import { formatDateOnly, isDateOnlyExpired } from "../utils/dateOnly.js";

export default function OfficeDetailPage() {
  const { officeId } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { notify } = useToast();

  const [editingNumber, setEditingNumber] = useState(false);
  const [numberDraft, setNumberDraft] = useState("");
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [deployAction, setDeployAction] = useState(null);
  const [activeDeploymentId, setActiveDeploymentId] = useState(null);
  const [activeDeployType, setActiveDeployType] = useState(null);

  const { data: office, isLoading, isError, error } = useQuery({
    queryKey: ["office", officeId],
    queryFn: () => getOffice(officeId),
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["office", officeId] });

  const updateNumberMutation = useMutation({
    mutationFn: (value) => updateOfficeNumber(officeId, value),
    onSuccess: () => {
      notify("Número do ofício atualizado.", "success");
      setEditingNumber(false);
      invalidate();
    },
    onError: (err) => notify(err.message, "error"),
  });

  const toggleDomainsMutation = useMutation({
    mutationFn: () => toggleOfficeDomains(officeId),
    onSuccess: (result) => {
      const label =
        result.action === "activated"
          ? `${result.updated} domínios ativados.`
          : `${result.updated} domínios desativados${result.preserved ? ` (${result.preserved} preservados).` : "."}`;
      notify(label, "success");
      invalidate();
    },
    onError: (err) => notify(err.message, "error"),
  });

  const toggleIpsMutation = useMutation({
    mutationFn: () => toggleOfficeIps(officeId),
    onSuccess: (result) => {
      const label =
        result.action === "activated"
          ? `${result.updated} IPs ativados.`
          : `${result.updated} IPs desativados${result.preserved ? ` (${result.preserved} preservados).` : "."}`;
      notify(label, "success");
      invalidate();
    },
    onError: (err) => notify(err.message, "error"),
  });

  const notificationMutation = useMutation({
    mutationFn: (sent) => setOfficeNotification(officeId, sent),
    onSuccess: (result) => {
      notify(result.notification_sent_at ? "Notificação marcada como enviada." : "Marca de notificação removida.", "success");
      invalidate();
      queryClient.invalidateQueries({ queryKey: ["offices"] });
    },
    onError: (err) => notify(err.message, "error"),
  });

  const deleteMutation = useMutation({
    mutationFn: (confirmNumber) => deleteOffice(officeId, confirmNumber),
    onSuccess: () => {
      notify("Ofício removido.", "success");
      navigate("/offices");
    },
    onError: (err) => notify(err.message, "error"),
  });

  const deployRpzMutation = useMutation({
    mutationFn: deployRpz,
    onSuccess: (result) => {
      notify(result.message || "RPZ publicada com sucesso.", "success");
      setDeployAction(null);
    },
    onError: (err) => {
      notify(err.message, "error");
      setDeployAction(null);
    },
  });

  const deployIpsMutation = useMutation({
    mutationFn: () => deployOfficeIpRoutes(officeId),
    onSuccess: (result) => {
      setDeployAction(null);
      setActiveDeployType("ips");
      setActiveDeploymentId(result.deployment_id);
    },
    onError: (err) => {
      notify(err.message, "error");
      setDeployAction(null);
    },
  });

  const deployExpiredMutation = useMutation({
    mutationFn: () => deployOfficeExpiredIpsDelete(officeId),
    onSuccess: (result) => {
      setDeployAction(null);
      setActiveDeployType("expired");
      setActiveDeploymentId(result.deployment_id);
    },
    onError: (err) => {
      notify(err.message, "error");
      setDeployAction(null);
    },
  });

  const deploymentQuery = useDeploymentStatus(activeDeploymentId);

  useEffect(() => {
    const status = deploymentQuery.data?.status;
    if (!status || status === "running") return;
    if (status === "success") {
      notify(deploymentQuery.data.message || "Publicação concluída.", "success");
    } else {
      notify(deploymentQuery.data.message || "Falha na publicação.", "error");
    }
    setActiveDeploymentId(null);
    setActiveDeployType(null);
  }, [deploymentQuery.data]);

  const deployBusy = Boolean(activeDeploymentId);

  if (isLoading) {
    return <div className="page-loading">Carregando…</div>;
  }

  if (isError) {
    return (
      <div className="messages">
        <div className="message error">{error.message}</div>
      </div>
    );
  }

  const hasActiveDomains = office.domains.some((domain) => domain.active);
  const hasActiveIps = office.ip_addresses.some((address) => address.active);
  const hasActiveExpiredIps = office.ip_addresses.some(
    (address) => address.active && isDateOnlyExpired(address.removal_date)
  );
  const showExpiredIpActions = office.expired_ip_count > 0 && !hasActiveExpiredIps;

  return (
    <div>
      <div className="page-head">
        <div className="card-head">
          <h1>{office.office_number}</h1>
          {editingNumber ? (
            <form
              className="office-number-form"
              onSubmit={(event) => {
                event.preventDefault();
                updateNumberMutation.mutate(numberDraft);
              }}
            >
              <input
                type="text"
                value={numberDraft}
                autoFocus
                onChange={(event) => setNumberDraft(event.target.value)}
              />
              <button type="submit" disabled={updateNumberMutation.isPending}>
                Salvar
              </button>
              <button type="button" className="ghost" onClick={() => setEditingNumber(false)}>
                Cancelar
              </button>
            </form>
          ) : (
            <button
              type="button"
              className="ghost compact"
              onClick={() => {
                setNumberDraft(office.office_number);
                setEditingNumber(true);
              }}
            >
              Alterar número
            </button>
          )}
        </div>
        <div className="actions">
          <button
            type="button"
            disabled={deployRpzMutation.isPending}
            onClick={() => setDeployAction("rpz")}
          >
            {deployRpzMutation.isPending ? "Publicando…" : "Publicar RPZ"}
          </button>
          {showExpiredIpActions && (
            <button
              type="button"
              className="danger-button"
              disabled={deployExpiredMutation.isPending || deployBusy}
              onClick={() => setDeployAction("expired")}
            >
              {deployExpiredMutation.isPending || activeDeployType === "expired"
                ? "Publicando…"
                : "Aplicar remoção IPs expirados"}
            </button>
          )}
          {hasActiveIps && (
            <button
              type="button"
              disabled={deployIpsMutation.isPending || deployBusy}
              onClick={() => setDeployAction("ips")}
            >
              {deployIpsMutation.isPending || activeDeployType === "ips"
                ? "Publicando…"
                : "Publicar IPs no roteador"}
            </button>
          )}
          <button
            type="button"
            className={hasActiveDomains ? "danger-button" : undefined}
            disabled={toggleDomainsMutation.isPending}
            onClick={() => toggleDomainsMutation.mutate()}
          >
            {hasActiveDomains ? "Desativar domínios" : "Ativar domínios"}
          </button>
          <button
            type="button"
            className={hasActiveIps ? "danger-button" : undefined}
            disabled={toggleIpsMutation.isPending}
            onClick={() => toggleIpsMutation.mutate()}
          >
            {hasActiveIps ? "Desativar IPs" : "Ativar IPs"}
          </button>
          <button
            type="button"
            className="icon-danger"
            onClick={() => setDeleteDialogOpen(true)}
            title="Remover ofício"
            aria-label="Remover ofício"
          >
            <TrashIcon />
          </button>
        </div>
      </div>

      <div className="detail-grid">
        <div className="detail-panel">
          <h2>Dados do ofício</h2>
          <dl className="meta-list">
            <div>
              <dt>Processo</dt>
              <dd>{office.process_number || "—"}</dd>
            </div>
            <div>
              <dt>SEI</dt>
              <dd>{office.sei_numbers || "—"}</dd>
            </div>
            <div>
              <dt>Expedição</dt>
              <dd>
                {office.expedition_date ? formatDateOnly(office.expedition_date) : "—"}
              </dd>
            </div>
            <div>
              <dt>Notificação (comunicado)</dt>
              <dd>
                <Badge variant={office.notification_sent_at ? "success" : "warning"}>
                  {office.notification_sent_at ? "enviada" : "pendente"}
                </Badge>{" "}
                {office.notification_sent_at && new Date(office.notification_sent_at).toLocaleString("pt-BR")}{" "}
                <button
                  type="button"
                  className="ghost compact"
                  disabled={notificationMutation.isPending}
                  onClick={() => notificationMutation.mutate(!office.notification_sent_at)}
                >
                  {office.notification_sent_at ? "Desmarcar" : "Marcar como enviada"}
                </button>{" "}
                <Link to="/comunicados">Comunicados</Link>
              </dd>
            </div>
            <div>
              <dt>Criado por</dt>
              <dd>{office.created_by_user ? office.created_by_user.username : "—"}</dd>
            </div>
            <div>
              <dt>Criado em</dt>
              <dd>{new Date(office.created_at).toLocaleString("pt-BR")}</dd>
            </div>
            <div>
              <dt>Domínios (novos / repetidos)</dt>
              <dd>
                {office.total_found} ({office.new_count} novos, {office.existing_count} repetidos)
              </dd>
            </div>
            <div>
              <dt>IPs (novos / repetidos)</dt>
              <dd>
                {office.ip_stats.total} ({office.ip_stats.new} novos, {office.ip_stats.existing} repetidos)
              </dd>
            </div>
          </dl>
        </div>

        <div className="detail-panel">
          <h2>Arquivos</h2>
          <FileList
            files={office.files}
            viewPath={(file) => `/offices/${officeId}/files/${file.id}`}
            downloadPath={(file) => `/offices/${officeId}/files/${file.id}/download`}
            emptyLabel="Nenhum arquivo anexado."
          />
          {office.ip_files.length > 0 && (
            <>
              <h2>Arquivos de IP</h2>
              <FileList
                files={office.ip_files}
                viewPath={(file) => `/ip-batches/${file.batch_id}/files/${file.id}`}
                downloadPath={(file) => `/ip-batches/${file.batch_id}/files/${file.id}/download`}
              />
            </>
          )}
        </div>
      </div>

      <OfficeImportPanels officeId={officeId} />

      <OfficeDomainsIpsLists
        domains={office.domains}
        ipAddresses={office.ip_addresses}
        officeId={officeId}
        officeNumber={office.office_number}
        ipBatchId={office.ip_batches[0]?.id}
      />

      <p style={{ marginTop: 24 }}>
        <Link to="/offices">← Voltar para ofícios</Link>
      </p>

      <ConfirmDialog
        open={deleteDialogOpen}
        title="Remover ofício"
        message={`Esta ação é irreversível. Domínios e IPs exclusivos deste ofício serão apagados; os compartilhados com outros ofícios serão preservados.`}
        mode="type"
        expectedText={office.office_number}
        confirmLabel="Remover ofício"
        danger
        busy={deleteMutation.isPending}
        onConfirm={() => deleteMutation.mutate(office.office_number)}
        onCancel={() => setDeleteDialogOpen(false)}
      />

      <ConfirmDialog
        open={deployAction === "rpz"}
        title="Confirmar publicação"
        message="Esta ação vai substituir o arquivo remoto /var/cache/bind/db.rpz.zone e executar o reload configurado, com todos os domínios ativos do sistema (não só deste ofício)."
        confirmLabel="Confirmar e publicar"
        busy={deployRpzMutation.isPending}
        onConfirm={() => deployRpzMutation.mutate()}
        onCancel={() => setDeployAction(null)}
      />

      <ConfirmDialog
        open={deployAction === "ips"}
        title="Publicar IPs no roteador"
        message="Publicar somente os IPs deste ofício no roteador de borda?"
        confirmLabel="Confirmar e publicar"
        busy={deployIpsMutation.isPending}
        onConfirm={() => deployIpsMutation.mutate()}
        onCancel={() => setDeployAction(null)}
      />

      <ConfirmDialog
        open={deployAction === "expired"}
        title="Remover IPs expirados no roteador"
        message="Aplicar no roteador a remoção dos IPs expirados deste ofício?"
        confirmLabel="Confirmar e remover"
        danger
        busy={deployExpiredMutation.isPending}
        onConfirm={() => deployExpiredMutation.mutate()}
        onCancel={() => setDeployAction(null)}
      />
    </div>
  );
}
