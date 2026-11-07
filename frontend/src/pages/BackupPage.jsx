import React, { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import DownloadButton from "../components/DownloadButton.jsx";
import ConfirmDialog from "../components/ConfirmDialog.jsx";
import BackupSchedulePanel from "../components/BackupSchedulePanel.jsx";
import { restoreDatabase, restoreFiles } from "../api/backup.js";
import { useToast } from "../components/Toast.jsx";

const CONFIRM_PHRASE = "RESTAURAR";

export default function BackupPage() {
  const { notify } = useToast();
  const [dbFile, setDbFile] = useState(null);
  const [filesFile, setFilesFile] = useState(null);
  const [confirmDbOpen, setConfirmDbOpen] = useState(false);
  const [confirmFilesOpen, setConfirmFilesOpen] = useState(false);

  const restoreDbMutation = useMutation({
    mutationFn: () => restoreDatabase(dbFile),
    onSuccess: () => {
      notify("Banco de dados restaurado com sucesso.", "success");
      setConfirmDbOpen(false);
      setDbFile(null);
    },
    onError: (err) => {
      notify(err.message, "error");
      setConfirmDbOpen(false);
    },
  });

  const restoreFilesMutation = useMutation({
    mutationFn: () => restoreFiles(filesFile),
    onSuccess: () => {
      notify("Arquivos restaurados com sucesso.", "success");
      setConfirmFilesOpen(false);
      setFilesFile(null);
    },
    onError: (err) => {
      notify(err.message, "error");
      setConfirmFilesOpen(false);
    },
  });

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Backup</h1>
          <p>Baixe, agende ou restaure o banco de dados e os arquivos anexados aos ofícios.</p>
        </div>
        <div className="actions">
          <Link className="button ghost" to="/general">
            Voltar
          </Link>
        </div>
      </div>

      <h2>Baixar backup</h2>
      <div className="deploy-box">
        <div className="deploy-option">
          <p>
            Gera um dump completo do banco de dados (schema + dados) em SQL, pronto para restaurar
            com <code>mysql</code>.
          </p>
          <DownloadButton path="/backup/database" filename="backup-banco.sql">
            Baixar backup do banco
          </DownloadButton>
        </div>
        <div className="deploy-option">
          <p>
            Gera um .zip com todos os arquivos anexados aos ofícios (intimações e listas de
            domínios/IPs importadas).
          </p>
          <DownloadButton path="/backup/files" filename="backup-arquivos.zip">
            Baixar backup dos arquivos
          </DownloadButton>
        </div>
      </div>

      <h2>Backup automático (FTP)</h2>
      <BackupSchedulePanel />

      <h2>Restaurar backup</h2>
      <div className="deploy-box">
        <div className="deploy-option">
          <p>
            <strong>Restaura o banco de dados</strong> a partir de um arquivo .sql ou .sql.gz: apaga e recria
            todas as tabelas, substituindo todos os dados atuais pelos do backup. Ação irreversível.
          </p>
          <input
            type="file"
            accept=".sql,.gz"
            onChange={(event) => setDbFile(event.target.files?.[0] || null)}
          />
          <button
            type="button"
            className="danger-button"
            disabled={!dbFile}
            onClick={() => setConfirmDbOpen(true)}
          >
            Restaurar banco de dados
          </button>
        </div>
        <div className="deploy-option">
          <p>
            <strong>Restaura os arquivos</strong> a partir de um .zip: apaga a pasta de uploads
            atual e extrai o .zip enviado no lugar (espelho exato do backup — arquivos anexados
            depois do backup são perdidos). Ação irreversível.
          </p>
          <input
            type="file"
            accept=".zip"
            onChange={(event) => setFilesFile(event.target.files?.[0] || null)}
          />
          <button
            type="button"
            className="danger-button"
            disabled={!filesFile}
            onClick={() => setConfirmFilesOpen(true)}
          >
            Restaurar arquivos
          </button>
        </div>
      </div>

      <ConfirmDialog
        open={confirmDbOpen}
        title="Restaurar banco de dados"
        message="Esta ação apaga e recria todas as tabelas do banco a partir do arquivo enviado, substituindo todos os dados atuais. Não pode ser desfeita."
        mode="type"
        expectedText={CONFIRM_PHRASE}
        confirmLabel="Restaurar banco de dados"
        danger
        busy={restoreDbMutation.isPending}
        onConfirm={() => restoreDbMutation.mutate()}
        onCancel={() => setConfirmDbOpen(false)}
      />

      <ConfirmDialog
        open={confirmFilesOpen}
        title="Restaurar arquivos"
        message="Esta ação apaga a pasta de uploads atual e extrai o .zip enviado no lugar, substituindo todos os arquivos atuais. Não pode ser desfeita."
        mode="type"
        expectedText={CONFIRM_PHRASE}
        confirmLabel="Restaurar arquivos"
        danger
        busy={restoreFilesMutation.isPending}
        onConfirm={() => restoreFilesMutation.mutate()}
        onCancel={() => setConfirmFilesOpen(false)}
      />
    </div>
  );
}
