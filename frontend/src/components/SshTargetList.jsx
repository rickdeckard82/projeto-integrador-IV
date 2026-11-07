import React, { useId } from "react";

// Lista de alvos SSH (servidores BIND ou roteadores) com credenciais próprias.
// As senhas nunca vêm da API: "<campo>_set" indica que há uma salva, campo em branco
// mantém a atual e "clear" pede para apagá-la ao salvar.

const BIND_DEFAULTS = {
  remote_path: "/var/cache/bind/db.rpz.zone",
  reload_command: "sudo service bind9 reload",
  test_resolver: "127.0.0.1",
};

export function emptyTarget(kind) {
  const target = { name: "", host: "", port: 22, user: "", password: "", key_path: "", key_passphrase: "" };
  return kind === "bind" ? { ...target, sudo_password: "", ...BIND_DEFAULTS } : target;
}

function SecretField({ label, item, field, onChange }) {
  const id = useId();
  const saved = Boolean(item[`${field}_set`]);
  const clear = item.clear || [];
  const clearing = clear.includes(field);

  function toggleClear() {
    const next = clearing ? clear.filter((name) => name !== field) : [...clear, field];
    onChange({ ...item, clear: next, [field]: "" });
  }

  let placeholder = "";
  if (clearing) placeholder = "(será apagada ao salvar)";
  else if (saved) placeholder = "(mantida — preencha para trocar)";

  return (
    <div className="secret-field">
      <div className="secret-field-head">
        <label htmlFor={id}>{label}</label>
        {saved && (
          <button className="ghost txt-button" type="button" onClick={toggleClear}>
            {clearing ? "Manter" : "Apagar"}
          </button>
        )}
      </div>
      <input
        id={id}
        type="password"
        autoComplete="new-password"
        disabled={clearing}
        placeholder={placeholder}
        value={item[field] || ""}
        onChange={(event) => onChange({ ...item, [field]: event.target.value })}
      />
    </div>
  );
}

function TextField({ label, item, field, placeholder, type = "text", className, onChange }) {
  return (
    <label className={className}>
      {label}
      <input
        type={type}
        autoComplete="off"
        placeholder={placeholder}
        value={item[field] ?? ""}
        onChange={(event) => onChange({ ...item, [field]: event.target.value })}
      />
    </label>
  );
}

export default function SshTargetList({ kind, title, addLabel, itemLabel, values, onChange }) {
  function updateAt(index, item) {
    const next = [...values];
    next[index] = item;
    onChange(next);
  }

  function removeAt(index) {
    onChange(values.filter((_, i) => i !== index));
  }

  return (
    <div className="dynamic-list">
      <div className="dynamic-list-head">
        <h3>{title}</h3>
        <button className="ghost" type="button" onClick={() => onChange([...values, emptyTarget(kind)])}>
          {addLabel}
        </button>
      </div>
      {values.length === 0 && <p className="form-note">Nenhum {itemLabel} cadastrado.</p>}
      <div className="dynamic-list-items">
        {values.map((item, index) => {
          const change = (next) => updateAt(index, next);
          return (
            <fieldset className="ssh-target" key={item.id || `new-${index}`}>
              <div className="ssh-target-head">
                <strong>{item.name || item.host || `Novo ${itemLabel}`}</strong>
                <button className="ghost compact" type="button" onClick={() => removeAt(index)}>
                  Remover
                </button>
              </div>
              <div className="form-grid">
                <TextField label="Nome" item={item} field="name" onChange={change} />
                <TextField label="IP/host" item={item} field="host" onChange={change} />
                <TextField label="Porta SSH" type="number" item={item} field="port" onChange={change} />
                <TextField label="Usuário SSH" item={item} field="user" onChange={change} />
                <SecretField label="Senha SSH" item={item} field="password" onChange={change} />
                <TextField
                  label="Caminho da chave privada (no container)"
                  placeholder="/run/secrets/bind_ssh_key"
                  item={item}
                  field="key_path"
                  onChange={change}
                />
                <SecretField label="Senha da chave privada" item={item} field="key_passphrase" onChange={change} />
                {kind === "bind" && (
                  <>
                    <SecretField label="Senha do sudo" item={item} field="sudo_password" onChange={change} />
                    <TextField label="Arquivo da zona" item={item} field="remote_path" onChange={change} />
                    <TextField label="Comando de reload" item={item} field="reload_command" onChange={change} />
                    <TextField
                      label="Resolver para o teste de bloqueio"
                      item={item}
                      field="test_resolver"
                      onChange={change}
                    />
                  </>
                )}
              </div>
            </fieldset>
          );
        })}
      </div>
    </div>
  );
}
