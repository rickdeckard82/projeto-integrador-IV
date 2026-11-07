# Ofícios RPZ

Sistema web para controlar ofícios de bloqueio/desbloqueio, consolidar domínios e IPs, gerar zonas RPZ para BIND e publicar configurações via SSH (BIND + roteador MX204).

- **`frontend`**: SPA React + Vite, servida por nginx, consome `api` via `/api/`.
- **`api`**: backend Flask, só JSON em `/api/v1`.
- **`db`**: MySQL 8.4.
- **`whois-worker`**: worker em background para consultas WHOIS/RDAP.
- **`abuse-worker`**: coleta IMAP das notificações de abuse.
- **`backup-worker`**: backup agendado (banco + anexos) por FTP.

Detalhes de arquitetura, fluxo de uso, endpoints da API e variáveis de ambiente estão em [README.md](README.md).

## Padrão visual (frontend)

Antes de criar ou alterar CSS, componentes de UI, cores ou tipografia neste projeto, siga **[docs/DESIGN_SYSTEM.md](docs/DESIGN_SYSTEM.md)**.

Resumo do que esse documento define:

- Paleta de cores (tema dark-only) e as CSS variables de `frontend/src/styles/global.css`
- Tipografia (Arial/Helvetica no produto, monoespaçada para saída técnica) e escala de tamanhos
- Espaçamento, raio de borda e os dois breakpoints padrão (820px / 1180px)
- Componentes-padrão (botão, badge, mensagem, tabela, card, modal) e como criar variantes
- O que evitar (cor hardcoded, novos breakpoints, introduzir Tailwind/CSS-in-JS sem decisão explícita)

Esse mesmo padrão deve ser reaproveitado em novos projetos frontend — não recriar um sistema de estilo do zero sem necessidade real.
