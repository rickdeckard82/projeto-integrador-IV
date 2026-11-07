// Histórico de versões exibido ao clicar na versão do rodapé.
// Adicione cada nova versão no topo da lista, junto com o arquivo VERSION.
export const CHANGELOG = [
  {
    version: "1.5.0",
    date: "2026-10-20",
    summary: "Comunicados enviados por e-mail direto pelo sistema e caixa de abuse (IMAP) configurada em Parâmetros.",
    added: [
      "Comunicados: o e-mail pode levar o db.rpz.zone e a config de IPs do ofício (gerados na hora) e outros arquivos do computador (até 10 anexos, 20 MB no total); os nomes dos anexos ficam no histórico.",
      "Comunicados: botão \"Enviar e-mail\" com destinatário(s) (um ou mais), assunto e o texto gerado; a assinatura cadastrada é adicionada ao final.",
      "Comunicados: o número do ofício agora é selecionado numa lista (preenche também o número do processo).",
      "Comunicados: lista \"E-mails enviados\" com data, ofício, destinatários, assunto, status (enviado ou falhou), usuário e o texto completo.",
      "Ofício: indica se a notificação foi enviada (marcada automaticamente no envio, com opção de marcar ou desmarcar à mão); a lista de ofícios também mostra a coluna Notificação.",
      "Parâmetros: seção E-mail (SMTP) com servidor, porta, segurança (STARTTLS, SSL/TLS ou nenhuma), usuário, senha, remetente, assinatura e botão para testar a conexão.",
    ],
    changed: [
      "A caixa de abuse (IMAP: servidor, porta, caixa, usuário e senha) passou do .env para Geral > Parâmetros, com botão de testar a conexão. O que estava no .env é copiado uma única vez na atualização, e o worker relê a configuração a cada rodada, sem reiniciar. CA própria e timeout continuam no .env.",
      "A senha do SMTP nunca é devolvida pela API: campo em branco mantém a atual e \"Apagar a senha salva\" remove.",
      "Remover um ofício mantém o histórico de e-mails enviados dele.",
    ],
  },
  {
    version: "1.4.2",
    date: "2026-10-20",
    summary: "Atualização das dependências: nenhuma vulnerabilidade conhecida no backend nem no frontend.",
    fixed: [
      "Leitura de PDF (pypdf 6.21.1), Flask 3.1.3, Werkzeug 3.1.9 e python-dotenv 1.2.4, com as correções de segurança publicadas.",
      "SSH com paramiko 5.0.1: assinatura RSA com SHA-1 e troca de chaves com SHA-1 deixam de ser aceitas.",
      "Frontend com react-router 7.18.4 (redirecionamento aberto em links) e build com Vite 7.",
    ],
    changed: [
      "BIND e roteadores precisam aceitar rsa-sha2 (qualquer OpenSSH/Junos atual); equipamentos que só falam ssh-rsa com SHA-1, DH-SHA1 ou chave DSA deixam de conectar.",
    ],
  },
  {
    version: "1.4.1",
    date: "2026-10-20",
    summary: "Atalhos make para instalar, subir, testar e manter o sistema.",
    added: [
      "Makefile com os atalhos do projeto (make help lista todos): init cria o .env com senhas aleatórias, up/rebuild/down, logs, test, mysql, audit de dependências, backup e teste de restauração.",
    ],
    fixed: [
      "A pasta de testes não entra mais na imagem de produção (.dockerignore).",
    ],
  },
  {
    version: "1.4.0",
    date: "2026-10-20",
    summary: "Servidores BIND, roteadores e credenciais SSH configurados em Geral > Parâmetros, sem passar pelo .env.",
    added: [
      "Cadastro de um ou mais servidores BIND em Parâmetros, cada um com host, porta, usuário, senha ou chave SSH, senha do sudo, arquivo da zona, comando de reload e resolver de teste. A zona RPZ é publicada em todos e o resultado de cada servidor fica no Log.",
      "Credenciais SSH próprias para cada roteador de publicação (porta, usuário, senha ou chave).",
      "Servidor de nomes do SOA/NS da zona RPZ e a verificação da chave de host SSH configurados em Parâmetros.",
      "Senhas salvas nunca aparecem na tela: campo em branco mantém a senha atual e o botão \"Apagar\" remove uma senha salva.",
    ],
    changed: [
      "A configuração SSH que estava no .env (SSH_*, SUDO_PASSWORD, RPZ_*, ROUTER_SSH_*) é copiada para Parâmetros uma única vez na atualização e depois deixa de ser lida.",
    ],
    fixed: [
      "Parâmetros: voltar para a aba do navegador não descarta mais o que estava sendo editado.",
    ],
  },
  {
    version: "1.3.2",
    date: "2026-10-19",
    summary: "Configuração sem endereços, nomes de servidor ou senhas fixos no código.",
    added: [
      "Variável RPZ_NAMESERVER no .env define o servidor de nomes do SOA/NS da zona RPZ (vazio = localhost).",
    ],
    changed: [
      "O docker compose exige SECRET_KEY, ADMIN_PASSWORD, MYSQL_USER, MYSQL_PASSWORD e MYSQL_ROOT_PASSWORD no .env, em vez de usar senhas padrão.",
      "ROUTER_SSH_HOST não tem mais roteador padrão: sem roteadores cadastrados em Parâmetros e sem essa variável, a publicação de IPs avisa que falta configurar.",
      "Comunicações: sem nome da empresa cadastrado, a assinatura fica \"Plantão NOC 24x7\".",
    ],
  },
  {
    version: "1.3.1",
    date: "2026-10-19",
    summary: "Backup automático para servidores FTP só de gravação, como o Pulse Backup.",
    added: [
      "Opção \"Destino só de gravação (Pulse Backup)\" no backup automático: envia cada arquivo direto com o nome final, sem .part, conferência de tamanho ou renomeação, e não apaga cópias antigas no FTP (o histórico fica no servidor de backup).",
    ],
  },
  {
    version: "1.3.0",
    date: "2026-10-19",
    summary: "Backup automático diário do banco e dos arquivos dos ofícios por FTP.",
    added: [
      "Backup automático por FTP/FTPS em Geral > Backup: horário diário, banco e/ou arquivos, quantidade de cópias mantidas no servidor, teste de conexão e execução imediata.",
      "Container backup-worker, que gera e envia o backup sem deixar cópia local e apaga as cópias antigas no FTP.",
      "Cada execução do backup automático fica registrada no Log, com os arquivos enviados ou o erro.",
    ],
    changed: [
      "Restaurar banco aceita também o .sql.gz gerado pelo backup automático.",
    ],
  },
  {
    version: "1.2.4",
    date: "2026-10-19",
    summary: "Leitura dos relatórios do SpamCop nas notificações de abuse.",
    added: [
      "Relatórios do SpamCop (\"Email from IP / data\") viram incidente de spam com IP e horário, inclusive quando encaminhados; o SpamCop não informa porta de origem.",
    ],
  },
  {
    version: "1.2.3",
    date: "2026-10-19",
    summary: "Leitura de amostras tcpdump em notificações de abuse encaminhadas pelo Outlook.",
    fixed: [
      "Amostras tcpdump com o cabeçalho do pacote quebrado em várias linhas (encaminhamento pelo Outlook) agora geram o incidente com porta de origem e horário.",
    ],
  },
  {
    version: "1.2.2",
    date: "2026-10-19",
    summary:
      "Leitura de notificações de abuse com X-ARF 4.2 e amostras tcpdump, sem incidentes duplicados para o mesmo IP.",
    added: [
      "Leitura de relatórios X-ARF 4.2 (ex.: lrob.net), inclusive quando o cabeçalho X-ARF não é \"yes\".",
      "Leitura de amostras de tcpdump no texto (ex.: NFOservers encaminhado pelo CERT.br), com porta de origem, destino e horário; pacotes do mesmo fluxo viram um só incidente.",
    ],
    fixed: [
      "Menção solta do IP no texto não gera mais um incidente extra sem porta e horário quando a mesma notificação já traz esses dados.",
    ],
  },
  {
    version: "1.2.1",
    date: "2026-10-18",
    summary:
      "Data de recebimento das notificações de abuse igual à do webmail e reprocessamento em lote das mensagens não reconhecidas.",
    added: [
      "Botão para reprocessar de uma vez todas as mensagens não reconhecidas, depois de cadastrar ou corrigir os prefixos próprios.",
    ],
    changed: [
      "\"Recebida em\" passa a usar a data de chegada no servidor de e-mail (a mesma do webmail), e não o cabeçalho Date do remetente.",
    ],
    fixed: [
      "Mensagens com cabeçalho Date inválido (comum em spam) apareciam com a data da coleta; as já coletadas são corrigidas automaticamente na próxima coleta.",
    ],
  },
  {
    version: "1.2.0",
    date: "2026-10-18",
    summary:
      "Início do módulo de notificações de abuse: estrutura para registrar notificações recebidas, incidentes por IP, regras do CGNAT determinístico e auditoria de acesso.",
    added: [
      "Estrutura de banco do módulo de abuse: mensagens recebidas, incidentes, regras de CGNAT com vigência, configurações e log de auditoria.",
      "Permissão de acesso ao módulo de abuse por usuário (somente o administrador inicial recebe acesso automaticamente).",
      "Cálculo do CGNAT determinístico (IP público + porta + horário → IP privado), com alocação intercalada (A10 use-all-nat-ips) ou sequencial e regras com vigência.",
      "Leitura do arquivo de fixed-nat exportado pelo A10, conferindo todas as linhas antes de aceitar a regra.",
      "Leitura das notificações de abuse nos formatos X-ARF, ARF (RFC 5965), CSV anexado e texto livre, considerando só IPs dos prefixos próprios e separando porta de origem e de destino.",
      "Coleta automática da caixa de abuse por IMAPS (container abuse-worker), em modo somente leitura, com controle por UID, deduplicação por Message-ID e cópia do e-mail bruto para auditoria.",
      "Tela Abuse: lista de incidentes com filtros e exportação CSV, detalhe com IP privado calculado, janela de consulta, reincidência e campos de identificação e tratamento.",
      "Tela de mensagens não reconhecidas ou com erro, com o e-mail em texto puro, download do .eml e reprocessamento.",
      "Telas em Geral para configurar o módulo de abuse (prefixos próprios, fusos por remetente, janela, reincidência, retenção) e importar regras de CGNAT do A10 com vigência.",
      "Acesso ao módulo de abuse por usuário, concedido só por quem já tem acesso, com registro em log de quem visualizou ou alterou cada incidente.",
      "Log de acesso ao módulo de abuse: quem visualizou, exportou ou alterou cada incidente, mensagem, regra ou configuração.",
      "Retenção diária: incidentes tratados são anonimizados 30 dias após o tratamento e o e-mail bruto é apagado 30 dias após o tratamento de todos os incidentes da mensagem (prazos configuráveis).",
      "Teste semanal de restauração do backup passa a conferir também os e-mails brutos do módulo de abuse.",
      "Testes automatizados (pytest) para a estrutura do banco, o cálculo do CGNAT, a leitura das notificações, a coleta IMAP, a API e a retenção do módulo.",
    ],
    changed: [
      "A senha de um usuário com acesso ao módulo de abuse só pode ser trocada por ele mesmo ou por outro usuário com acesso; o último usuário com acesso não pode ser desativado.",
    ],
    fixed: [],
  },
  {
    version: "1.1.0",
    date: "2026-10-05",
    summary:
      "Gráficos no painel, backup automático criptografado e verificação da chave de host SSH, além de correções na importação de planilhas e no status de IPs reimportados.",
    added: [
      "Gráficos de rosca com a distribuição de domínios e IPs (ativos em prazo, removíveis e inativos) no painel.",
      "Gráfico de barras com a quantidade de ofícios nos últimos 12 meses no painel.",
      "Backup automático criptografado (banco, anexos e configuração) com rotação local e envio por rsync via SSH ou rsync daemon.",
      "Teste semanal de restauração do backup em um MySQL descartável, conferindo linhas, anexos e configuração.",
      "Verificação da chave de host SSH na publicação para o BIND e os roteadores, via known_hosts montado no container.",
    ],
    changed: [
      "IP ou domínio desativado manualmente volta a ficar ativo quando é citado em um novo ofício.",
    ],
    fixed: [
      "Importação de planilhas trazia domínios de colunas e abas auxiliares (ex.: provedor de hospedagem); agora só lê as colunas com cabeçalho de domínio.",
      "IP reimportado sem prazo em um ofício novo continuava aparecendo como expirado por causa de um ofício antigo.",
      "Rolagem horizontal no painel e tabela de ofícios recentes desalinhada com os gráficos.",
      "Caminhos de volume do .env.example ainda apontavam para o nome antigo do projeto (oficios-anatel).",
    ],
  },
  {
    version: "1.0.0",
    date: "2026-09-27",
    summary:
      "Primeira versão estável: controle de ofícios, consolidação de domínios e IPs, geração e publicação da zona RPZ no BIND, rotas discard nos roteadores e comunicados.",
    added: [
      "Ondas animadas no rodapé da tela de login e das telas internas.",
      "Histórico de versões acessível ao clicar na versão no rodapé.",
      "Arquivo .env.example com todas as variáveis de configuração documentadas.",
    ],
    changed: [
      "Rodapé passa a exibir a versão lida do arquivo VERSION (via /api/v1/health), em vez de um valor fixo no código.",
      "Adicionados .gitignore e .dockerignore para manter .env, uploads, chaves SSH e node_modules fora do repositório e das imagens.",
    ],
    fixed: ["Rodapé exibia a versão desatualizada v0.2.0."],
  },
];

export const CHANGELOG_SECTIONS = [
  { key: "added", title: "Novidades" },
  { key: "changed", title: "Alterações" },
  { key: "fixed", title: "Correções" },
];
