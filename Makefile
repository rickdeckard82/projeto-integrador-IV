SHELL := /bin/bash
COMPOSE := docker compose
APP_IMAGE := oficios-rpz-app
NODE_IMAGE := node:20.20.2-alpine
APP_SERVICES := api frontend whois-worker abuse-worker backup-worker
# Git Bash no Windows converte "/app" em "C:/Program Files/Git/app" nos argumentos do docker.
export MSYS_NO_PATHCONV := 1
# Os scripts de backup leem /etc/oficios-rpz/backup.env (root, chmod 600).
SUDO := $(shell [ "$$(id -u)" = 0 ] || echo sudo)

.PHONY: help init build up rebuild down clean ps logs health shell mysql migrate test frontend-build audit backup restore-test

help: ## Lista os alvos disponíveis
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-15s\033[0m %s\n",$$1,$$2}'

init: ## Cria .env a partir do exemplo com segredos aleatórios (só precisa de openssl)
	@if [ -f .env ]; then echo ">> .env já existe, mantido."; exit 0; fi; \
	 cp .env.example .env; \
	 sed -i \
	   -e "s|^SECRET_KEY=.*|SECRET_KEY=$$(openssl rand -hex 48)|" \
	   -e "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=$$(openssl rand -base64 15 | tr -d '/+=')|" \
	   -e "s|^MYSQL_PASSWORD=.*|MYSQL_PASSWORD=$$(openssl rand -hex 16)|" \
	   -e "s|^MYSQL_ROOT_PASSWORD=.*|MYSQL_ROOT_PASSWORD=$$(openssl rand -hex 16)|" \
	   .env; \
	 chmod 600 .env; \
	 echo ">> .env criado. Ajuste os caminhos HOST_* e NPM_* para o servidor."; \
	 echo ">> Usuário admin inicial: $$(grep ^ADMIN_USERNAME= .env | cut -d= -f2-) / senha: $$(grep ^ADMIN_PASSWORD= .env | cut -d= -f2-)"; \
	 echo ">> BIND, roteadores e credenciais SSH são cadastrados depois em Geral > Parâmetros."

build: ## Builda as imagens
	$(COMPOSE) build

up: ## Sobe a stack (db, api, frontend e workers)
	$(COMPOSE) up -d

rebuild: ## Rebuilda e recria api, frontend e workers após alterar código (o banco fica)
	$(COMPOSE) build api frontend
	$(COMPOSE) up -d --force-recreate $(APP_SERVICES)

down: ## Derruba a stack (mantém o volume do banco)
	$(COMPOSE) down

clean: ## Derruba e APAGA o volume do banco (pede confirmação)
	@read -r -p "Isto APAGA o banco (volume oficios-rpz_mysql_data). Digite APAGAR para confirmar: " ok; \
	 [ "$$ok" = "APAGAR" ] || { echo ">> Cancelado."; exit 1; }
	$(COMPOSE) down -v

ps: ## Status dos containers
	$(COMPOSE) ps

logs: ## Segue os logs (um serviço só: make logs s=api)
	$(COMPOSE) logs -f --tail=100 $(s)

health: ## Confere o /health da API (de dentro do container: a api não publica porta)
	$(COMPOSE) exec api python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8000/api/v1/health').read().decode())"

shell: ## Abre um shell no container da api
	$(COMPOSE) exec api bash

mysql: ## Abre o cliente mysql no banco da aplicação
	$(COMPOSE) exec db sh -c 'MYSQL_PWD="$$MYSQL_PASSWORD" exec mysql -u"$$MYSQL_USER" "$$MYSQL_DATABASE"'

migrate: ## Aplica as alterações de schema (a api já faz isso ao subir)
	$(COMPOSE) exec api python -m app.init_db

test: ## Roda os testes (pytest, SQLite em memória) num container da imagem da api: make test a="-k abuse"
	$(COMPOSE) build api
	docker run --rm -v "$(CURDIR):/app" -w /app $(APP_IMAGE) \
	  sh -c "pip install -q -r requirements-dev.txt && python -m pytest -q -p no:cacheprovider $(a)"

frontend-build: ## Confere se o frontend builda (vite build num container descartável)
	docker run --rm -v "$(CURDIR)/frontend:/app" -v /app/node_modules -v /app/dist -w /app $(NODE_IMAGE) \
	  sh -c "npm ci --no-audit --no-fund >/dev/null && npm run build"

audit: ## Vulnerabilidades conhecidas nas dependências (pip-audit e npm audit; roda os dois)
	@status=0; \
	 echo ">> Python (requirements.txt)"; \
	 docker run --rm -v "$(CURDIR):/app" -w /app $(APP_IMAGE) \
	   sh -c "pip install -q pip-audit 2>/dev/null && pip-audit -r requirements.txt" || status=1; \
	 echo ">> Frontend (package-lock.json)"; \
	 docker run --rm -v "$(CURDIR)/frontend:/app" -v /app/node_modules -w /app $(NODE_IMAGE) \
	   npm audit --omit=dev || status=1; \
	 exit $$status

backup: ## Backup manual criptografado (banco + anexos + config), ver README > Backup automático
	$(SUDO) ./scripts/backup/backup.sh

restore-test: ## Testa a restauração do último backup num MySQL descartável
	$(SUDO) ./scripts/backup/restore-test.sh
