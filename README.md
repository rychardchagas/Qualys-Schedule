# Qualys Schedule

Automação de agendamento e orquestração de scans no **Qualys WAS (Web Application Scanning)**, com dashboard web em tempo real para monitoramento e download de reports.

## Visão Geral

O sistema autentica na API Qualys, distribui URLs entre os workers (WebApps) configurados respeitando afinidade de worker, monitora a execução dos scans e gera relatórios PDF e CSV automaticamente ao final de cada scan.

**Fluxo de execução:**
1. Inicia o servidor web → dashboard disponível em `http://<host>:8080`
2. Usuário autentica no dashboard (usuário/senha Qualys)
3. Usuário informa as URLs e clica em **Iniciar**
4. Sistema consulta a API Qualys (WebApps, option profiles, scans do mês)
5. Orquestração automática dos scans com afinidade de worker
6. Download automático dos reports (PDF e CSV) ao final de cada scan
7. Possibilidade de reiniciar a rotina

## Estrutura do Projeto

```
qualys-schedule/
├── main.py                 # Entry point
├── requirements.txt        # Dependências Python
├── .gitignore
├── config/
│   └── settings.py         # Configurações centralizadas (lidas de env vars)
├── core/
│   ├── port_checker.py     # Validação de portas (proteção SSRF)
│   └── shared_state.py     # Estado compartilhado entre threads
├── qualys/
│   ├── client.py           # Cliente HTTP da API Qualys WAS
│   ├── scan_tracker.py     # Rastreamento de scans do mês e afinidade de worker
│   └── service.py          # Camada de negócio sobre o client
├── web/
│   ├── server.py           # Servidor HTTP do dashboard (stdlib)
│   ├── dashboard.html      # Página principal / orquestração
│   ├── historico.html      # Histórico de scans do mês
│   ├── vulns.html          # Vulnerabilidades encontradas
│   └── reports.html        # Downloads de reports gerados
├── logs/                   # Logs de execução (gerado em runtime)
└── reports/                # Reports PDF/CSV gerados (gerado em runtime)
```

## Requisitos

- Python 3.11+
- Acesso HTTPS de saída para `<API do qualys>`
- Conta Qualys com permissão no módulo WAS

## Instalação

```bash
git clone <repo-url>
cd qualys-schedule

python -m venv .venv
source .venv/bin/activate       # Linux/macOS
.venv\Scripts\activate          # Windows

pip install -r requirements.txt
```

## Configuração

Toda a configuração é feita via variáveis de ambiente. Crie um arquivo `.env` na raiz (já ignorado pelo `.gitignore`) ou exporte diretamente no shell/systemd.

### Workers (WebApps Qualys WAS)

Defina uma variável por worker usando o prefixo `QUALYS_WORKER_`. O sufixo vira o nome do worker exibido no dashboard, e o valor é o ID numérico do WebApp no Qualys WAS.

```bash
QUALYS_WORKER_VULN1=123456789
QUALYS_WORKER_VULN2=987654321
QUALYS_WORKER_VULN3=111222333
```

Os IDs estão disponíveis no console Qualys em **WAS > Web Applications**.

Para escalar, basta adicionar mais variáveis — não há limite e nenhum arquivo precisa ser modificado.

### Demais variáveis

| Variável                  | Padrão                                              | Descrição                              |
|---------------------------|-----------------------------------------------------|----------------------------------------|
| `QUALYS_SCAN_PROFILE_ID`  | *(vazio — usa o profile padrão do WebApp)*          | ID do option profile de scan           |
| `QUALYS_API_BASE`         | `https://<API do qualys>/qps/rest/3.0`| URL base da API Qualys                 |
| `QUALYS_MAX_CONCURRENT`   | `3`                                                 | Máximo de requisições simultâneas      |
| `QUALYS_SCAN_INTERVAL`    | `300`                                               | Intervalo de polling dos scans (seg)   |
| `QUALYS_WEB_HOST`         | `0.0.0.0`                                           | Host do servidor web                   |
| `QUALYS_WEB_PORT`         | `8080`                                              | Porta do servidor web                  |

### Exemplo de arquivo `.env`

```bash
# Workers
QUALYS_WORKER_VULN1=123456789
QUALYS_WORKER_VULN2=987654321

# Option Profile
QUALYS_SCAN_PROFILE_ID=111111

# API
QUALYS_API_BASE=https://<API do qualys>/qps/rest/3.0

# Dashboard
QUALYS_WEB_HOST=0.0.0.0
QUALYS_WEB_PORT=8080
```

## Uso

```bash
# Carregar variáveis do arquivo .env (se aplicável)
export $(grep -v '^#' .env | xargs)

python main.py
```

Acesse o dashboard em `http://<host>:8080`, autentique com suas credenciais Qualys e informe as URLs a serem escaneadas.

Os reports PDF e CSV são salvos automaticamente em `reports/` ao término de cada scan.

> O sistema valida a configuração na inicialização e exibe um erro claro se nenhum worker estiver definido.

## Segurança

- Proteção contra **SSRF**: IPs internos/reservados são bloqueados no `port_checker`
- Proteção contra **path traversal**: nomes de arquivo são sanitizados antes de salvar
- **Rate limiting** por IP nas rotas do dashboard
- **CSRF token** em todas as ações de escrita
- Validação de entrada em todos os endpoints da API web
- Limite de 1 MB por request body e 500 URLs por requisição
- Dados sensíveis (credenciais, IDs) exclusivamente via variáveis de ambiente
