"""
Configuracoes centralizadas do projeto.
Todos os valores sao lidos de variaveis de ambiente — nenhum dado sensivel
ou especifico de ambiente deve ser hardcoded aqui.

Workers (WebApps Qualys WAS)
-----------------------------
Defina uma variavel de ambiente por worker, usando o prefixo QUALYS_WORKER_:

    QUALYS_WORKER_VULN1=123456789
    QUALYS_WORKER_VULN2=987654321

O sufixo apos QUALYS_WORKER_ vira o nome do worker exibido no dashboard.
Qualquer quantidade de workers e suportada — basta adicionar mais variaveis.

Option Profile
--------------
    QUALYS_SCAN_PROFILE_ID=111111
"""
import os

# --- Diretorios ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# --- Orquestracao de Scans ---
SCAN_CHECK_INTERVAL = int(os.environ.get("QUALYS_SCAN_INTERVAL", "300"))
SCAN_PROFILE_ID = os.environ.get("QUALYS_SCAN_PROFILE_ID", "")

# --- Dashboard Web ---
WEB_HOST = os.environ.get("QUALYS_WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.environ.get("QUALYS_WEB_PORT", "8080"))

# --- Qualys API ---
QUALYS_API_BASE = os.environ.get(
    "QUALYS_API_BASE",
    "https://<API do qualys>/qps/rest/3.0",
)
QUALYS_API_URL = f"{QUALYS_API_BASE}/search/was/webapp"
QUALYS_MAX_RETRIES = 3
QUALYS_RETRY_DELAY = 5
QUALYS_TIMEOUT = 45
QUALYS_RESULTS_LIMIT = 100
QUALYS_MAX_CONCURRENT = int(os.environ.get("QUALYS_MAX_CONCURRENT", "3"))
QUALYS_RETRY_STATUSES = {401, 429, 503}

# --- Workers (WebApps de Scan) ---
# Carregados dinamicamente de variaveis de ambiente com prefixo QUALYS_WORKER_.
# Formato: QUALYS_WORKER_<NOME>=<ID numerico>
# Exemplo: QUALYS_WORKER_VULN1=123456789
_WORKER_PREFIX = "QUALYS_WORKER_"

QUALYS_SCAN_WEBAPPS: dict[str, int] = {}
for _key, _val in os.environ.items():
    if _key.startswith(_WORKER_PREFIX):
        _name = _key[len(_WORKER_PREFIX):]
        try:
            QUALYS_SCAN_WEBAPPS[_name] = int(_val)
        except ValueError:
            raise ValueError(
                f"Variavel de ambiente {_key} deve conter um ID numerico, "
                f"mas recebeu: {_val!r}"
            )

QUALYS_HEADERS = {
    "Content-Type": "text/xml; charset=utf-8",
    "Accept": "application/xml, text/xml, */*",
    "X-Requested-With": "XMLHttpRequest",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
}

# --- Qualys Report (usa WAS API /qps/rest/3.0/) ---
QUALYS_REPORT_POLL_INTERVAL = 5    # segundos entre verificacoes de status
QUALYS_REPORT_MAX_ATTEMPTS = 60    # 60 x 5s = 5 min max
REPORT_OUTPUT_DIR = os.path.join(BASE_DIR, "reports")

# --- Report Retry ---
REPORT_DOWNLOAD_MAX_RETRIES = 3                    # tentativas por formato (PDF/CSV)
REPORT_DOWNLOAD_RETRY_BACKOFF = [300, 300, 300]    # 5 min entre cada retry

# --- Logs ---
LOG_OUTPUT_DIR = os.path.join(BASE_DIR, "logs")

# --- Validacao de Portas ---
PORTS_TO_CHECK = [443, 80]
