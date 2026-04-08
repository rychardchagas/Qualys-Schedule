"""
Servidor web para o dashboard de monitoramento.
Usa apenas a stdlib do Python (http.server + threading).
Serve o dashboard HTML e expoe API JSON para atualizacoes em tempo real.
Inclui headers de seguranca, validacao de entrada, limites de request,
autenticacao por endpoint, rate limiting e protecao CSRF.
"""
import hashlib
import json
import os
import re
import secrets
import threading
import time
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

from core.shared_state import dashboard

DASHBOARD_HTML_PATH = os.path.join(os.path.dirname(__file__), "dashboard.html")
HISTORICO_HTML_PATH = os.path.join(os.path.dirname(__file__), "historico.html")
VULNS_HTML_PATH = os.path.join(os.path.dirname(__file__), "vulns.html")
REPORTS_HTML_PATH = os.path.join(os.path.dirname(__file__), "reports.html")

# --- Limites de seguranca ---
MAX_REQUEST_BODY = 1_048_576   # 1 MB max para body de requests
MAX_URL_COUNT = 500            # Max URLs por request
MAX_URL_LENGTH = 2048          # Max caracteres por URL

# Referencia global ao QualysService (definida pelo main apos setup)
_qualys_service = None
_qualys_service_lock = threading.Lock()

# --- Rate Limiting ---
# Limita requisicoes por IP para prevenir brute-force e DoS
_rate_limit_lock = threading.Lock()
_rate_limit_requests: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT_WINDOW = 60          # Janela de tempo em segundos
RATE_LIMIT_MAX_REQUESTS = 120   # Max requests por IP dentro da janela
RATE_LIMIT_AUTH_WINDOW = 60     # Janela para tentativas de auth
RATE_LIMIT_AUTH_MAX = 5         # Max tentativas de auth por IP
_rate_limit_auth: dict[str, list[float]] = defaultdict(list)

# --- CSRF Token ---
_csrf_token: str = secrets.token_hex(32)
_csrf_token_lock = threading.Lock()


def _get_csrf_token() -> str:
    """Retorna o token CSRF atual."""
    with _csrf_token_lock:
        return _csrf_token


def _check_rate_limit(client_ip: str) -> bool:
    """Verifica rate limit geral. Retorna True se permitido, False se excedeu."""
    now = time.monotonic()
    with _rate_limit_lock:
        reqs = _rate_limit_requests[client_ip]
        # Limpar entradas antigas
        _rate_limit_requests[client_ip] = [t for t in reqs if now - t < RATE_LIMIT_WINDOW]
        if len(_rate_limit_requests[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
            return False
        _rate_limit_requests[client_ip].append(now)
        return True


def _check_auth_rate_limit(client_ip: str) -> bool:
    """Verifica rate limit de autenticacao. Retorna True se permitido."""
    now = time.monotonic()
    with _rate_limit_lock:
        reqs = _rate_limit_auth[client_ip]
        _rate_limit_auth[client_ip] = [t for t in reqs if now - t < RATE_LIMIT_AUTH_WINDOW]
        if len(_rate_limit_auth[client_ip]) >= RATE_LIMIT_AUTH_MAX:
            return False
        _rate_limit_auth[client_ip].append(now)
        return True


def set_qualys_service(service) -> None:
    """Define a referencia ao QualysService para uso nos endpoints de report."""
    global _qualys_service
    with _qualys_service_lock:
        _qualys_service = service


def get_qualys_service():
    with _qualys_service_lock:
        return _qualys_service


def _is_valid_numeric_id(value: str) -> bool:
    """Valida que o valor contem apenas digitos (previne path traversal/injection)."""
    return bool(re.match(r"^\d+$", value))


_SAFE_FILENAME_RE = re.compile(r'[^a-zA-Z0-9._\- ]')


def _sanitize_filename(name: str) -> str:
    """Remove caracteres perigosos de nomes de arquivo."""
    return _SAFE_FILENAME_RE.sub('_', name).replace('..', '_').strip('. ') or 'unnamed'


def _build_report_filename(scan_target: str) -> str:
    """Gera nome do arquivo a partir do scan target: 'url porta.pdf'."""
    if not scan_target:
        return "report.pdf"
    target = scan_target.strip()
    # Formato: YYYYMMDD dns port
    parts = target.split()
    if len(parts) >= 3 and re.match(r"^\d{8}$", parts[0]):
        url, port = parts[1], parts[-1]
        name = f"{url} {port}"
    elif len(parts) == 2 and re.match(r"^\d{8}$", parts[0]):
        name = parts[1]
    else:
        # URL com protocolo
        clean = re.sub(r"^https?://", "", target).split("/")[0]
        port_match = re.search(r":(\d+)$", clean)
        if port_match:
            name = clean.replace(f":{port_match.group(1)}", "") + f" {port_match.group(1)}"
        else:
            name = clean
    return f"{_sanitize_filename(name)}.pdf"


class DashboardHandler(BaseHTTPRequestHandler):
    """Handler HTTP para o dashboard com autenticacao, rate limiting e CSRF."""

    def _get_client_ip(self) -> str:
        """Extrai IP do cliente (suporta X-Forwarded-For para reverse proxy)."""
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            # Pegar primeiro IP (cliente real) e validar formato basico
            ip = forwarded.split(",")[0].strip()
            if re.match(r"^[\d.:a-fA-F]+$", ip):
                return ip
        return self.client_address[0]

    def _is_authenticated(self) -> bool:
        """Verifica se o usuario esta autenticado (fase != auth)."""
        return dashboard.phase != dashboard.PHASE_AUTH

    def _require_auth(self) -> bool:
        """Verifica autenticacao. Retorna True se OK, False se bloqueou."""
        if not self._is_authenticated():
            self._send_json(401, {"ok": False, "error": "Autenticacao necessaria"})
            return False
        return True

    def _require_csrf(self) -> bool:
        """Valida token CSRF no header. Retorna True se OK, False se bloqueou."""
        token = self.headers.get("X-CSRF-Token", "")
        if not token or not secrets.compare_digest(token, _get_csrf_token()):
            self._send_json(403, {"ok": False, "error": "Token CSRF invalido"})
            return False
        return True

    def do_GET(self):
        # Rate limiting
        if not _check_rate_limit(self._get_client_ip()):
            self._send_json(429, {"ok": False, "error": "Muitas requisicoes. Tente novamente em breve."})
            return

        if self.path == "/" or self.path == "/index.html":
            self._serve_html_file(DASHBOARD_HTML_PATH)
        elif self.path in ("/historico.html", "/historico"):
            self._serve_html_file(HISTORICO_HTML_PATH)
        elif self.path in ("/resultados.html", "/resultados"):
            self.send_response(302)
            self.send_header("Location", "/")
            self._send_security_headers()
            self.end_headers()
        elif self.path in ("/vulns.html", "/vulns"):
            self._serve_html_file(VULNS_HTML_PATH)
        elif self.path in ("/reports.html", "/reports"):
            self._serve_html_file(REPORTS_HTML_PATH)
        elif self.path == "/api/csrf-token":
            self._serve_csrf_token()
        elif self.path == "/api/files/list":
            if self._require_auth():
                self._handle_files_list()
        elif self.path.startswith("/api/files/download/"):
            if self._require_auth():
                self._handle_files_download()
        elif self.path == "/api/state":
            self._serve_state()
        elif self.path == "/api/export/csv":
            if self._require_auth():
                self._serve_export_csv()
        elif self.path.startswith("/api/search/worker"):
            if self._require_auth():
                self._handle_search_worker()
        elif self.path.startswith("/api/report/status/"):
            if self._require_auth():
                self._handle_report_status()
        elif self.path.startswith("/api/report/download/"):
            if self._require_auth():
                self._handle_report_pdf_download()
        elif self.path.startswith("/api/report/generate/"):
            if self._require_auth():
                self._handle_report_generate()
        elif self.path.startswith("/api/vulns/scan/"):
            if self._require_auth():
                self._handle_vulns_scan_lookup()
        else:
            self.send_response(404)
            self._send_security_headers()
            self.end_headers()

    def do_POST(self):
        # Rate limiting
        if not _check_rate_limit(self._get_client_ip()):
            self._send_json(429, {"ok": False, "error": "Muitas requisicoes. Tente novamente em breve."})
            return

        if self.path == "/api/auth":
            self._handle_auth()
        elif self.path == "/api/start":
            if self._require_auth() and self._require_csrf():
                self._handle_start()
        elif self.path == "/api/add-urls":
            if self._require_auth() and self._require_csrf():
                self._handle_add_urls()
        elif self.path == "/api/restart":
            if self._require_auth() and self._require_csrf():
                self._handle_restart()
        elif self.path == "/api/force-rescan":
            if self._require_auth() and self._require_csrf():
                self._handle_force_rescan()
        elif self.path.startswith("/api/report/create/"):
            if self._require_auth() and self._require_csrf():
                self._handle_report_create()
        elif self.path == "/api/vulns/load-history":
            if self._require_auth() and self._require_csrf():
                self._handle_vulns_load_history()
        else:
            self.send_response(404)
            self._send_security_headers()
            self.end_headers()

    # Rejeitar metodos nao suportados
    def do_PUT(self):
        self._method_not_allowed()

    def do_DELETE(self):
        self._method_not_allowed()

    def do_PATCH(self):
        self._method_not_allowed()

    def _method_not_allowed(self):
        self.send_response(405)
        self._send_security_headers()
        self.end_headers()

    def _read_json_body(self, max_size: int = MAX_REQUEST_BODY) -> dict | None:
        """Le e parseia body JSON com limite de tamanho. Retorna None se invalido."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > max_size:
            self._send_json(413, {"ok": False, "error": "Request body muito grande"})
            return None
        if content_length == 0:
            return {}
        try:
            body = self.rfile.read(content_length).decode("utf-8")
            return json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"ok": False, "error": "JSON invalido"})
            return None

    def _serve_csrf_token(self):
        """GET /api/csrf-token → retorna token CSRF para uso em requests POST."""
        self._send_json(200, {"ok": True, "token": _get_csrf_token()})

    def _handle_auth(self):
        # Rate limit especifico para auth (anti brute-force)
        client_ip = self._get_client_ip()
        if not _check_auth_rate_limit(client_ip):
            dashboard.log(f"  [Security] Rate limit auth excedido para IP {client_ip}")
            self._send_json(429, {"ok": False, "error": "Muitas tentativas de login. Aguarde 60 segundos."})
            return
        data = self._read_json_body()
        if data is None:
            return
        username = str(data.get("username", "")).strip()[:256]
        password = str(data.get("password", "")).strip()[:256]
        token = str(data.get("token", "")).strip()[:512]
        ok = dashboard.authenticate(username, password, token)
        if ok:
            dashboard.log(f"  [Security] Autenticacao bem-sucedida de {client_ip}")
        else:
            dashboard.log(f"  [Security] Falha de autenticacao de {client_ip}")
        self._send_json(200 if ok else 400, {"ok": ok})

    def _handle_start(self):
        data = self._read_json_body()
        if data is None:
            return
        raw_urls = data.get("urls", [])
        if not isinstance(raw_urls, list):
            self._send_json(400, {"ok": False, "error": "urls deve ser uma lista"})
            return
        # Sanitizar e limitar URLs
        urls = []
        for u in raw_urls[:MAX_URL_COUNT]:
            if isinstance(u, str):
                cleaned = u.strip()[:MAX_URL_LENGTH]
                if cleaned:
                    urls.append(cleaned)
        ok = dashboard.trigger_start(urls)
        self._send_json(200 if ok else 409, {"ok": ok})

    def _handle_add_urls(self):
        """Endpoint para adicionar URLs durante a execucao."""
        data = self._read_json_body()
        if data is None:
            return
        raw_urls = data.get("urls", [])
        if not isinstance(raw_urls, list) or not raw_urls:
            self._send_json(400, {"ok": False, "error": "Nenhuma URL informada"})
            return
        # Sanitizar e limitar
        urls = []
        for u in raw_urls[:MAX_URL_COUNT]:
            if isinstance(u, str):
                cleaned = u.strip()[:MAX_URL_LENGTH]
                if cleaned:
                    urls.append(cleaned)
        if not urls:
            self._send_json(400, {"ok": False, "error": "Nenhuma URL valida"})
            return
        count, error_msg = dashboard.add_additional_urls(urls)
        if count == 0:
            self._send_json(409, {"ok": False, "error": error_msg or "Nao e possivel adicionar URLs"})
            return
        self._send_json(200, {"ok": True, "added": count})

    def _extract_path_id(self, position: int = 4) -> str | None:
        """Extrai e valida um ID numerico do path na posicao indicada."""
        parts = self.path.split("/")
        if len(parts) <= position:
            self._send_json(400, {"ok": False, "error": "ID obrigatorio na URL"})
            return None
        id_val = parts[position].split("?")[0]
        if not _is_valid_numeric_id(id_val):
            self._send_json(400, {"ok": False, "error": "ID invalido (deve ser numerico)"})
            return None
        return id_val

    def _handle_report_create(self):
        """POST /api/report/create/{scan_id} → cria report, retorna report_id."""
        scan_id = self._extract_path_id(4)
        if not scan_id:
            return

        # Ler scan_target e format do body (opcionais)
        data = self._read_json_body()
        if data is None:
            return  # _read_json_body ja enviou resposta de erro
        scan_target = ""
        if isinstance(data.get("scan_target"), str):
            scan_target = data["scan_target"].strip()[:256]
        report_format = "PDF"
        if isinstance(data.get("format"), str) and data["format"].upper() in ("PDF", "CSV"):
            report_format = data["format"].upper()

        svc = get_qualys_service()
        if not svc:
            self._send_json(503, {"ok": False, "error": "Servico Qualys nao disponivel"})
            return

        try:
            report_id = svc.create_report(scan_id, scan_target=scan_target,
                                          report_format=report_format)
        except ValueError as e:
            self._send_json(400, {"ok": False, "error": str(e)})
            return
        except Exception as e:
            dashboard.log(f"  [Security] Erro ao criar report scan_id={scan_id}: {e}")
            self._send_json(500, {"ok": False, "error": "Erro interno ao criar report"})
            return

        self._send_json(200, {"ok": True, "report_id": report_id})

    def _handle_report_status(self):
        """GET /api/report/status/{report_id} → retorna status do report."""
        report_id = self._extract_path_id(4)
        if not report_id:
            return

        svc = get_qualys_service()
        if not svc:
            self._send_json(503, {"ok": False, "error": "Servico Qualys nao disponivel"})
            return

        try:
            status = svc.get_report_status(report_id)
        except ValueError as e:
            self._send_json(400, {"ok": False, "error": str(e)})
            return
        except Exception as e:
            dashboard.log(f"  [Security] Erro ao verificar status report_id={report_id}: {e}")
            self._send_json(500, {"ok": False, "error": "Erro interno ao verificar status"})
            return

        if not status:
            self._send_json(500, {"ok": False, "error": "Falha ao verificar status"})
            return

        self._send_json(200, {"ok": True, "report_id": report_id, "status": status})

    def _handle_report_pdf_download(self):
        """GET /api/report/download/{report_id} → retorna PDF bytes."""
        report_id = self._extract_path_id(4)
        if not report_id:
            return

        svc = get_qualys_service()
        if not svc:
            self._send_json(503, {"ok": False, "error": "Servico Qualys nao disponivel"})
            return

        try:
            content = svc.download_report(report_id)
        except ValueError as e:
            self._send_json(400, {"ok": False, "error": str(e)})
            return
        except Exception as e:
            dashboard.log(f"  [Security] Erro ao baixar report_id={report_id}: {e}")
            self._send_json(500, {"ok": False, "error": "Erro interno ao baixar report"})
            return

        if not content:
            self._send_json(500, {"ok": False, "error": "Falha ao baixar PDF"})
            return

        filename = f"report_{_sanitize_filename(report_id)}.pdf"
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(content)))
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(content)

    def _handle_report_generate(self):
        """GET /api/report/generate/{scan_id}?target=...&format=PDF|CSV → fluxo completo."""
        scan_id = self._extract_path_id(4)
        if not scan_id:
            return

        svc = get_qualys_service()
        if not svc:
            self._send_json(503, {"ok": False, "error": "Servico Qualys nao disponivel"})
            return

        # Parametros via query string
        scan_target = ""
        report_format = "PDF"
        if "?" in self.path:
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(self.path).query)
            scan_target = qs.get("target", [""])[0][:256]
            fmt_qs = qs.get("format", ["PDF"])[0].upper()
            if fmt_qs in ("PDF", "CSV"):
                report_format = fmt_qs

        try:
            result = svc.generate_full_report(scan_id, scan_target=scan_target,
                                              report_format=report_format)
        except ValueError as e:
            self._send_json(400, {"ok": False, "error": str(e)})
            return
        except RuntimeError as e:
            dashboard.log(f"  [Security] Erro ao gerar report scan_id={scan_id}: {e}")
            self._send_json(500, {"ok": False, "error": "Erro interno ao gerar report"})
            return
        except Exception as e:
            dashboard.log(f"  [Security] Erro inesperado report scan_id={scan_id}: {e}")
            self._send_json(500, {"ok": False, "error": "Erro interno ao gerar report"})
            return

        content = result["content"]
        report_id = result["report_id"]
        fmt = result["format"]
        base_name = _build_report_filename(scan_target)

        if fmt == "CSV":
            filename = base_name.replace(".pdf", ".csv")
            content_type = "text/csv; charset=utf-8"
        else:
            filename = base_name
            content_type = "application/pdf"

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Report-Id", report_id)
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(content)

    def _handle_search_worker(self):
        """GET /api/search/worker?url=... → pesquisa qual worker rodou a URL."""
        from urllib.parse import parse_qs, urlparse
        qs = parse_qs(urlparse(self.path).query)
        query = qs.get("url", [""])[0].strip()[:MAX_URL_LENGTH]
        if not query:
            self._send_json(400, {"ok": False, "error": "Parametro 'url' obrigatorio"})
            return
        results = dashboard.search_by_url(query)
        self._send_json(200, {"ok": True, "query": query, "results": results, "count": len(results)})

    def _serve_export_csv(self):
        """Serve o export CSV dos resultados."""
        csv_content = dashboard.export_csv
        if not csv_content:
            self._send_json(404, {"ok": False, "error": "Export nao disponivel"})
            return

        encoded = csv_content.encode("utf-8-sig")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="qualys_scan_results.csv"')
        self.send_header("Content-Length", str(len(encoded)))
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(encoded)

    def _serve_html_file(self, filepath: str):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
        except FileNotFoundError:
            self.send_response(404)
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(b"Page not found")

    def _send_security_headers(self):
        """Adiciona headers de seguranca a todas as respostas."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "form-action 'self'; base-uri 'self'; object-src 'none'",
        )
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        self.send_header("X-Permitted-Cross-Domain-Policies", "none")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")

    def _serve_state(self):
        state = dashboard.get_state()
        payload = json.dumps(state, ensure_ascii=False)
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(payload.encode("utf-8"))

    def _handle_force_rescan(self):
        """Endpoint para marcar URLs para re-scan forcado (ignora validacao mensal)."""
        data = self._read_json_body()
        if data is None:
            return
        raw_urls = data.get("urls", [])
        if not isinstance(raw_urls, list) or not raw_urls:
            self._send_json(400, {"ok": False, "error": "Nenhuma URL informada"})
            return
        urls = []
        for u in raw_urls[:MAX_URL_COUNT]:
            if isinstance(u, str):
                cleaned = u.strip()[:MAX_URL_LENGTH]
                if cleaned:
                    urls.append(cleaned)
        if not urls:
            self._send_json(400, {"ok": False, "error": "Nenhuma URL valida"})
            return

        current_phase = dashboard.phase
        dashboard.log(f"  [Re-scan] Solicitacao recebida: {len(urls)} URL(s) | Fase atual: {current_phase}")
        for u in urls:
            dashboard.log(f"  [Re-scan] URL: {u}")

        # 1. Marcar URLs para bypass da validacao mensal
        count, error_msg = dashboard.add_force_rescan_urls(urls)
        if count == 0:
            dashboard.log(f"  [Re-scan] ERRO ao marcar URLs: {error_msg}")
            self._send_json(409, {"ok": False, "error": error_msg or "Nao foi possivel marcar URLs"})
            return
        dashboard.log(f"  [Re-scan] {count} URL(s) marcadas para re-scan forcado")

        # 2. Adicionar URLs a fila de processamento
        added, add_error = dashboard.add_additional_urls(urls, force=True)
        dashboard.log(f"  [Re-scan] {added} URL(s) adicionadas a fila"
                      + (f" ({add_error})" if add_error else ""))

        # 3. Auto-restart se o ciclo ja finalizou
        auto_restarted = False
        if current_phase == dashboard.PHASE_FINISHED:
            dashboard.log("  [Re-scan] Fase FINISHED detectada - iniciando auto-restart...")
            restarted = dashboard.restart()
            if restarted:
                dashboard.log(f"  [Re-scan] Restart OK | input_urls: {len(dashboard.input_urls)} URL(s)")
                started = dashboard.trigger_start()
                if started:
                    auto_restarted = True
                    dashboard.log("  [Re-scan] Novo ciclo iniciado automaticamente!")
                else:
                    dashboard.log("  [Re-scan] ERRO: trigger_start falhou (input_urls vazio?)")
            else:
                dashboard.log("  [Re-scan] ERRO: restart falhou (fase ja mudou?)")
        elif current_phase == dashboard.PHASE_RUNNING:
            dashboard.log("  [Re-scan] Ciclo em execucao - URLs serao processadas na proxima iteracao")
        else:
            dashboard.log(f"  [Re-scan] Fase {current_phase} - URLs aguardando proximo ciclo")

        self._send_json(200, {
            "ok": True, "force_marked": count, "queued": added,
            "auto_restarted": auto_restarted,
        })

    def _handle_vulns_scan_lookup(self):
        """GET /api/vulns/scan/{scan_id} → consulta vulns de um scan especifico via API."""
        scan_id = self._extract_path_id(4)
        if not scan_id:
            return

        svc = get_qualys_service()
        if not svc:
            self._send_json(503, {"ok": False, "error": "Servico Qualys nao disponivel"})
            return

        try:
            findings = svc.get_scan_vulns_summary(scan_id)
        except Exception as e:
            dashboard.log(f"  [Security] Erro ao consultar vulns scan_id={scan_id}: {e}")
            self._send_json(500, {"ok": False, "error": "Erro interno ao consultar vulnerabilidades"})
            return

        if findings is None:
            self._send_json(404, {"ok": False, "error": "Scan nao encontrado ou sem dados"})
            return

        findings.pop("status", None)
        self._send_json(200, {"ok": True, "scan_id": scan_id, "findings": findings})

    def _handle_vulns_load_history(self):
        """POST /api/vulns/load-history → carrega vulns de scans antigos (12 meses) em background."""
        import threading

        svc = get_qualys_service()
        if not svc:
            self._send_json(503, {"ok": False, "error": "Servico Qualys nao disponivel"})
            return

        state = dashboard.get_state()
        all_history = state.get("api", {}).get("scans_all_history", [])
        month_start = state.get("api", {}).get("month_ref", "")

        # Filtrar scans que NAO sao do mes atual (os do mes atual ja foram carregados)
        older_scans = []
        for scan in all_history:
            launched = scan.get("launched", scan.get("launchedDate", ""))
            if month_start and launched >= month_start:
                continue  # Ja carregado
            older_scans.append(scan)

        if not older_scans:
            self._send_json(200, {"ok": True, "message": "Nenhum scan anterior ao mes atual", "count": 0})
            return

        dashboard.log(f"  [Vulns] Carga sob demanda solicitada: {len(older_scans)} scan(s) anteriores ao mes atual")

        def _load_older():
            from concurrent.futures import ThreadPoolExecutor
            loaded = 0
            errors = 0
            max_workers = min(8, len(older_scans))

            def _fetch(scan):
                scan_name = scan.get("name", "")
                sid = str(scan.get("id", ""))
                if not scan_name or not sid:
                    return None
                finding_details = []
                # Download completo (counts + detalhes vulns/igs)
                full_result = svc.get_scan_findings_full(sid)
                if full_result:
                    findings = full_result["findings"]
                    finding_details = full_result.get("finding_details", [])
                else:
                    # Fallback: summary-only
                    findings = svc.get_scan_vulns_summary(sid)
                    if findings is None:
                        return None
                    findings.pop("status", None)
                parts = scan_name.split()
                url = ""
                port = None
                if len(parts) >= 2:
                    dns = parts[1]
                    port = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 443
                    url = f"https://{dns}:{port}" if port else f"https://{dns}"
                launched = scan.get("launched", "")
                return {
                    "scan_label": scan_name, "url": url,
                    "worker": scan.get("worker", ""), "worker_id": None,
                    "scan_id": sid, "port": port,
                    "finished_date": launched[:10] if len(launched) >= 10 else "",
                    "finished_at": launched[11:19] if len(launched) >= 19 else "",
                    "findings": findings, "finding_details": finding_details,
                    "source": "historico",
                }

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_fetch, s): s for s in older_scans}
                for future in futures:
                    try:
                        entry = future.result()
                        if entry:
                            dashboard.add_vulns_entry(entry)
                            loaded += 1
                            if loaded % 10 == 0:
                                dashboard.log(f"  [Vulns-Historico] Progresso: {loaded}/{len(older_scans)} scan(s)...")
                        else:
                            errors += 1
                    except Exception:
                        errors += 1

            dashboard.log(f"  [Vulns-Historico] Concluido: {loaded} carregados | {errors} erro(s) | total na aba: {len(dashboard.vulns_data)}")

        thread = threading.Thread(target=_load_older, daemon=True, name="vulns-history-ondemand")
        thread.start()

        self._send_json(200, {
            "ok": True,
            "message": f"Carga de {len(older_scans)} scan(s) antigos iniciada em background",
            "count": len(older_scans),
        })

    def _handle_files_list(self):
        """GET /api/files/list → lista arquivos PDF e CSV no diretorio de reports."""
        from config.settings import REPORT_OUTPUT_DIR
        if not os.path.isdir(REPORT_OUTPUT_DIR):
            self._send_json(200, {"ok": True, "files": []})
            return
        files = []
        for name in os.listdir(REPORT_OUTPUT_DIR):
            ext = os.path.splitext(name)[1].lower()
            if ext not in (".pdf", ".csv"):
                continue
            filepath = os.path.join(REPORT_OUTPUT_DIR, name)
            if not os.path.isfile(filepath):
                continue
            stat = os.stat(filepath)
            files.append({
                "name": name,
                "size": stat.st_size,
                "modified": stat.st_mtime,
                "type": ext[1:],
            })
        files.sort(key=lambda f: f["modified"], reverse=True)
        self._send_json(200, {"ok": True, "files": files})

    def _handle_files_download(self):
        """GET /api/files/download/{filename} → serve arquivo do diretorio de reports."""
        from config.settings import REPORT_OUTPUT_DIR
        from urllib.parse import unquote
        # Extrair filename do path: /api/files/download/nome do arquivo.pdf
        prefix = "/api/files/download/"
        raw_name = unquote(self.path[len(prefix):])
        # Seguranca: bloquear path traversal
        if not raw_name or ".." in raw_name or "/" in raw_name or "\\" in raw_name:
            self._send_json(400, {"ok": False, "error": "Nome de arquivo invalido"})
            return
        # Whitelist de extensoes permitidas
        ext_check = os.path.splitext(raw_name)[1].lower()
        if ext_check not in (".pdf", ".csv"):
            self._send_json(400, {"ok": False, "error": "Tipo de arquivo nao permitido"})
            return
        filepath = os.path.join(REPORT_OUTPUT_DIR, raw_name)
        real_report_dir = os.path.realpath(REPORT_OUTPUT_DIR)
        real_filepath = os.path.realpath(filepath)
        if not real_filepath.startswith(real_report_dir + os.sep) and real_filepath != real_report_dir:
            self._send_json(403, {"ok": False, "error": "Acesso negado"})
            return
        if not os.path.isfile(real_filepath):
            self._send_json(404, {"ok": False, "error": "Arquivo nao encontrado"})
            return
        ext = os.path.splitext(raw_name)[1].lower()
        content_type = "application/pdf" if ext == ".pdf" else "text/csv; charset=utf-8"
        safe_name = _sanitize_filename(os.path.splitext(raw_name)[0]) + ext
        try:
            with open(real_filepath, "rb") as f:
                content = f.read()
        except OSError:
            self._send_json(500, {"ok": False, "error": "Erro ao ler arquivo"})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
        self.send_header("Content-Length", str(len(content)))
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(content)

    def _handle_restart(self):
        """Reinicia a rotina (volta para fase ready mantendo credenciais)."""
        ok = dashboard.restart()
        self._send_json(200 if ok else 409, {"ok": ok})

    def _send_json(self, status_code: int, data: dict) -> None:
        """Helper para enviar resposta JSON."""
        payload = json.dumps(data, ensure_ascii=False)
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(payload.encode("utf-8"))

    def log_message(self, format, *args):
        """Suprime logs do http.server para nao poluir o console."""
        pass


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """HTTPServer com suporte a multiplas threads simultaneas."""
    daemon_threads = True


def start_dashboard_server(port: int = 8080, host: str = None) -> ThreadedHTTPServer:
    """Inicia o servidor do dashboard em uma thread daemon."""
    from config.settings import WEB_HOST
    bind_host = host or WEB_HOST
    server = ThreadedHTTPServer((bind_host, port), DashboardHandler)
    print(f"  Dashboard: http://{bind_host}:{port}", flush=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
