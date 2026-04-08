"""
Estado compartilhado entre o processo principal e o dashboard web.
Thread-safe para acesso concorrente.
Credenciais nunca sao expostas via API ou logs.
"""
import re
import threading
from datetime import datetime

# Limite de URLs para prevenir abuso de memoria
MAX_URLS = 1000
MAX_URL_LENGTH = 2048
MAX_LOG_ENTRIES = 1000


class DashboardState:
    """Gerencia o estado global do dashboard em tempo real."""

    # Fases do ciclo de vida: auth -> ready -> setup -> running -> finished
    PHASE_AUTH = "auth"        # Aguardando autenticacao
    PHASE_READY = "ready"      # Aguardando usuario informar URLs e Iniciar
    PHASE_SETUP = "setup"      # Executando verificacoes
    PHASE_RUNNING = "running"  # Orquestrando scans
    PHASE_FINISHED = "finished"

    def __init__(self):
        self._lock = threading.Lock()
        self._auth_event = threading.Event()
        self._start_event = threading.Event()
        self.phase: str = self.PHASE_AUTH
        self.auth_credentials: dict = {}        # {"username": ..., "password": ..., "token": ...}
        self.input_urls: list[str] = []         # URLs informadas pelo usuario via dashboard
        self.urls_total: list[str] = []
        self._urls_total_set: set[str] = set()  # O(1) lookup
        self.urls_scanning: dict[str, str] = {}  # worker_name -> url
        self.urls_completed: list[dict] = []  # [{"url": ..., "worker": ..., "port": ..., "finished_at": ...}]
        self.urls_skipped: list[dict] = []   # [{"url": ..., "reason": ...}]
        self.urls_pending: list[str] = []
        self._urls_pending_set: set[str] = set()  # O(1) lookup
        self.logs: list[dict] = []
        self.started_at: str | None = None
        self.workers: dict[str, dict] = {}  # worker_name -> {"status": ..., "url": ...}
        # Dados da API Qualys (populados no setup)
        self.api_webapps: list[dict] = []       # [{"name": ..., "id": ..., "url": ...}]
        self.api_profiles: list[dict] = []      # [{"id": ..., "name": ...}]
        self.api_scanned_month: list[str] = []  # URLs ja escaneadas no mes via API
        self.api_scans_detail: list[dict] = []  # Detalhes dos scans finalizados (mes atual)
        self.api_scans_all_history: list[dict] = []  # Todos os scans dos ultimos 12 meses
        self.month_ref: str = ""
        # URLs adicionais (adicionadas durante execucao)
        self._additional_urls: list[str] = []
        # Reports downloads (PDF/CSV gerados automaticamente)
        self.reports_downloads: list[dict] = []
        # Export CSV dos resultados
        self.export_csv: str = ""
        # Force re-scan: URLs que devem ignorar validacao mensal
        self._force_rescan_urls: set[str] = set()
        # Resultado da validacao pos-loop de reports
        self.report_validation: dict = {}
        # Dados de vulnerabilidades por scan (populado pelo generate_export_csv)
        self.vulns_data: list[dict] = []

    def set_phase(self, phase: str) -> None:
        with self._lock:
            self.phase = phase

    def authenticate(self, username: str, password: str, token: str) -> bool:
        """Chamado pelo endpoint /api/auth. Armazena credenciais e transiciona para READY."""
        with self._lock:
            if self.phase != self.PHASE_AUTH:
                return False
            # Validacao basica de credenciais
            username = str(username).strip()[:256]
            password = str(password).strip()[:256]
            token = str(token).strip()[:512]
            if not username or not password:
                return False
            self.auth_credentials = {
                "username": username,
                "password": password,
                "token": token,
            }
            self.phase = self.PHASE_READY
        self._auth_event.set()
        return True

    def wait_for_auth(self) -> None:
        """Bloqueia a thread principal ate o usuario se autenticar no dashboard."""
        self._auth_event.wait()

    def trigger_start(self, urls: list[str] | None = None) -> bool:
        """Chamado pelo endpoint /api/start. Recebe URLs, transiciona para SETUP e libera main."""
        with self._lock:
            if self.phase != self.PHASE_READY:
                return False
            if urls:
                self.input_urls = list(urls)
            if not self.input_urls:
                return False
            self.phase = self.PHASE_SETUP
            self.started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._start_event.set()
        return True

    def log(self, message: str) -> None:
        """Adiciona uma mensagem ao log e imprime no console. Nao loga credenciais."""
        # Sanitizar: nunca logar senhas ou tokens
        safe_msg = re.sub(r'(password|senha|token|secret)[=:]\s*\S+', r'\1=***', message, flags=re.IGNORECASE)
        print(safe_msg)
        with self._lock:
            self.logs.append({
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "message": safe_msg,
            })
            if len(self.logs) > MAX_LOG_ENTRIES:
                self.logs = self.logs[-MAX_LOG_ENTRIES:]

    def set_total_urls(self, urls: list[str]) -> None:
        with self._lock:
            self.urls_total = list(urls)
            self._urls_total_set = set(urls)
            self.urls_pending = list(urls)
            self._urls_pending_set = set(urls)

    def mark_scanning(self, worker: str, url: str, port: int | None = None,
                      scan_label: str = "", scan_id: str = "",
                      worker_id: int | None = None) -> None:
        with self._lock:
            self.urls_scanning[worker] = url
            self.workers[worker] = {
                "status": "scanning", "url": url, "port": port,
                "scan_label": scan_label, "scan_id": scan_id, "worker_id": worker_id,
            }
            if url in self._urls_pending_set:
                self.urls_pending.remove(url)
                self._urls_pending_set.discard(url)

    def mark_completed(self, worker: str, url: str) -> None:
        with self._lock:
            port = None
            scan_label = ""
            scan_id = ""
            worker_id = None
            if worker in self.workers:
                port = self.workers[worker].get("port")
                scan_label = self.workers[worker].get("scan_label", "")
                scan_id = self.workers[worker].get("scan_id", "")
                worker_id = self.workers[worker].get("worker_id")
            self.urls_scanning.pop(worker, None)
            self.urls_completed.append({
                "url": url,
                "worker": worker,
                "worker_id": worker_id,
                "port": port,
                "scan_label": scan_label,
                "scan_id": scan_id,
                "finished_at": datetime.now().strftime("%H:%M:%S"),
                "finished_date": datetime.now().strftime("%Y-%m-%d"),
            })
            self.workers[worker] = {"status": "available", "url": None, "port": None}

    def mark_skipped(self, url: str, reason: str, details: str = "") -> None:
        with self._lock:
            entry = {"url": url, "reason": reason}
            if details:
                entry["details"] = details
            self.urls_skipped.append(entry)
            if url in self._urls_pending_set:
                self.urls_pending.remove(url)
                self._urls_pending_set.discard(url)

    def mark_warning(self, url: str, reason: str, details: str = "") -> None:
        """Registra aviso informativo (nao remove da fila, apenas acompanhamento)."""
        with self._lock:
            entry = {"url": url, "reason": reason, "warning": True}
            if details:
                entry["details"] = details
            self.urls_skipped.append(entry)

    def mark_worker_waiting(self, worker: str, url: str) -> None:
        with self._lock:
            self.urls_scanning[worker] = url
            self.workers[worker] = {"status": "waiting", "url": url}

    def mark_worker_available(self, worker: str) -> None:
        with self._lock:
            self.urls_scanning.pop(worker, None)
            self.workers[worker] = {"status": "available", "url": None}

    def remove_from_pending(self, url: str) -> None:
        with self._lock:
            if url in self._urls_pending_set:
                self.urls_pending.remove(url)
                self._urls_pending_set.discard(url)

    def add_to_pending(self, url: str) -> None:
        """Adiciona URL a lista de pendentes (usada ao adicionar URLs em execucao)."""
        with self._lock:
            if url not in self._urls_pending_set:
                self.urls_pending.append(url)
                self._urls_pending_set.add(url)
            if url not in self._urls_total_set:
                self.urls_total.append(url)
                self._urls_total_set.add(url)

    def add_additional_urls(self, urls: list[str], force: bool = False) -> tuple[int, str]:
        """
        Adiciona URLs extras durante a execucao.
        Retorna (quantidade_adicionada, mensagem_erro).
        Se quantidade > 0, mensagem_erro eh vazia.
        Se force=True, ignora verificacao de _urls_total_set (usado por force-rescan).
        """
        with self._lock:
            if self.phase not in (self.PHASE_RUNNING, self.PHASE_SETUP, self.PHASE_READY, self.PHASE_FINISHED):
                return 0, f"Fase atual ({self.phase}) nao permite adicionar URLs"
            count = 0
            duplicates = 0
            for url in urls:
                url = url.strip()
                if not url:
                    continue
                if url in self._additional_urls:
                    duplicates += 1
                elif not force and (url in self._urls_pending_set or url in self._urls_total_set):
                    duplicates += 1
                else:
                    self._additional_urls.append(url)
                    count += 1
            if count == 0 and duplicates > 0:
                return 0, f"{duplicates} URL(s) ja estao na fila ou em processamento"
            return count, ""

    def pop_additional_urls(self) -> list[str]:
        """Retorna e limpa URLs adicionais pendentes (consumido pelo main loop)."""
        with self._lock:
            urls = list(self._additional_urls)
            self._additional_urls.clear()
            return urls

    def add_force_rescan_urls(self, urls: list[str]) -> tuple[int, str]:
        """
        Marca URLs para re-scan forcado (ignora is_scanned_this_month).
        Retorna (quantidade_marcada, mensagem_erro).
        """
        with self._lock:
            if self.phase not in (self.PHASE_RUNNING, self.PHASE_SETUP, self.PHASE_READY, self.PHASE_FINISHED):
                return 0, f"Fase atual ({self.phase}) nao permite force re-scan"
            count = 0
            for url in urls:
                normalized = url.replace("https://", "").replace("http://", "").split("/")[0].lower().strip()
                if not normalized:
                    continue
                self._force_rescan_urls.add(normalized)
                count += 1
            return count, ""

    def is_force_rescan(self, url: str) -> bool:
        """Verifica se a URL foi marcada para re-scan forcado."""
        normalized = url.replace("https://", "").replace("http://", "").split("/")[0].lower().strip()
        with self._lock:
            return normalized in self._force_rescan_urls

    def remove_force_rescan(self, url: str) -> None:
        """Remove URL do conjunto de force-rescan apos consumo."""
        normalized = url.replace("https://", "").replace("http://", "").split("/")[0].lower().strip()
        with self._lock:
            self._force_rescan_urls.discard(normalized)

    def add_report_download(self, worker: str, scan_label: str, scan_id: str,
                            fmt: str) -> int:
        """Registra inicio de download de report. Retorna indice para atualizar status."""
        with self._lock:
            idx = len(self.reports_downloads)
            self.reports_downloads.append({
                "worker": worker,
                "scan_label": scan_label,
                "scan_id": scan_id,
                "format": fmt,
                "status": "downloading",
                "size_kb": 0,
                "filename": "",
                "started_at": datetime.now().strftime("%H:%M:%S"),
                "finished_at": "",
                "retry_count": 0,
                "error_message": "",
            })
            return idx

    def update_report_download(self, idx: int, status: str,
                               filename: str = "", size_kb: float = 0,
                               retry_count: int = 0, error_message: str = "") -> None:
        """Atualiza status de um report download."""
        with self._lock:
            if 0 <= idx < len(self.reports_downloads):
                self.reports_downloads[idx]["status"] = status
                self.reports_downloads[idx]["filename"] = filename
                self.reports_downloads[idx]["size_kb"] = round(size_kb, 1)
                self.reports_downloads[idx]["retry_count"] = retry_count
                self.reports_downloads[idx]["error_message"] = error_message
                if status in ("done", "error"):
                    self.reports_downloads[idx]["finished_at"] = datetime.now().strftime("%H:%M:%S")

    def set_report_validation(self, validation: dict) -> None:
        """Define resultados da validacao pos-loop de reports."""
        with self._lock:
            self.report_validation = dict(validation)

    def set_export_data(self, csv_content: str) -> None:
        """Define o conteudo CSV para download."""
        with self._lock:
            self.export_csv = csv_content

    def set_vulns_data(self, data: list[dict]) -> None:
        """Define dados de vulnerabilidades extraidos dos CSVs de report."""
        with self._lock:
            self.vulns_data = list(data)

    def add_vulns_entry(self, entry: dict) -> None:
        """Adiciona uma entrada de vulnerabilidade ao vulns_data (progressivo, com dedup)."""
        with self._lock:
            # Deduplicar por scan_label ou scan_id
            new_label = entry.get("scan_label", "")
            new_id = entry.get("scan_id", "")
            for i, existing in enumerate(self.vulns_data):
                if new_label and existing.get("scan_label") == new_label:
                    self.vulns_data[i] = entry  # Atualizar entrada existente
                    return
                if new_id and existing.get("scan_id") == new_id:
                    self.vulns_data[i] = entry
                    return
            self.vulns_data.append(entry)

    def restart(self) -> bool:
        """Reseta o estado para READY, mantendo credenciais e logs. Permite nova execucao."""
        with self._lock:
            if self.phase != self.PHASE_FINISHED:
                return False
            # Preservar URLs adicionadas durante FINISHED para o proximo ciclo
            carry_over_urls = list(self._additional_urls)
            self.phase = self.PHASE_READY
            self.input_urls = carry_over_urls
            self.urls_total.clear()
            self._urls_total_set.clear()
            self.urls_scanning.clear()
            self.urls_completed.clear()
            self.urls_skipped.clear()
            self.urls_pending.clear()
            self._urls_pending_set.clear()
            self.workers.clear()
            self.api_webapps.clear()
            self.api_profiles.clear()
            self.api_scanned_month.clear()
            self.api_scans_detail.clear()
            self.api_scans_all_history.clear()
            self.month_ref = ""
            self._additional_urls.clear()
            self.reports_downloads.clear()
            self.export_csv = ""
            self.vulns_data.clear()
            # NAO limpar _force_rescan_urls: marcacoes de re-scan devem sobreviver ao restart
            # para que as URLs carregadas em input_urls bypassem a validacao mensal
            self.report_validation = {}
            self.started_at = None
            # Criar novo Event para o proximo ciclo
            self._start_event = threading.Event()
        return True

    def wait_for_start(self) -> None:
        """Bloqueia a thread principal ate o usuario clicar Iniciar no dashboard."""
        self._start_event.wait()

    def set_api_data(self, webapps: list[dict], profiles: list[dict],
                     scanned_month: list[str], scans_detail: list[dict],
                     month_ref: str, scans_all_history: list[dict] | None = None) -> None:
        """Define os dados lidos da API Qualys (chamado apos setup)."""
        with self._lock:
            self.api_webapps = list(webapps)
            self.api_profiles = list(profiles)
            self.api_scanned_month = list(scanned_month)
            self.api_scans_detail = list(scans_detail)
            self.api_scans_all_history = list(scans_all_history) if scans_all_history else []
            self.month_ref = month_ref

    def search_by_url(self, query: str) -> list[dict]:
        """
        Pesquisa scans completados por URL (parcial, case-insensitive).
        Retorna lista de resultados com worker, porta, scan_id, datas, etc.
        Busca tambem no historico da API (api_scans_detail).
        """
        query_lower = query.strip().lower()
        if not query_lower:
            return []

        results = []
        seen_scan_ids = set()

        with self._lock:
            # 1. Buscar nos scans concluidos do ciclo atual
            for item in self.urls_completed:
                url = item.get("url", "").lower()
                label = item.get("scan_label", "").lower()
                if query_lower in url or query_lower in label:
                    results.append({
                        "source": "ciclo_atual",
                        "url": item.get("url", ""),
                        "worker": item.get("worker", ""),
                        "worker_id": item.get("worker_id"),
                        "port": item.get("port"),
                        "scan_label": item.get("scan_label", ""),
                        "scan_id": item.get("scan_id", ""),
                        "finished_date": item.get("finished_date", ""),
                        "finished_at": item.get("finished_at", ""),
                    })
                    seen_scan_ids.add(item.get("scan_id", ""))

            # 2. Buscar no historico da API (scans de meses anteriores)
            for scan in self.api_scans_detail:
                scan_id = str(scan.get("id", ""))
                if scan_id in seen_scan_ids:
                    continue
                name = scan.get("name", "").lower()
                target_url = scan.get("target_url", "").lower()
                if query_lower in name or query_lower in target_url:
                    results.append({
                        "source": "historico_api",
                        "url": scan.get("target_url", scan.get("name", "")),
                        "worker": scan.get("webapp_name", ""),
                        "worker_id": scan.get("webapp_id"),
                        "port": None,
                        "scan_label": scan.get("name", ""),
                        "scan_id": scan_id,
                        "finished_date": scan.get("endScanDate", scan.get("launchedDate", "")),
                        "finished_at": "",
                    })

        return results

    def get_state(self) -> dict:
        """
        Retorna snapshot do estado atual (thread-safe).
        IMPORTANTE: Nunca inclui credenciais ou dados sensiveis.
        """
        with self._lock:
            return {
                "phase": self.phase,
                "total": len(self.urls_total),
                "scanning": dict(self.urls_scanning),
                "completed": list(self.urls_completed),
                "skipped": list(self.urls_skipped),
                "pending": list(self.urls_pending),
                "logs": list(self.logs[-200:]),
                "started_at": self.started_at,
                "workers": dict(self.workers),
                "completed_count": len(self.urls_completed),
                "skipped_count": len(self.urls_skipped),
                "pending_count": len(self.urls_pending),
                "scanning_count": len(self.urls_scanning),
                "has_export": bool(self.export_csv),
                "reports": list(self.reports_downloads),
                "reports_count": len(self.reports_downloads),
                "force_rescan_urls": sorted(self._force_rescan_urls),
                "report_validation": dict(self.report_validation),
                "vulns_data": list(self.vulns_data),
                "api": {
                    "webapps": list(self.api_webapps),
                    "profiles": list(self.api_profiles),
                    "scanned_month": list(self.api_scanned_month),
                    "scans_detail": list(self.api_scans_detail),
                    "scans_all_history": list(self.api_scans_all_history),
                    "month_ref": self.month_ref,
                },
                # auth_credentials NUNCA incluido aqui
            }


# Instancia global
dashboard = DashboardState()
