"""
Servico de integracao com Qualys.
Camada de alto nivel sobre o QualysClient.
"""
import time

from config.settings import QUALYS_REPORT_MAX_ATTEMPTS, QUALYS_REPORT_POLL_INTERVAL
from qualys.client import QualysClient


class QualysService:
    """Servico para cruzamento de dados com Qualys WAS."""

    def __init__(self, client: QualysClient):
        self.client = client
        self._cached_apps: list[str] | None = None

    def load_webapps(self) -> None:
        """Carrega lista de webapps do Qualys (com cache em memoria)."""
        if self._cached_apps is None:
            self._cached_apps = self.client.fetch_webapps()

    @property
    def webapps(self) -> list[str]:
        if self._cached_apps is None:
            self.load_webapps()
        return self._cached_apps

    def is_registered(self, url: str) -> bool:
        """Verifica se a URL esta cadastrada no Qualys."""
        url_clean = (
            url.replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
            .lower()
        )
        return any(url_clean in app for app in self.webapps)

    def get_option_profiles(self) -> list[dict]:
        """Busca option profiles disponiveis no Qualys WAS."""
        return self.client.search_option_profiles()

    def get_scan_info(self, webapp_id: int) -> dict:
        """Retorna informacoes (nome e URL) de um WebApp de scan."""
        return self.client.get_webapp(webapp_id)

    def ensure_external_scanner(self, webapp_id: int) -> bool:
        """
        Verifica se o WebApp usa scanner EXTERNAL. Se nao, atualiza.
        Retorna True se ja era EXTERNAL ou se foi corrigido com sucesso.
        """
        info = self.client.get_webapp(webapp_id)
        current_type = info.get("scannerType", "")
        if current_type == "EXTERNAL":
            return True
        print(f"  WebApp {webapp_id}: Scanner type = '{current_type}' -> Corrigindo para EXTERNAL...")
        return self.client.update_webapp_scanner_type(webapp_id, "EXTERNAL")

    def check_running_scans(self, webapp_id: int, date: str) -> list[dict]:
        """Busca scans em execucao para um WebApp na data informada."""
        return self.client.search_running_scans(webapp_id, date)

    def get_scan_status(self, scan_id: str) -> str | None:
        """Consulta status real de um scan especifico. Retorna status ou None."""
        return self.client.get_scan_status(scan_id)

    def get_scan_vulns_summary(self, scan_id: str) -> dict | None:
        """Consulta contagens de vulns via GET /download/was/wasscan/{id}. Retorna findings ou None."""
        return self.client.get_scan_vulns_summary(scan_id)

    def get_scan_findings_full(self, scan_id: str) -> dict | None:
        """
        Consulta scan results via GET /download/was/wasscan/{id}.
        Retorna dict com contagens (findings) E lista detalhada (finding_details).
        """
        return self.client.get_scan_findings_full(scan_id)

    def launch_scan(self, webapp_id: int, scan_name: str, profile_id: str = "") -> str | None:
        """Lanca um scan de vulnerabilidade. Retorna scan ID ou None."""
        return self.client.launch_scan(webapp_id, scan_name, profile_id)

    def update_scan_url(self, webapp_id: int, new_url: str) -> bool:
        """Atualiza a URL de um WebApp de scan."""
        return self.client.update_webapp_url(webapp_id, new_url)

    def get_completed_scans(self, webapp_id: int, month_start: str) -> list[dict]:
        """Busca scans finalizados para um WebApp a partir de uma data."""
        return self.client.search_completed_scans(webapp_id, month_start)

    def create_report(self, scan_id: str, scan_target: str = "",
                      report_format: str = "PDF") -> str | None:
        """Cria relatorio (WAS) a partir do scan_id. Retorna report_id."""
        return self.client.create_report(scan_id, scan_target=scan_target,
                                         report_format=report_format)

    def get_report_status(self, report_id: str) -> str | None:
        """Verifica status do relatorio. Retorna string (Finished, Running...)."""
        return self.client.get_report_status(report_id)

    def download_report(self, report_id: str) -> bytes | None:
        """Baixa o PDF de um relatorio pelo report_id."""
        return self.client.download_report(report_id)

    def generate_full_report(
        self,
        scan_id: str,
        scan_target: str = "",
        report_format: str = "PDF",
        on_progress: callable = None,
    ) -> dict:
        """
        Fluxo completo de report: create → poll status → download.

        Args:
            scan_id: ID do scan WAS.
            scan_target: Nome/URL do alvo (para nome do report).
            report_format: PDF ou CSV.
            on_progress: Callback opcional (step, message) para log de progresso.

        Returns:
            dict com 'report_id', 'content', 'status', 'format'.
        Raises:
            RuntimeError se qualquer etapa falhar.
        """
        fmt = report_format.upper()

        def _log(step: str, msg: str):
            if on_progress:
                on_progress(step, msg)

        # ── Passo 1: Criar report ──
        _log("create", f"Criando report {fmt} para scan_id={scan_id}...")
        report_id = self.client.create_report(scan_id, scan_target=scan_target,
                                              report_format=fmt)
        _log("create", f"Report criado: report_id={report_id}")

        # ── Passo 2: Poll status com tentativas ──
        _log("status", "Aguardando processamento...")
        final_status = None

        for attempt in range(1, QUALYS_REPORT_MAX_ATTEMPTS + 1):
            status = self.client.get_report_status(report_id)
            _log("status", f"Tentativa {attempt}/{QUALYS_REPORT_MAX_ATTEMPTS}: {status}")

            if status and status.upper() in ("COMPLETE", "FINISHED"):
                final_status = status
                break

            if status and status.upper() in ("ERROR", "FAILED", "CANCELLED"):
                raise RuntimeError(f"Report falhou com status: {status}")

            time.sleep(QUALYS_REPORT_POLL_INTERVAL)
        else:
            raise RuntimeError(
                f"Timeout: report nao ficou pronto apos "
                f"{QUALYS_REPORT_MAX_ATTEMPTS} tentativas "
                f"({QUALYS_REPORT_MAX_ATTEMPTS * QUALYS_REPORT_POLL_INTERVAL}s)"
            )

        # ── Passo 3: Download ──
        _log("download", f"Baixando {fmt} (report_id={report_id})...")
        content = self.client.download_report(report_id)

        if not content:
            raise RuntimeError(f"Falha ao baixar {fmt}: resposta vazia ou formato invalido")

        _log("download", f"{fmt} baixado: {len(content)} bytes")

        return {
            "report_id": report_id,
            "content": content,
            "format": fmt,
            "status": final_status,
        }
