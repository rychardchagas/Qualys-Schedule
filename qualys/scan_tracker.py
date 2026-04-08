"""
Servico de rastreamento de URLs ja escaneadas por mes de referencia.
Consulta a API Qualys para verificar scans finalizados no mes atual.
Suporta dois formatos de nome de scan:
  - Legado: Scan_{dns}_{YYYY-MM-DD}
  - Novo:   YYYYMMDD dns porta
"""
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import date

from config.settings import QUALYS_SCAN_WEBAPPS
from qualys.service import QualysService


class ScanTracker:
    """Rastreia URLs escaneadas via API Qualys para evitar duplicatas no mes."""

    def __init__(self, qualys_service: QualysService):
        self.qualys_service = qualys_service
        self._scanned_urls: set[str] = set()
        self._scans_detail: list[dict] = []
        self._scans_all_history: list[dict] = []  # Todos os scans dos ultimos 12 meses
        # Affinity: dns -> worker (pre-built dict, O(1) lookup)
        self._affinity_map: dict[str, str] = {}

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normaliza URL para comparacao (remove protocolo, extrai dominio)."""
        return (
            url.replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
            .lower()
            .strip()
        )

    @staticmethod
    def _extract_dns_from_scan_name(scan_name: str) -> str | None:
        """Extrai o DNS do nome do scan. Suporta formato atual e legados."""
        # Formato atual: YYYYMMDD dns porta  (ex: 20260223 example.com 443)
        match = re.match(r"^\d{8}\s+(.+)$", scan_name)
        if match:
            rest = match.group(1).strip()
            # Remover sufixo ': [porta]' caso exista (formato legado)
            rest = re.sub(r":\s*\[\d+\]$", "", rest)
            # Remover porta numerica no final (formato atual: dns porta)
            rest = re.sub(r"\s+\d+$", "", rest)
            return rest.lower().strip()

        # Formato legado: Scan_{dns}_{YYYY-MM-DD}
        if scan_name.startswith("Scan_"):
            rest = scan_name[5:]
            if len(rest) > 11 and rest[-11] == "_":
                return rest[:-11].lower()

        return None

    def load_all(self) -> None:
        """
        Busca dados da API em uma unica passada:
        - Scans do mes atual (para is_scanned_this_month + dashboard)
        - Historico amplo de 12 meses (para afinidade de worker)

        Antes: 2 chamadas API por worker (14 total para 7 workers).
        Agora: 1 chamada API por worker (7 total) com range amplo,
               filtrando mes atual em memoria.
        """
        today = date.today()
        month_start = today.replace(day=1).isoformat()

        # Calcular 12 meses atras para afinidade
        m = today.month - 12
        y = today.year
        if m <= 0:
            m += 12
            y -= 1
        history_start = date(y, m, 1).isoformat()

        self._scanned_urls.clear()
        self._scans_detail.clear()
        self._scans_all_history.clear()
        self._affinity_map.clear()

        print(f"  Buscando scans desde {history_start} (afinidade 12 meses + mes atual)...")

        # Buscar scans de todos os workers em paralelo
        def _fetch_worker(wname: str, wid: int) -> tuple[str, list[dict]]:
            return wname, self.qualys_service.get_completed_scans(wid, history_start)

        worker_results: list[tuple[str, list[dict]]] = []
        with ThreadPoolExecutor(max_workers=len(QUALYS_SCAN_WEBAPPS)) as executor:
            futures = {
                executor.submit(_fetch_worker, wname, wid): wname
                for wname, wid in QUALYS_SCAN_WEBAPPS.items()
            }
            for future in futures:
                worker_results.append(future.result())

        # Processar resultados em memoria (single-thread, rapido)
        affinity_candidates: dict[str, tuple[str, str]] = {}

        for wname, scans in worker_results:
            for scan in scans:
                scan_name = scan.get("name", "")
                launched = scan.get("launchedDate", "")
                dns = self._extract_dns_from_scan_name(scan_name)

                scan_entry = {
                    "id": scan.get("id", ""),
                    "name": scan_name,
                    "status": scan.get("status", ""),
                    "launched": launched,
                    "worker": wname,
                }

                # Todos os scans dos ultimos 12 meses → historico completo
                self._scans_all_history.append(scan_entry)

                # Scans do mes atual → dashboard + is_scanned_this_month
                if launched >= month_start:
                    self._scans_detail.append(scan_entry)
                    if dns:
                        self._scanned_urls.add(dns)

                # Todos os scans → afinidade (manter o mais recente por dns)
                if dns:
                    existing = affinity_candidates.get(dns)
                    if not existing or launched >= existing[0]:
                        affinity_candidates[dns] = (launched, wname)

        # Construir mapa de afinidade O(1)
        self._affinity_map = {
            dns: worker for dns, (_, worker) in affinity_candidates.items()
        }

        # Ordenar detalhes (mais recente primeiro)
        self._scans_detail.sort(key=lambda s: s.get("launched", ""), reverse=True)
        self._scans_all_history.sort(key=lambda s: s.get("launched", ""), reverse=True)

        print(f"  Historico: {len(affinity_candidates)} URL(s) com afinidade | "
              f"Mes atual: {len(self._scanned_urls)} URL(s) escaneadas | "
              f"Total 12 meses: {len(self._scans_all_history)} scan(s)")

    def is_scanned_this_month(self, url: str) -> bool:
        """Verifica se a URL ja foi escaneada no mes de referencia atual."""
        return self._normalize_url(url) in self._scanned_urls

    def get_scanned_urls(self) -> list[str]:
        """Retorna lista de URLs escaneadas no mes atual."""
        return sorted(self._scanned_urls)

    def get_scans_detail(self) -> list[dict]:
        """Retorna detalhes dos scans finalizados no mes (para exibicao no dashboard)."""
        return list(self._scans_detail)

    def get_scans_all_history(self) -> list[dict]:
        """Retorna detalhes de TODOS os scans dos ultimos 12 meses."""
        return list(self._scans_all_history)

    def get_scanned_count(self) -> int:
        """Retorna quantidade de URLs escaneadas no mes atual."""
        return len(self._scanned_urls)

    def find_last_worker_for_url(self, url: str) -> str | None:
        """
        Busca no mapa de afinidade (O(1)) qual worker escaneou esta URL por ultimo.
        Retorna o nome do worker ou None se nao encontrado.
        """
        dns = self._normalize_url(url)
        return self._affinity_map.get(dns)
