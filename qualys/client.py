"""
Client HTTP para API Qualys WAS.
Responsavel por autenticacao, requests com retry e parsing XML.
Inclui validacao de entrada e prevencao de XML injection.
Possui rate limiter (semaforo) e retry com backoff exponencial para 401/503.
"""
import re
import threading
import time
import defusedxml.ElementTree as ET

import requests

from config.settings import (
    QUALYS_API_BASE,
    QUALYS_API_URL,
    QUALYS_HEADERS,
    QUALYS_MAX_CONCURRENT,
    QUALYS_MAX_RETRIES,
    QUALYS_RESULTS_LIMIT,
    QUALYS_RETRY_DELAY,
    QUALYS_RETRY_STATUSES,
    QUALYS_TIMEOUT,
)

# --- Constantes de report ---
REPORT_REQUEST_TIMEOUT = 60
REPORT_DOWNLOAD_TIMEOUT = 120


def _validate_id(value) -> str:
    """Valida que o valor eh um ID numerico. Previne XML injection."""
    s = str(value).strip()
    if not re.match(r"^\d+$", s):
        raise ValueError(f"ID invalido (deve ser numerico): {s!r}")
    return s


def _sanitize_xml_text(value: str) -> str:
    """Escapa caracteres especiais para uso seguro em XML."""
    return (
        value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


class QualysClient:
    """Client para comunicacao com a API Qualys WAS."""

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.api_url = QUALYS_API_URL
        # Session reutiliza conexoes TCP (keep-alive) e cache SSL
        self._session = requests.Session()
        self._session.auth = (username, password)
        self._session.headers.update(QUALYS_HEADERS)
        # Forcar verificacao SSL/TLS (previne MITM)
        self._session.verify = True
        # Semaforo limita requisicoes concorrentes para evitar rate limiting
        self._semaphore = threading.Semaphore(QUALYS_MAX_CONCURRENT)
        # Cache de QIDs do grupo SECURITY_WEAKNESS (populado sob demanda)
        self._sw_qids: set[str] | None = None

    def _request(
        self,
        method: str,
        url: str,
        *,
        data: str | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
        retries: int | None = None,
        label: str = "",
    ) -> requests.Response | None:
        """
        Requisicao HTTP centralizada com:
        - Semaforo de concorrencia (max QUALYS_MAX_CONCURRENT simultaneas)
        - Retry com backoff exponencial para status em QUALYS_RETRY_STATUSES
        - Log padronizado de erros

        Retorna Response com status 200 ou None se todas as tentativas falharem.
        """
        max_retries = retries if retries is not None else QUALYS_MAX_RETRIES
        req_timeout = timeout or QUALYS_TIMEOUT

        for attempt in range(1, max_retries + 1):
            self._semaphore.acquire()
            try:
                if method.upper() == "GET":
                    response = self._session.get(
                        url, timeout=req_timeout, headers=headers or {},
                    )
                else:
                    response = self._session.post(
                        url, data=data, timeout=req_timeout, headers=headers or {},
                    )
            except requests.RequestException as e:
                if label:
                    print(f"  Erro de conexao ({label}): {e}")
                if attempt < max_retries:
                    time.sleep(QUALYS_RETRY_DELAY)
                continue
            finally:
                self._semaphore.release()

            if response.status_code == 200:
                return response

            if response.status_code in QUALYS_RETRY_STATUSES and attempt < max_retries:
                delay = QUALYS_RETRY_DELAY * attempt  # backoff linear: 5s, 10s, 15s
                if label:
                    print(f"  {label}: Status {response.status_code}, retry {attempt}/{max_retries} em {delay}s...")
                time.sleep(delay)
                continue

            # Status nao retentavel ou ultima tentativa
            if label:
                print(f"  Erro {label}: Status {response.status_code} (tentativa {attempt}/{max_retries})")
            return None

        # Todas as tentativas falharam por excecao de conexao
        if label:
            print(f"  Falha {label} apos {max_retries} tentativas de conexao.")
        return None

    def fetch_webapps(self) -> list[str]:
        """
        Busca todas as URLs de WebApps cadastradas no Qualys.
        Retorna lista de URLs normalizadas (lowercase).
        """
        xml_payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<ServiceRequest><preferences>"
            f"<limitResults>{QUALYS_RESULTS_LIMIT}</limitResults>"
            "</preferences></ServiceRequest>"
        )

        print(f"  Sincronizando com Qualys...")
        response = self._request(
            "POST", self.api_url, data=xml_payload,
            label="ao buscar WebApps",
        )
        if response:
            return self._parse_webapps_xml(response.text)

        print("  Falha apos todas as tentativas de conexao com Qualys.")
        return []

    def get_webapp(self, webapp_id: int) -> dict:
        """
        Busca detalhes de um WebApp especifico pelo ID.
        Retorna dict com 'name', 'url' e 'scannerType', ou vazio em caso de erro.
        scannerType: 'EXTERNAL', 'INTERNAL' ou '' (nao definido).
        """
        safe_id = _validate_id(webapp_id)
        url = f"{QUALYS_API_BASE}/get/was/webapp/{safe_id}"

        response = self._request(
            "GET", url, label=f"ao consultar WebApp {safe_id}",
        )
        if not response:
            return {}

        root = ET.fromstring(response.text)
        webapp_name = ""
        webapp_url = ""
        scanner_type = ""
        name_el = root.find(".//WebApp/name")
        url_el = root.find(".//WebApp/url")
        if name_el is not None and name_el.text:
            webapp_name = name_el.text.strip()
        if url_el is not None and url_el.text:
            webapp_url = url_el.text.strip()
        # Scanner appliance type (EXTERNAL ou INTERNAL)
        for path in (
            ".//WebApp/defaultScanner/type",
            ".//WebApp/scannerAppliance/type",
            ".//WebApp/defaultScannerAppliance/type",
        ):
            el = root.find(path)
            if el is not None and el.text:
                scanner_type = el.text.strip().upper()
                break
        return {"name": webapp_name, "url": webapp_url, "scannerType": scanner_type}

    def search_option_profiles(self) -> list[dict]:
        """
        Busca option profiles disponiveis no Qualys WAS.
        Retorna lista de dicts com 'id' e 'name'.
        """
        url = f"{QUALYS_API_BASE}/search/was/optionprofile"
        xml_payload = (
            "<ServiceRequest>"
            "<preferences>"
            "<limitResults>10</limitResults>"
            "</preferences>"
            "</ServiceRequest>"
        )

        response = self._request(
            "POST", url, data=xml_payload,
            label="ao buscar option profiles",
        )
        if not response:
            return []

        root = ET.fromstring(response.text)
        profiles = []
        for profile_el in root.findall(".//OptionProfile"):
            pid = ""
            pname = ""
            id_el = profile_el.find("id")
            name_el = profile_el.find("name")
            if id_el is not None and id_el.text:
                pid = id_el.text.strip()
            if name_el is not None and name_el.text:
                pname = name_el.text.strip()
            if pid:
                profiles.append({"id": pid, "name": pname})
        return profiles

    def search_running_scans(self, webapp_id: int, date: str) -> list[dict]:
        """
        Busca scans ativos (RUNNING ou SUBMITTED) para um WebApp na data informada.
        Retorna lista de dicts com id, name, status, launchedDate.
        """
        safe_id = _validate_id(webapp_id)
        safe_date = _sanitize_xml_text(date)
        url = f"{QUALYS_API_BASE}/search/was/wasscan"
        all_scans = []

        for status in ("RUNNING", "SUBMITTED"):
            xml_payload = (
                "<ServiceRequest>"
                "<filters>"
                f'<Criteria field="webApp.id" operator="EQUALS">{safe_id}</Criteria>'
                f'<Criteria field="status" operator="EQUALS">{status}</Criteria>'
                f'<Criteria field="launchedDate" operator="EQUALS">{safe_date}</Criteria>'
                "</filters>"
                "<preferences></preferences>"
                "</ServiceRequest>"
            )

            response = self._request(
                "POST", url, data=xml_payload,
                label=f"ao buscar scans ({status}) do WebApp {safe_id}",
            )
            if response:
                all_scans.extend(self._parse_wasscan_xml(response.text))

        return all_scans

    def get_scan_status(self, scan_id: str) -> str | None:
        """
        Consulta o status real de um scan especifico pelo ID.
        Retorna o status (SUBMITTED, RUNNING, FINISHED, CANCELED, ERROR)
        ou None se nao conseguir consultar.
        """
        safe_id = _validate_id(scan_id)
        url = f"{QUALYS_API_BASE}/get/was/wasscan/{safe_id}"

        response = self._request(
            "GET", url, label=f"ao consultar status do scan {safe_id}",
        )
        if not response:
            return None

        root = ET.fromstring(response.text)
        status_el = root.find(".//WasScan/status")
        if status_el is not None and status_el.text:
            return status_el.text.strip()
        return None

    def get_scan_vulns_summary(self, scan_id: str) -> dict | None:
        """
        Consulta resultados de um scan via GET /download/was/wasscan/{id}.
        Extrai contagens de vulnerabilidades por severidade das stats do XML.

        Conforme Qualys WAS API Guide, o endpoint /download/ retorna o XML
        completo com <stats>, <vulns>, <igs> e <sensitiveContents>.
        O /get/ retorna apenas metadados (nome, status, target).

        Formato das stats no XML:
            <stats><global>
                <nbVulnsTotal>N</nbVulnsTotal>
                <nbVulnsLevel5>N</nbVulnsLevel5>  (Urgent)
                <nbVulnsLevel4>N</nbVulnsLevel4>  (High)
                ...
                <nbScsTotal>N</nbScsTotal>        (Sensitive Content)
                <nbScsLevel5>N</nbScsLevel5>
                ...
                <nbIgsTotal>N</nbIgsTotal>        (Info Gathered)
                <nbIgsLevel5>N</nbIgsLevel5>
                ...
            </global></stats>

        Retorna dict com findings no formato padrao:
        {
            "status": "FINISHED",
            "Urgent": {"vulns": N, "sensitive": N, "info": N},
            "High": ..., "Medium": ..., "Low": ..., "Minimal": ...,
            "_totals": {"vulns": N, "sensitive": N, "info": N, "total": N}
        }
        Ou None se nao conseguir consultar.
        """
        safe_id = _validate_id(scan_id)
        url = f"{QUALYS_API_BASE}/download/was/wasscan/{safe_id}"

        # Mapeamento level numerico -> nome de severidade
        level_map = {
            "5": "Urgent", "4": "High", "3": "Medium", "2": "Low", "1": "Minimal",
        }

        response = self._request(
            "GET", url, label=f"[Vulns] scan {safe_id}",
        )
        if not response:
            return None

        try:
            root = ET.fromstring(response.text)
        except ET.ParseError as e:
            print(f"  [Vulns] Erro ao parsear XML do scan {safe_id}: {e}")
            return None

        # Root e <WasScan> diretamente (nao ServiceResponse)
        # Status do scan
        status = ""
        status_el = root.find("status")
        if status_el is not None and status_el.text:
            status = status_el.text.strip()

        # Inicializar findings
        findings: dict = {}
        for sev_name in ("Urgent", "High", "Medium", "Low", "Minimal"):
            findings[sev_name] = {"vulns": 0, "sensitive": 0, "info": 0}
        totals = {"vulns": 0, "sensitive": 0, "info": 0, "total": 0}

        global_el = root.find("stats/global")
        if global_el is not None:
            # Parsear nbVulnsLevelN (Vulnerabilities)
            for level, sev_name in level_map.items():
                el = global_el.find(f"nbVulnsLevel{level}")
                if el is not None and el.text:
                    try:
                        count = int(el.text.strip())
                        findings[sev_name]["vulns"] = count
                        totals["vulns"] += count
                        totals["total"] += count
                    except ValueError:
                        pass

            # Parsear nbScsLevelN (Sensitive Content)
            for level, sev_name in level_map.items():
                el = global_el.find(f"nbScsLevel{level}")
                if el is not None and el.text:
                    try:
                        count = int(el.text.strip())
                        findings[sev_name]["sensitive"] = count
                        totals["sensitive"] += count
                        totals["total"] += count
                    except ValueError:
                        pass

            # Parsear nbIgsLevelN (Information Gathered)
            for level, sev_name in level_map.items():
                el = global_el.find(f"nbIgsLevel{level}")
                if el is not None and el.text:
                    try:
                        count = int(el.text.strip())
                        findings[sev_name]["info"] = count
                        totals["info"] += count
                        totals["total"] += count
                    except ValueError:
                        pass

        findings["_totals"] = totals
        findings["status"] = status
        return findings

    def get_security_weakness_qids(self) -> set[str]:
        """
        Consulta a KnowledgeBase do WAS para obter QIDs do grupo SECURITY_WEAKNESS.
        O resultado e cacheado na instancia para evitar chamadas repetidas.
        Usa POST /search/was/knowledgebase com filtro group=SECURITY_WEAKNESS.
        """
        if self._sw_qids is not None:
            return self._sw_qids

        url = f"{QUALYS_API_BASE}/search/was/knowledgebase"
        xml_payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<ServiceRequest><filters>"
            '<Criteria field="group" operator="EQUALS">SECURITY_WEAKNESS</Criteria>'
            "</filters><preferences>"
            "<limitResults>1000</limitResults>"
            "</preferences></ServiceRequest>"
        )

        response = self._request(
            "POST", url, data=xml_payload,
            label="[KnowledgeBase] ao buscar SW QIDs",
        )
        if not response:
            self._sw_qids = set()
            return self._sw_qids

        try:
            root = ET.fromstring(response.text)
        except ET.ParseError as e:
            print(f"  [KnowledgeBase] Erro ao parsear XML: {e}")
            self._sw_qids = set()
            return self._sw_qids

        qids: set[str] = set()
        # Resposta: <ServiceResponse><data><WasKnowledgeBase><qid>NNNNN</qid>...
        for kb_el in root.findall(".//WasKnowledgeBase"):
            qid = kb_el.findtext("qid", "").strip()
            if qid:
                qids.add(qid)

        self._sw_qids = qids
        print(f"  [KnowledgeBase] {len(qids)} QID(s) do grupo SECURITY_WEAKNESS")
        return self._sw_qids

    def get_scan_findings_full(self, scan_id: str) -> dict | None:
        """
        Consulta resultados completos de um scan via GET /download/was/wasscan/{id}.
        Retorna dict com summary counts E lista detalhada de vulns/igs.

        Conforme Qualys WAS API Guide, o XML de resposta contem:
            <vulns><list><WasScanVuln> com qid, severity, title, uri, group
            <igs><list><WasScanIg> com qid, title
            <sensitiveContents><list><WasScanSensitiveContent> com qid, title

        Os IGs nao possuem campo <group> no XML de download.
        O grupo SECURITY_WEAKNESS e determinado via consulta a KnowledgeBase (cacheada).

        Formato retornado: {
            "findings": {Urgent: {...}, ..., _totals: {...}},
            "finding_details": [{"name": str, "severity": str, "type": str, "qid": str, "group": str}, ...]
        }
        Ou None se falhar.
        """
        safe_id = _validate_id(scan_id)
        url = f"{QUALYS_API_BASE}/download/was/wasscan/{safe_id}"

        level_map = {
            "5": "Urgent", "4": "High", "3": "Medium", "2": "Low", "1": "Minimal",
        }

        response = self._request(
            "GET", url, label=f"ao baixar scan {safe_id}",
        )
        if not response:
            return None

        try:
            root = ET.fromstring(response.text)
        except ET.ParseError:
            return None

        # Inicializar contagens
        findings: dict = {}
        for sev_name in ("Urgent", "High", "Medium", "Low", "Minimal"):
            findings[sev_name] = {"vulns": 0, "sensitive": 0, "info": 0}
        totals = {"vulns": 0, "sensitive": 0, "info": 0, "total": 0}
        finding_details: list[dict] = []

        # --- Stats globais (contagens rapidas) ---
        global_el = root.find("stats/global")
        if global_el is not None:
            for level, sev_name in level_map.items():
                for prefix, key in [("nbVulnsLevel", "vulns"),
                                    ("nbScsLevel", "sensitive"),
                                    ("nbIgsLevel", "info")]:
                    el = global_el.find(f"{prefix}{level}")
                    if el is not None and el.text:
                        try:
                            count = int(el.text.strip())
                            findings[sev_name][key] = count
                            totals[key] += count
                            totals["total"] += count
                        except ValueError:
                            pass

        # --- Detalhes: <vulns><list><WasScanVuln> ---
        for vuln_el in root.findall("vulns/list/WasScanVuln"):
            qid = vuln_el.findtext("qid", "").strip()
            title = vuln_el.findtext("title", "").strip()
            severity = vuln_el.findtext("severity", "").strip()
            group = vuln_el.findtext("group", "").strip()
            sev_name = level_map.get(severity, "")

            if title:
                finding_details.append({
                    "name": title,
                    "severity": sev_name or f"Level{severity}",
                    "type": "VULNERABILITY",
                    "qid": qid,
                    "group": group,
                })

        # --- Detalhes: <igs><list><WasScanIg> ---
        # IGs no XML de download NAO possuem <group>.
        # O grupo e determinado via KnowledgeBase (cacheado).
        sw_qids = self.get_security_weakness_qids()
        for ig_el in root.findall("igs/list/WasScanIg"):
            qid = ig_el.findtext("qid", "").strip()
            title = ig_el.findtext("title", "").strip()
            severity = ig_el.findtext("severity", "").strip()
            sev_name_ig = level_map.get(severity, "Minimal")
            ig_group = "SECURITY_WEAKNESS" if qid in sw_qids else "INFO"

            if title:
                finding_details.append({
                    "name": title,
                    "severity": sev_name_ig,
                    "type": "INFORMATION_GATHERED",
                    "qid": qid,
                    "group": ig_group,
                })

        # --- Detalhes: <sensitiveContents><list><WasScanSensitiveContent> ---
        for sc_el in root.findall("sensitiveContents/list/WasScanSensitiveContent"):
            qid = sc_el.findtext("qid", "").strip()
            title = sc_el.findtext("title", "").strip()
            severity = sc_el.findtext("severity", "").strip()
            sev_name_sc = level_map.get(severity, "Medium")

            if title:
                finding_details.append({
                    "name": title,
                    "severity": sev_name_sc,
                    "type": "SENSITIVE_CONTENT",
                    "qid": qid,
                    "group": "SENSITIVE",
                })

        findings["_totals"] = totals
        return {
            "findings": findings,
            "finding_details": finding_details,
        }

    @staticmethod
    def _parse_wasscan_xml(xml_text: str) -> list[dict]:
        """Extrai informacoes de scans do XML de resposta."""
        root = ET.fromstring(xml_text)
        scans = []
        for scan_el in root.findall(".//WasScan"):
            scan = {}
            id_el = scan_el.find("id")
            name_el = scan_el.find("name")
            status_el = scan_el.find("status")
            launched_el = scan_el.find("launchedDate")
            if id_el is not None and id_el.text:
                scan["id"] = id_el.text.strip()
            if name_el is not None and name_el.text:
                scan["name"] = name_el.text.strip()
            if status_el is not None and status_el.text:
                scan["status"] = status_el.text.strip()
            if launched_el is not None and launched_el.text:
                scan["launchedDate"] = launched_el.text.strip()
            if scan:
                scans.append(scan)
        return scans

    def search_completed_scans(self, webapp_id: int, month_start: str) -> list[dict]:
        """
        Busca scans finalizados para um WebApp a partir de uma data.
        Retorna lista de dicts com id, name, status, launchedDate.
        """
        safe_id = _validate_id(webapp_id)
        safe_date = _sanitize_xml_text(month_start)
        url = f"{QUALYS_API_BASE}/search/was/wasscan"
        xml_payload = (
            "<ServiceRequest>"
            "<filters>"
            f'<Criteria field="webApp.id" operator="EQUALS">{safe_id}</Criteria>'
            f'<Criteria field="status" operator="EQUALS">FINISHED</Criteria>'
            f'<Criteria field="launchedDate" operator="GREATER">{safe_date}</Criteria>'
            "</filters>"
            "<preferences>"
            "<limitResults>1000</limitResults>"
            "</preferences>"
            "</ServiceRequest>"
        )

        response = self._request(
            "POST", url, data=xml_payload,
            label=f"ao buscar scans finalizados do WebApp {safe_id}",
        )
        if response:
            return self._parse_wasscan_xml(response.text)
        return []

    def launch_scan(self, webapp_id: int, scan_name: str, profile_id: str = "") -> str | None:
        """
        Lanca um scan de vulnerabilidade para um WebApp.
        Retorna o scan ID (str) se bem-sucedido, None caso contrario.
        """
        safe_wid = _validate_id(webapp_id)
        safe_name = _sanitize_xml_text(scan_name)
        url = f"{QUALYS_API_BASE}/launch/was/wasscan"

        profile_xml = ""
        if profile_id:
            safe_pid = _validate_id(profile_id)
            profile_xml = f"<profile><id>{safe_pid}</id></profile>"

        xml_payload = (
            "<ServiceRequest>"
            "<data>"
            "<WasScan>"
            f"<name><![CDATA[{safe_name}]]></name>"
            "<type>VULNERABILITY</type>"
            f"{profile_xml}"
            "<target>"
            "<webApp>"
            f"<id>{safe_wid}</id>"
            "</webApp>"
            "<scannerAppliance>"
            "<type>EXTERNAL</type>"
            "</scannerAppliance>"
            "</target>"
            "</WasScan>"
            "</data>"
            "</ServiceRequest>"
        )

        response = self._request(
            "POST", url, data=xml_payload,
            label=f"ao lancar scan no WebApp {safe_wid}",
        )
        if not response:
            return None

        root = ET.fromstring(response.text)
        code_el = root.find(".//responseCode")
        if code_el is not None and code_el.text == "SUCCESS":
            scan_id_el = root.find(".//WasScan/id")
            scan_id = scan_id_el.text.strip() if scan_id_el is not None and scan_id_el.text else ""
            return scan_id or "unknown"
        print(f"  Resposta inesperada ao lancar scan: {response.text[:200]}")
        return None

    def update_webapp_url(self, webapp_id: int, new_url: str) -> bool:
        """
        Atualiza a URL de um WebApp no Qualys WAS.
        Retorna True se a atualizacao foi bem-sucedida.
        """
        safe_id = _validate_id(webapp_id)
        safe_url = _sanitize_xml_text(new_url)
        url = f"{QUALYS_API_BASE}/update/was/webapp/{safe_id}"
        xml_payload = (
            "<ServiceRequest>"
            "<data>"
            "<WebApp>"
            f"<url><![CDATA[{safe_url}]]></url>"
            "</WebApp>"
            "</data>"
            "</ServiceRequest>"
        )

        response = self._request(
            "POST", url, data=xml_payload,
            label=f"ao atualizar WebApp {safe_id}",
        )
        if not response:
            return False

        root = ET.fromstring(response.text)
        code_el = root.find(".//responseCode")
        if code_el is not None and code_el.text == "SUCCESS":
            return True
        print(f"  Resposta inesperada da API: {response.text[:200]}")
        return False

    def update_webapp_scanner_type(self, webapp_id: int, scanner_type: str = "EXTERNAL") -> bool:
        """
        Atualiza o tipo de Scanner Appliance de um WebApp para EXTERNAL ou INTERNAL.
        Retorna True se a atualizacao foi bem-sucedida.
        """
        safe_id = _validate_id(webapp_id)
        stype = scanner_type.strip().upper()
        if stype not in ("EXTERNAL", "INTERNAL"):
            raise ValueError(f"Scanner type invalido: {stype}. Use EXTERNAL ou INTERNAL.")
        url = f"{QUALYS_API_BASE}/update/was/webapp/{safe_id}"
        xml_payload = (
            "<ServiceRequest>"
            "<data>"
            "<WebApp>"
            "<defaultScanner>"
            f"<type>{stype}</type>"
            "</defaultScanner>"
            "</WebApp>"
            "</data>"
            "</ServiceRequest>"
        )

        response = self._request(
            "POST", url, data=xml_payload,
            label=f"ao atualizar scanner type do WebApp {safe_id}",
        )
        if not response:
            return False

        root = ET.fromstring(response.text)
        code_el = root.find(".//responseCode")
        if code_el is not None and code_el.text == "SUCCESS":
            return True
        print(f"  Resposta inesperada ao atualizar scanner type: {response.text[:200]}")
        return False

    # ── Report WAS API: create → status → download (/qps/rest/3.0/) ───

    def create_report(self, scan_id: str, scan_target: str = "",
                      report_format: str = "PDF") -> str:
        """
        Passo 1: POST /qps/rest/3.0/create/was/report
        Cria relatorio para um scan WAS via API WAS.
        report_format: PDF ou CSV.
        Retorna o report_id. Lanca RuntimeError se falhar.
        """
        safe_scan_id = _validate_id(scan_id)
        fmt = report_format.upper()
        if fmt not in ("PDF", "CSV"):
            raise ValueError(f"Formato invalido: {fmt}. Use PDF ou CSV.")

        if scan_target:
            safe_target = _sanitize_xml_text(scan_target.strip()[:128])
            report_name = f"Scan Report - {safe_target} - ID {safe_scan_id}"
        else:
            report_name = f"Scan Report - ID {safe_scan_id}"

        url = f"{QUALYS_API_BASE}/create/was/report"
        xml_payload = (
            "<ServiceRequest>"
            "<data>"
            "<Report>"
            f"<name><![CDATA[{report_name}]]></name>"
            f"<format>{fmt}</format>"
            "<type>WAS_SCAN_REPORT</type>"
            "<config>"
            "<scanReport>"
            "<target>"
            "<scans>"
            f"<WasScan><id>{safe_scan_id}</id></WasScan>"
            "</scans>"
            "</target>"
            "</scanReport>"
            "</config>"
            "</Report>"
            "</data>"
            "</ServiceRequest>"
        )

        print(f"  [REPORT] Passo 1/3: Criando report '{report_name}'...")
        response = self._request(
            "POST", url, data=xml_payload,
            timeout=REPORT_REQUEST_TIMEOUT,
            label=f"[REPORT] ao criar report para scan {safe_scan_id}",
        )
        if not response:
            raise RuntimeError(f"Falha ao criar report apos {QUALYS_MAX_RETRIES} tentativas")

        print(f"  [REPORT] HTTP {response.status_code}, {len(response.content)} bytes")

        try:
            root = ET.fromstring(response.text)
        except ET.ParseError as e:
            raise RuntimeError(f"XML parse error: {e} | Raw: {response.text[:200]}")

        code_el = root.find(".//responseCode")
        if code_el is not None and code_el.text == "SUCCESS":
            id_el = root.find(".//Report/id")
            if id_el is not None and id_el.text:
                report_id = id_el.text.strip()
                print(f"  [REPORT] Report criado: report_id={report_id}")
                return report_id

        # Extrair mensagem de erro detalhada
        err_detail = root.find(".//responseErrorDetails/errorMessage")
        err_msg = err_detail.text if err_detail is not None and err_detail.text else ""
        if not err_msg:
            err_code = root.find(".//responseCode")
            err_msg = err_code.text if err_code is not None and err_code.text else ""
        if not err_msg:
            err_msg = response.text[:300]
        raise RuntimeError(err_msg)

    def get_report_status(self, report_id: str) -> str | None:
        """
        Passo 2: GET /qps/rest/3.0/status/was/report/{report_id}
        Retorna o status do relatorio (RUNNING, COMPLETE, ERROR).
        """
        safe_id = _validate_id(report_id)
        url = f"{QUALYS_API_BASE}/status/was/report/{safe_id}"

        response = self._request(
            "GET", url, timeout=REPORT_REQUEST_TIMEOUT,
            label=f"[REPORT] ao verificar status do report {safe_id}",
        )
        if not response:
            return None

        print(f"  [REPORT] Status check: HTTP {response.status_code} | {response.text[:200]}")

        try:
            root = ET.fromstring(response.text)
        except ET.ParseError as e:
            print(f"  [REPORT] Erro ao parsear status: {e}")
            return None

        # Tentar varios caminhos possiveis
        for path in (".//Report/status", ".//status", ".//STATE"):
            el = root.find(path)
            if el is not None and el.text:
                return el.text.strip()

        return None

    def download_report(self, report_id: str) -> bytes | None:
        """
        Passo 3: GET /qps/rest/3.0/download/was/report/{report_id}
        Baixa o conteudo do report (PDF ou CSV). Retorna bytes ou None.
        """
        safe_id = _validate_id(report_id)
        url = f"{QUALYS_API_BASE}/download/was/report/{safe_id}"

        print(f"  [REPORT] Passo 3/3: Baixando report (report_id={safe_id})...")
        response = self._request(
            "GET", url, timeout=REPORT_DOWNLOAD_TIMEOUT,
            headers={"Accept": "*/*"},
            label=f"[REPORT] ao baixar report {safe_id}",
        )
        if not response:
            return None

        content_type = response.headers.get("Content-Type", "")
        print(f"  [REPORT] HTTP {response.status_code}, Content-Type: {content_type}, {len(response.content)} bytes")

        # Aceitar PDF ou CSV
        if ("application/pdf" in content_type
                or "text/csv" in content_type
                or "application/octet-stream" in content_type
                or response.content[:5] == b"%PDF-"):
            print(f"  [REPORT] Download OK: {len(response.content)} bytes")
            return response.content

        # Conteudo desconhecido mas com dados — aceitar mesmo assim
        if len(response.content) > 100:
            print(f"  [REPORT] Content-Type inesperado ({content_type}), mas com {len(response.content)} bytes. Aceitando.")
            return response.content

        print(f"  [REPORT] Resposta inesperada: {content_type}")
        print(f"  [REPORT] Primeiros bytes: {response.content[:100]}")
        return None

    @staticmethod
    def _parse_webapps_xml(xml_text: str) -> list[str]:
        """Extrai URLs do XML de resposta da API Qualys."""
        root = ET.fromstring(xml_text)
        urls = [
            app.text.strip().lower()
            for app in root.findall(".//url")
            if app.text
        ]
        print(f"  Sucesso: {len(urls)} aplicacoes encontradas no Qualys.")
        return urls
