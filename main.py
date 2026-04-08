"""
Entry point da automacao Qualys Schedule.

Fluxo:
  1. Inicia servidor web (dashboard disponivel imediatamente)
  2. Aguarda usuario se autenticar no dashboard
  3. Aguarda usuario informar URLs e clicar "Iniciar"
  4. Consulta API Qualys (WebApps, profiles, scans do mes)
  5. Orquestracao automatica de scans (com afinidade de worker)
  6. Gera export dos resultados
  7. Permite reiniciar a rotina

Dashboard web disponivel em http://localhost:8080
"""
import csv
import io
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date

# Garante que o diretorio raiz do projeto esta no sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import (
    LOG_OUTPUT_DIR, QUALYS_SCAN_WEBAPPS, REPORT_OUTPUT_DIR, SCAN_CHECK_INTERVAL,
    SCAN_PROFILE_ID, WEB_PORT, REPORT_DOWNLOAD_MAX_RETRIES, REPORT_DOWNLOAD_RETRY_BACKOFF,
)
from core.port_checker import resolve_port
from core.shared_state import dashboard
from qualys.client import QualysClient
from qualys.scan_tracker import ScanTracker
from qualys.service import QualysService
from web.server import set_qualys_service, start_dashboard_server


_SAFE_FILENAME_RE = re.compile(r'[^a-zA-Z0-9._\- ]')


def safe_filename(name: str) -> str:
    """Remove caracteres perigosos de nomes de arquivo para prevenir path traversal."""
    sanitized = _SAFE_FILENAME_RE.sub('_', name)
    # Remover .. e barras residuais
    sanitized = sanitized.replace('..', '_').strip('. ')
    return sanitized or 'unnamed'


def safe_filepath(directory: str, filename: str) -> str:
    """Constroi filepath seguro, validando que permanece dentro do diretorio."""
    filepath = os.path.join(directory, safe_filename(filename))
    real_dir = os.path.realpath(directory)
    real_path = os.path.realpath(filepath)
    if not real_path.startswith(real_dir + os.sep) and real_path != real_dir:
        raise ValueError(f"Path traversal detectado: {filename}")
    return filepath


def log(message: str) -> None:
    """Log centralizado: imprime no console e envia ao dashboard."""
    dashboard.log(message)


def _extract_dns(url: str) -> str:
    """Extrai e normaliza o DNS de uma URL (remove protocolo, path, lowercase)."""
    return url.replace("https://", "").replace("http://", "").split("/")[0].lower()


def _download_scan_reports(
    qualys_service: QualysService, scan_id: str, scan_label: str, wname: str,
) -> dict[str, str]:
    """
    Baixa reports PDF e CSV em paralelo apos finalizacao do scan.
    Salva em REPORT_OUTPUT_DIR/{scan_label}.{ext}.
    Atualiza o dashboard com status em tempo real.
    Retorna dict com formato -> filepath dos arquivos gerados.
    Em caso de erro, loga e continua (nao bloqueia o fluxo).
    """
    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)
    results: dict[str, str] = {}

    def _generate_and_save(fmt: str) -> tuple[str, str | None]:
        idx = dashboard.add_report_download(wname, scan_label, scan_id, fmt)
        last_error = ""

        for attempt in range(1, REPORT_DOWNLOAD_MAX_RETRIES + 1):
            try:
                if attempt > 1:
                    backoff_idx = min(attempt - 2, len(REPORT_DOWNLOAD_RETRY_BACKOFF) - 1)
                    wait = REPORT_DOWNLOAD_RETRY_BACKOFF[backoff_idx]
                    log(f"  {wname} [Report] Retry {attempt}/{REPORT_DOWNLOAD_MAX_RETRIES} "
                        f"para {fmt} em {wait}s...")
                    dashboard.update_report_download(
                        idx, "retrying", retry_count=attempt - 1,
                        error_message=f"Tentativa {attempt}/{REPORT_DOWNLOAD_MAX_RETRIES}",
                    )
                    time.sleep(wait)

                log(f"  {wname} [Report] Gerando {fmt} para scan {scan_id} "
                    f"(tentativa {attempt}/{REPORT_DOWNLOAD_MAX_RETRIES})...")
                result = qualys_service.generate_full_report(
                    scan_id=scan_id,
                    scan_target=scan_label,
                    report_format=fmt,
                )
                ext = fmt.lower()
                filename = f"{safe_filename(scan_label)}.{ext}"
                filepath = safe_filepath(REPORT_OUTPUT_DIR, filename)
                with open(filepath, "wb") as f:
                    f.write(result["content"])
                size_kb = len(result["content"]) / 1024
                log(f"  {wname} [Report] {fmt} salvo: {filename} ({size_kb:.1f} KB)")
                dashboard.update_report_download(idx, "done", filename, size_kb,
                                                 retry_count=attempt - 1)
                return fmt, filepath

            except Exception as e:
                last_error = str(e)
                log(f"  {wname} [Report] ERRO ao gerar {fmt} "
                    f"(tentativa {attempt}/{REPORT_DOWNLOAD_MAX_RETRIES}): {e}")

        # Todas as tentativas falharam
        log(f"  {wname} [Report] FALHA DEFINITIVA ao gerar {fmt} apos "
            f"{REPORT_DOWNLOAD_MAX_RETRIES} tentativas: {last_error}")
        dashboard.update_report_download(
            idx, "error", retry_count=REPORT_DOWNLOAD_MAX_RETRIES,
            error_message=last_error,
        )
        return fmt, None

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(_generate_and_save, fmt) for fmt in ("PDF", "CSV")]
        for f in futures:
            fmt, filepath = f.result()
            if filepath:
                results[fmt] = filepath

    return results


def _check_csv_has_findings(filepath: str) -> tuple[bool, str]:
    """
    Verifica se o CSV de report Qualys possui achados reais.
    Analisa a linha de SUMMARY (formato: "Risk","Vulns","Sensitive","InfoGathered").
    Retorna (tem_dados, descricao).
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                # Linha de summary: "Low","0","0","0" ou "High","5","0","3"
                if stripped.startswith('"') and any(
                    stripped.startswith(f'"{risk}"')
                    for risk in ("Low", "Medium", "High", "Minimal", "Urgent")
                ):
                    parts = [p.strip().strip('"') for p in stripped.split(",")]
                    if len(parts) >= 4:
                        try:
                            vulns = int(parts[1])
                            sensitive = int(parts[2])
                            info = int(parts[3])
                            total = vulns + sensitive + info
                            desc = f"Vulns={vulns} Sensitive={sensitive} Info={info}"
                            return total > 0, desc
                        except ValueError:
                            continue
    except Exception:
        pass
    return True, "formato nao reconhecido"


def _parse_csv_report_findings(filepath: str) -> dict[str, dict[str, int]]:
    """
    Extrai contagens de vulnerabilidades por criticidade do CSV de report Qualys.
    Analisa as linhas de SUMMARY: "Risk","Vulns","Sensitive","InfoGathered".
    Retorna dict com totais por severidade, ex:
    {
        "Urgent": {"vulns": 2, "sensitive": 0, "info": 1},
        "High": {"vulns": 5, "sensitive": 0, "info": 3},
        ...
        "_totals": {"vulns": 10, "sensitive": 2, "info": 8, "total": 20}
    }
    """
    severity_levels = ("Urgent", "High", "Medium", "Low", "Minimal")
    findings: dict[str, dict[str, int]] = {}
    totals = {"vulns": 0, "sensitive": 0, "info": 0, "total": 0}

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if not stripped.startswith('"'):
                    continue
                for risk in severity_levels:
                    if stripped.startswith(f'"{risk}"'):
                        parts = [p.strip().strip('"') for p in stripped.split(",")]
                        if len(parts) >= 4:
                            try:
                                vulns = int(parts[1])
                                sensitive = int(parts[2])
                                info = int(parts[3])
                                findings[risk] = {
                                    "vulns": vulns,
                                    "sensitive": sensitive,
                                    "info": info,
                                }
                                totals["vulns"] += vulns
                                totals["sensitive"] += sensitive
                                totals["info"] += info
                                totals["total"] += vulns + sensitive + info
                            except ValueError:
                                pass
                        break
    except Exception:
        pass

    findings["_totals"] = totals
    return findings


def _load_historical_vulns_background(qualys_service: QualysService) -> None:
    """
    Carrega dados de vulnerabilidades dos scans FINALIZADOS do mes de referencia atual.
    Consulta a API Qualys diretamente (GET /was/wasscan/{id}) para cada scan,
    extraindo contagens de vulnerabilidades por severidade.
    Executa em background thread e popula vulns_data progressivamente.
    """
    state = dashboard.get_state()
    # Usar scans do mes atual (api_scans_detail) ao inves de 12 meses
    scans_month = state.get("api", {}).get("scans_detail", [])
    if not scans_month:
        log("  [Vulns] Nenhum scan do mes atual retornado pela API. Nada a carregar.")
        return

    month_ref = date.today().strftime("%Y-%m")
    log(f"  [Vulns] Consultando vulnerabilidades de {len(scans_month)} scan(s) do mes {month_ref} via API (background)...")

    loaded = 0
    errors = 0
    max_workers = min(8, len(scans_month))

    def _fetch_scan_vulns(scan: dict) -> dict | None:
        """Consulta vulns de um scan via API e retorna entry para vulns_data."""
        scan_name = scan.get("name", "")
        scan_id = str(scan.get("id", ""))
        if not scan_name or not scan_id:
            return None

        # Tentar download completo (retorna counts + detalhes de vulns/igs)
        finding_details = []
        full_result = qualys_service.get_scan_findings_full(scan_id)
        if full_result:
            findings = full_result["findings"]
            finding_details = full_result.get("finding_details", [])
        else:
            # Fallback: summary-only (apenas contagens)
            findings = qualys_service.get_scan_vulns_summary(scan_id)
            if findings is None:
                return None
            findings.pop("status", None)

        # Extrair URL e porta do nome do scan (formato: "YYYYMM example.com 443")
        parts = scan_name.split()
        url = ""
        port = None
        if len(parts) >= 2:
            dns = parts[1]
            port = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 443
            url = f"https://{dns}:{port}" if port else f"https://{dns}"

        launched = scan.get("launched", "")
        finished_date = launched[:10] if len(launched) >= 10 else ""
        finished_at = launched[11:19] if len(launched) >= 19 else ""

        return {
            "scan_label": scan_name,
            "url": url,
            "worker": scan.get("worker", ""),
            "worker_id": None,
            "scan_id": scan_id,
            "port": port,
            "finished_date": finished_date,
            "finished_at": finished_at,
            "findings": findings,
            "finding_details": finding_details,
            "source": "historico",
        }

    # Processar em lotes paralelos, adicionando progressivamente ao dashboard
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_fetch_scan_vulns, scan): scan
            for scan in scans_month
        }
        for future in futures:
            scan = futures[future]
            try:
                entry = future.result()
                if entry:
                    dashboard.add_vulns_entry(entry)
                    loaded += 1
                    entry_totals = (entry.get("findings") or {}).get("_totals", {})
                    total_vulns = entry_totals.get("total", 0)
                    # Logar os primeiros 3 scans com detalhes para diagnostico
                    if loaded <= 3:
                        log(f"  [Vulns] Scan {entry.get('scan_label', '?')}: {total_vulns} finding(s) (vulns={entry_totals.get('vulns', 0)}, info={entry_totals.get('info', 0)})")
                    if loaded % 10 == 0 or loaded == len(scans_month):
                        log(f"  [Vulns] Progresso: {loaded}/{len(scans_month)} scan(s) carregados...")
                else:
                    errors += 1
                    scan_name = scan.get("name", "?")
                    log(f"  [Vulns] Scan {scan_name}: sem dados retornados pela API")
            except Exception as e:
                errors += 1
                scan_name = scan.get("name", "?")
                log(f"  [Vulns] Erro ao consultar scan {scan_name}: {e}")

    log(f"  [Vulns] Carga mes atual concluida: {loaded} scan(s) carregados | {errors} erro(s) | total na aba: {len(dashboard.vulns_data)}")


def _check_workers_availability(qualys_service: QualysService) -> None:
    """
    Verifica disponibilidade dos workers e popula o estado.
    Permite que o dashboard mostre o status dos workers antes de iniciar scans.
    """
    hoje = date.today().isoformat()
    log("  [Workers] Verificando disponibilidade dos workers...")

    def _check_worker(wname: str, wid: int) -> tuple[str, int, bool, str | None]:
        running = qualys_service.check_running_scans(wid, hoje)
        is_busy = len(running) > 0
        current_url = None
        if is_busy:
            info = qualys_service.get_scan_info(wid)
            current_url = info.get("url", "")
        return wname, wid, is_busy, current_url

    with ThreadPoolExecutor(max_workers=len(QUALYS_SCAN_WEBAPPS)) as executor:
        futures = [
            executor.submit(_check_worker, wname, wid)
            for wname, wid in QUALYS_SCAN_WEBAPPS.items()
        ]
        available = 0
        busy = 0
        for f in futures:
            wname, wid, is_busy, current_url = f.result()
            if is_busy:
                dashboard.mark_worker_waiting(wname, current_url or "")
                log(f"  [Workers] {wname}: Ocupado (URL: {current_url})")
                busy += 1
            else:
                dashboard.mark_worker_available(wname)
                log(f"  [Workers] {wname}: Disponivel")
                available += 1

    log(f"  [Workers] Status: {available} disponivel(is) | {busy} ocupado(s) | Total: {len(QUALYS_SCAN_WEBAPPS)}")


def _start_vulns_background_load(qualys_service: QualysService) -> None:
    """Inicia a carga de vulns historicas em background thread."""
    thread = threading.Thread(
        target=_load_historical_vulns_background,
        args=(qualys_service,),
        daemon=True,
        name="vulns-history-loader",
    )
    thread.start()
    log("  [Vulns] Thread de carga do mes atual iniciada (dados aparecerao progressivamente na aba Vulns).")


def _validate_and_recover_reports(qualys_service: QualysService) -> dict:
    """
    Validacao pos-loop: verifica se todos os scans concluidos possuem
    PDF e CSV no disco. Tenta re-download dos faltantes usando scan_id.
    Tambem verifica se os CSVs possuem achados reais (nao apenas headers).
    Retorna dict com resultados da validacao para o dashboard.
    """
    state = dashboard.get_state()
    completed = state["completed"]

    if not completed:
        return {"ran": True, "total_scans": 0, "total_expected_files": 0,
                "missing_files": [], "recovered_count": 0, "still_missing_count": 0,
                "empty_reports": []}

    log("\n  [Validacao] Verificando reports no disco...")
    missing_files: list[dict] = []
    empty_reports: list[dict] = []

    for item in completed:
        scan_label = item.get("scan_label", "")
        scan_id = item.get("scan_id", "")
        if not scan_label:
            continue
        for fmt in ("pdf", "csv"):
            filename = f"{safe_filename(scan_label)}.{fmt}"
            filepath = safe_filepath(REPORT_OUTPUT_DIR, filename)
            if not os.path.isfile(filepath):
                missing_files.append({
                    "scan_label": scan_label, "scan_id": scan_id,
                    "format": fmt.upper(), "filepath": filepath,
                    "recovered": False, "error": "",
                })
            elif os.path.getsize(filepath) == 0:
                missing_files.append({
                    "scan_label": scan_label, "scan_id": scan_id,
                    "format": fmt.upper(), "filepath": filepath,
                    "recovered": False, "error": "Arquivo vazio (0 bytes)",
                })

        # Verificar conteudo do CSV (achados reais)
        csv_path = safe_filepath(REPORT_OUTPUT_DIR, f"{safe_filename(scan_label)}.csv")
        if os.path.isfile(csv_path) and os.path.getsize(csv_path) > 0:
            has_findings, summary = _check_csv_has_findings(csv_path)
            if not has_findings:
                empty_reports.append({
                    "scan_label": scan_label, "scan_id": scan_id,
                    "summary": summary,
                })
                log(f"  [Validacao] AVISO: {scan_label} - report sem achados ({summary})")
                dashboard.mark_warning(
                    item.get("url", scan_label),
                    "report sem achados",
                    details=f"O scan finalizou mas nao gerou vulnerabilidades ou informacoes. {summary}",
                )

    total_scans = len(completed)
    total_expected = total_scans * 2

    if not missing_files:
        msg = f"  [Validacao] OK - Todos os {total_expected} arquivos presentes ({total_scans} scans x 2 formatos)"
        if empty_reports:
            msg += f" | {len(empty_reports)} scan(s) sem achados"
        log(msg)
        return {"ran": True, "total_scans": total_scans,
                "total_expected_files": total_expected,
                "missing_files": [], "recovered_count": 0, "still_missing_count": 0,
                "empty_reports": empty_reports}

    log(f"  [Validacao] {len(missing_files)} arquivo(s) faltando. Tentando re-download...")
    recovered = 0

    for mf in missing_files:
        scan_id = mf["scan_id"]
        fmt = mf["format"]
        scan_label = mf["scan_label"]

        if not scan_id:
            mf["error"] = "scan_id indisponivel - impossivel re-download"
            log(f"  [Validacao] SKIP {scan_label} {fmt}: scan_id indisponivel")
            continue

        log(f"  [Validacao] Re-download: {scan_label} {fmt} (scan_id={scan_id})...")
        idx = dashboard.add_report_download("Validacao", scan_label, scan_id, fmt)

        for attempt in range(1, REPORT_DOWNLOAD_MAX_RETRIES + 1):
            try:
                if attempt > 1:
                    backoff_idx = min(attempt - 2, len(REPORT_DOWNLOAD_RETRY_BACKOFF) - 1)
                    wait = REPORT_DOWNLOAD_RETRY_BACKOFF[backoff_idx]
                    log(f"  [Validacao] Retry {attempt}/{REPORT_DOWNLOAD_MAX_RETRIES} "
                        f"para {scan_label} {fmt} em {wait}s...")
                    dashboard.update_report_download(
                        idx, "retrying", retry_count=attempt - 1,
                        error_message=f"Tentativa {attempt}/{REPORT_DOWNLOAD_MAX_RETRIES}",
                    )
                    time.sleep(wait)

                result = qualys_service.generate_full_report(
                    scan_id=scan_id,
                    scan_target=scan_label,
                    report_format=fmt,
                )
                filepath = mf["filepath"]
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                with open(filepath, "wb") as f:
                    f.write(result["content"])
                size_kb = len(result["content"]) / 1024
                log(f"  [Validacao] RECUPERADO: {scan_label}.{fmt.lower()} ({size_kb:.1f} KB)")
                mf["recovered"] = True
                mf["error"] = ""
                recovered += 1
                dashboard.update_report_download(
                    idx, "done", f"{scan_label}.{fmt.lower()}", size_kb,
                    retry_count=attempt - 1,
                )
                break

            except Exception as e:
                mf["error"] = str(e)
                log(f"  [Validacao] ERRO tentativa {attempt}/{REPORT_DOWNLOAD_MAX_RETRIES} "
                    f"para {scan_label} {fmt}: {e}")
        else:
            log(f"  [Validacao] FALHA DEFINITIVA: {scan_label} {fmt} - {mf['error']}")
            dashboard.update_report_download(
                idx, "error", retry_count=REPORT_DOWNLOAD_MAX_RETRIES,
                error_message=mf["error"],
            )

    still_missing = len(missing_files) - recovered
    msg = (f"  [Validacao] Resultado: {recovered} recuperado(s), "
           f"{still_missing} ainda faltando de {len(missing_files)} total")
    if empty_reports:
        msg += f" | {len(empty_reports)} scan(s) sem achados"
    log(msg)

    return {
        "ran": True, "total_scans": total_scans,
        "total_expected_files": total_expected,
        "missing_files": [
            {k: v for k, v in mf.items() if k != "filepath"}
            for mf in missing_files
        ],
        "recovered_count": recovered,
        "still_missing_count": still_missing,
        "empty_reports": empty_reports,
    }


def _fetch_api_data(qualys_service: QualysService, scan_tracker: ScanTracker | None = None) -> ScanTracker:
    """
    Busca dados da API Qualys (WebApps, profiles, scans) e popula o dashboard.
    Se scan_tracker fornecido, reutiliza. Senao, cria e carrega.
    Retorna o scan_tracker para reuso.
    """
    month_ref = date.today().strftime("%Y-%m")

    # WebApps (paralelo)
    def _fetch_webapp_info(scan_name: str, webapp_id: int) -> dict:
        info = qualys_service.get_scan_info(webapp_id)
        return {"name": scan_name, "id": webapp_id, "url": info.get("url", "N/A")}

    webapps_info = []
    with ThreadPoolExecutor(max_workers=len(QUALYS_SCAN_WEBAPPS)) as executor:
        futures = [
            executor.submit(_fetch_webapp_info, sn, wid)
            for sn, wid in QUALYS_SCAN_WEBAPPS.items()
        ]
        for f in futures:
            webapps_info.append(f.result())
    for wi in webapps_info:
        log(f"  {wi['name']} (ID: {wi['id']}): URL atual = {wi['url']}")

    # Option Profiles + Scans finalizados (em paralelo)
    log("  Buscando Option Profiles e historico de scans...")
    if not scan_tracker:
        scan_tracker = ScanTracker(qualys_service)
        needs_load = True
    else:
        needs_load = False

    with ThreadPoolExecutor(max_workers=2) as executor:
        profile_future = executor.submit(qualys_service.get_option_profiles)
        if needs_load:
            tracker_future = executor.submit(scan_tracker.load_all)

        profiles = profile_future.result()
        if needs_load:
            tracker_future.result()

    for p in profiles:
        log(f"  Profile: {p['name']} (ID: {p['id']})")
    scanned_urls = scan_tracker.get_scanned_urls()
    log(f"  Mes de referencia: {month_ref}")
    log(f"  Scans finalizados no mes (API): {scan_tracker.get_scanned_count()}")

    # Enviar dados ao dashboard
    dashboard.set_api_data(
        webapps=webapps_info,
        profiles=profiles,
        scanned_month=scanned_urls,
        scans_detail=scan_tracker.get_scans_detail(),
        month_ref=month_ref,
        scans_all_history=scan_tracker.get_scans_all_history(),
    )
    return scan_tracker


def main():
    # Validar configuracao antes de qualquer coisa
    if not QUALYS_SCAN_WEBAPPS:
        print(
            "ERRO: Nenhum worker configurado.\n"
            "Defina ao menos uma variavel de ambiente no formato:\n"
            "  QUALYS_WORKER_<NOME>=<ID numerico>\n"
            "Exemplo:\n"
            "  QUALYS_WORKER_VULN1=123456789\n"
            "  QUALYS_WORKER_VULN2=987654321"
        )
        raise SystemExit(1)

    # 1. Iniciar servidor web PRIMEIRO (dashboard acessivel imediatamente)
    log("=" * 60)
    log("  QUALYS SCHEDULE - Automacao de Validacao")
    log("=" * 60)
    log(f"  Workers configurados: {len(QUALYS_SCAN_WEBAPPS)}")
    for wname, wid in QUALYS_SCAN_WEBAPPS.items():
        log(f"    {wname} (ID: {wid})")
    if SCAN_PROFILE_ID:
        log(f"  Option Profile ID: {SCAN_PROFILE_ID}")
    start_dashboard_server(WEB_PORT)
    log(f"\n  Dashboard: http://localhost:{WEB_PORT}")
    log("  Aguardando autenticacao...")

    # Aguardar usuario se autenticar no dashboard
    dashboard.wait_for_auth()
    log("  Autenticacao realizada com sucesso!")

    # Credenciais persistem entre ciclos
    creds = dashboard.auth_credentials
    username = creds.get("username", "")
    password = creds.get("password", "")

    # Buscar dados da API imediatamente apos autenticacao
    log("  Consultando dados da API Qualys...")
    qualys_client = QualysClient(username, password)
    qualys_service = QualysService(qualys_client)
    set_qualys_service(qualys_service)
    _fetch_api_data(qualys_service)

    # Verificar disponibilidade dos workers (exibe no dashboard antes de iniciar scans)
    _check_workers_availability(qualys_service)

    # Carregar vulns do mes atual via API em background
    # Os dados aparecem progressivamente na aba Vulns sem precisar iniciar scans
    _start_vulns_background_load(qualys_service)

    # Loop principal: permite reiniciar a rotina apos finalizacao
    cycle = 0
    while True:
        cycle += 1
        if cycle > 1:
            log("\n" + "=" * 60)
            log(f"  NOVA EXECUCAO (ciclo {cycle})")
            log("=" * 60)
            # Atualizar dados da API ao reiniciar
            _fetch_api_data(qualys_service)
            # Verificar disponibilidade dos workers
            _check_workers_availability(qualys_service)
            # Recarregar vulns do mes atual via API em background
            _start_vulns_background_load(qualys_service)

        log("  Aguardando URLs e inicio via dashboard...")
        dashboard.wait_for_start()
        log("\n  Inicio solicitado via dashboard!")

        run_scan_cycle(qualys_service)

        # Aguardar restart ou Ctrl+C
        log("  Aguardando nova execucao ou Ctrl+C para encerrar...")
        try:
            while dashboard.phase == dashboard.PHASE_FINISHED:
                time.sleep(1)
            # Se saiu do loop, o phase mudou para READY (restart foi chamado)
            log("  Reinicio solicitado via dashboard!")
        except KeyboardInterrupt:
            log("Encerrando...")
            break


def run_scan_cycle(qualys_service: QualysService) -> None:
    """Executa um ciclo completo de scans."""
    # 1. URLs recebidas via dashboard
    urls = list(dashboard.input_urls)
    force_rescan_active = list(dashboard._force_rescan_urls) if dashboard._force_rescan_urls else []
    log(f"\n[1/2] {len(urls)} URLs recebidas via dashboard")
    if force_rescan_active:
        log(f"  [Re-scan] {len(force_rescan_active)} URL(s) marcadas para re-scan forcado: {', '.join(force_rescan_active)}")
    for u in urls:
        log(f"  URL: {u}")
    if not urls:
        log("  Nenhuma URL informada. Abortando ciclo.")
        dashboard.set_phase(dashboard.PHASE_FINISHED)
        return

    # 2. Atualizar dados da API (scans podem ter mudado)
    log("\n[2/2] Atualizando dados da API Qualys...")
    scan_tracker = ScanTracker(qualys_service)
    scan_tracker.load_all()
    _fetch_api_data(qualys_service, scan_tracker)

    # Recarregar vulns historicas (12 meses) via API em background
    _start_vulns_background_load(qualys_service)

    month_ref = date.today().strftime("%Y-%m")
    scan_profile_id = SCAN_PROFILE_ID

    # Validacao mensal sera feita apos afinidade (dentro do loop de atribuicao)
    log(f"  {len(urls)} URLs para processar")

    dashboard.set_total_urls(urls)

    # --- Transicionar para fase RUNNING ---
    dashboard.set_phase(dashboard.PHASE_RUNNING)
    log("\n" + "=" * 60)
    log("  Orquestrando scans automaticos...")
    log("=" * 60)

    hoje = date.today().isoformat()
    hoje_compact = date.today().strftime("%Y%m")
    url_queue = list(urls)
    total_urls = len(url_queue)
    processed = 0
    skipped = []
    url_preferred_worker: dict[str, str] = {}  # dns -> worker (preenchido na Fase 3)

    # Validar e corrigir Scanner Appliance Type dos workers (EXTERNAL)
    log("  Validando Scanner Appliance Type dos workers...")

    def _ensure_external(wname: str, wid: int) -> tuple[str, int, bool]:
        ok = qualys_service.ensure_external_scanner(wid)
        return wname, wid, ok

    with ThreadPoolExecutor(max_workers=len(QUALYS_SCAN_WEBAPPS)) as executor:
        scanner_futures = [
            executor.submit(_ensure_external, wn, wid)
            for wn, wid in QUALYS_SCAN_WEBAPPS.items()
        ]
        for f in scanner_futures:
            wname, wid, ok = f.result()
            if ok:
                log(f"  {wname}: Scanner Appliance = EXTERNAL (OK)")
            else:
                log(f"  {wname}: AVISO - Nao foi possivel garantir Scanner EXTERNAL")

    # Inicializar workers em paralelo (cada WebApp eh um worker)
    def _init_worker(wname: str, wid: int) -> tuple[str, int, bool, str | None]:
        running = qualys_service.check_running_scans(wid, hoje)
        is_busy = len(running) > 0
        current_url = None
        if is_busy:
            info = qualys_service.get_scan_info(wid)
            current_url = info.get("url", "")
        return wname, wid, is_busy, current_url

    workers = {}
    urls_em_scan = set()
    with ThreadPoolExecutor(max_workers=len(QUALYS_SCAN_WEBAPPS)) as executor:
        init_futures = [
            executor.submit(_init_worker, wname, wid)
            for wname, wid in QUALYS_SCAN_WEBAPPS.items()
        ]
        for f in init_futures:
            wname, wid, is_busy, current_url = f.result()
            if is_busy:
                if current_url:
                    urls_em_scan.add(_extract_dns(current_url))
                log(f"  {wname}: Aguardando scan em andamento finalizar... (URL: {current_url})")
                dashboard.mark_worker_waiting(wname, current_url or "")
            else:
                log(f"  {wname}: Disponivel")
                dashboard.mark_worker_available(wname)
            workers[wname] = {"id": wid, "busy": is_busy, "current_url": current_url}

    # Funcao de verificacao de status (definida fora do loop para evitar recriacao)
    def _check_worker_status(wname: str, winfo: dict) -> tuple[str, list[dict]]:
        return wname, qualys_service.check_running_scans(winfo["id"], hoje)

    while url_queue or any(w["busy"] for w in workers.values()):
        # Verificar se ha novas URLs adicionadas via dashboard
        new_urls = dashboard.pop_additional_urls()
        if new_urls:
            for new_url in new_urls:
                if scan_tracker.is_scanned_this_month(new_url) and not dashboard.is_force_rescan(new_url):
                    log(f"  URL adicional ignorada (ja escaneada em {month_ref}): {new_url}")
                    dashboard.mark_skipped(new_url, f"ja escaneada em {month_ref}")
                elif new_url not in url_queue:
                    url_queue.append(new_url)
                    dashboard.add_to_pending(new_url)
                    log(f"  URL adicional adicionada a fila: {new_url}")
            total_urls = processed + len(url_queue) + sum(1 for w in workers.values() if w["busy"])

        # ── Fase 1+2: Verificar status de TODOS os workers em paralelo ──
        with ThreadPoolExecutor(max_workers=len(workers)) as executor:
            status_futures = [
                executor.submit(_check_worker_status, wn, wi)
                for wn, wi in workers.items()
            ]
            worker_statuses = [f.result() for f in status_futures]

        # Separar workers finalizados e livres
        finished_workers: list[tuple[str, dict]] = []
        for wname, running in worker_statuses:
            winfo = workers[wname]
            if winfo["busy"]:
                # Fase 1: Worker ocupado — verificar se terminou
                if not running:
                    # Confirmar status real do scan antes de declarar finalizado
                    scan_id = winfo.get("scan_id")
                    if scan_id:
                        real_status = qualys_service.get_scan_status(scan_id)
                        if real_status is None:
                            # Erro ao consultar API — nao tratar como finalizado
                            log(f"  {wname}: Nao foi possivel confirmar status do scan {scan_id}. Mantendo como ativo...")
                            continue
                        if real_status not in ("FINISHED", "CANCELED", "ERROR"):
                            # Scan ainda em andamento (RUNNING, SUBMITTED, etc.)
                            log(f"  {wname}: Scan {scan_id} status real = {real_status}. Ainda em andamento...")
                            continue
                        log(f"  {wname}: Scan {scan_id} confirmado como {real_status}.")
                    finished_workers.append((wname, winfo))
            else:
                # Fase 2: Worker livre — verificar se scan externo apareceu
                if not url_queue:
                    continue
                if running:
                    info = qualys_service.get_scan_info(winfo["id"])
                    winfo["busy"] = True
                    winfo["current_url"] = info.get("url", "")
                    if winfo["current_url"]:
                        dns_busy = _extract_dns(winfo["current_url"])
                        urls_em_scan.add(dns_busy)
                    log(f"  {wname}: Scan em andamento detectado. Aguardando...")
                    dashboard.mark_worker_waiting(wname, winfo["current_url"] or "")

        # Fase 1: Baixar reports dos workers finalizados (em paralelo) antes de liberar
        if finished_workers:
            def _report_for_worker(wname: str, winfo: dict) -> tuple[str, dict, dict]:
                sid = winfo.get("scan_id")
                slabel = winfo.get("scan_label", "")
                report_results: dict[str, str] = {}
                if sid and slabel:
                    log(f"  {wname}: Scan finalizado - Baixando reports...")
                    report_results = _download_scan_reports(qualys_service, sid, slabel, wname)
                return wname, winfo, report_results

            with ThreadPoolExecutor(max_workers=len(finished_workers)) as executor:
                report_futures = [
                    executor.submit(_report_for_worker, wn, wi)
                    for wn, wi in finished_workers
                ]
                for f in report_futures:
                    wn, wi, rr = f.result()
                    wi["report_results"] = rr

            # Agora liberar os workers (apos todos os downloads)
            for wname, winfo in finished_workers:
                if winfo["current_url"]:
                    finished_dns = _extract_dns(winfo["current_url"])
                    urls_em_scan.discard(finished_dns)
                    processed += 1
                    # Avisar se reports faltaram
                    rr = winfo.get("report_results", {})
                    missing_fmts = {"PDF", "CSV"} - set(rr.keys())
                    if missing_fmts:
                        log(f"  {wname}: AVISO - Reports faltando: {', '.join(sorted(missing_fmts))}")
                    log(f"  {wname}: Concluido ({processed}/{total_urls}) - {winfo['current_url']}")
                    dashboard.mark_completed(wname, winfo["current_url"])

                    # Atualizar vulns_data progressivamente (aba Vulns atualiza em tempo real)
                    scan_label = winfo.get("scan_label", "")
                    scan_id = winfo.get("scan_id", "")
                    if scan_label and scan_id:
                        finding_details = []
                        # Tentar download completo (counts + detalhes vulns/igs)
                        full_result = qualys_service.get_scan_findings_full(scan_id)
                        if full_result:
                            findings = full_result["findings"]
                            finding_details = full_result.get("finding_details", [])
                        else:
                            # Fallback: summary-only (apenas contagens)
                            findings = qualys_service.get_scan_vulns_summary(scan_id)
                            if findings is None:
                                # Fallback: tentar ler do CSV baixado
                                csv_path = safe_filepath(REPORT_OUTPUT_DIR, f"{safe_filename(scan_label)}.csv")
                                if os.path.isfile(csv_path):
                                    findings = _parse_csv_report_findings(csv_path)
                                    log(f"  [Vulns] Dados obtidos do CSV (fallback): {scan_label}")
                                else:
                                    log(f"  [Vulns] Nao foi possivel obter dados de vulns para {scan_label}")
                            else:
                                findings.pop("status", None)

                        if findings:
                            total_achados = findings.get("_totals", {}).get("total", 0)
                            label_parts = scan_label.split()
                            scan_port = int(label_parts[-1]) if label_parts and label_parts[-1].isdigit() else 443
                            dashboard.add_vulns_entry({
                                "scan_label": scan_label,
                                "url": winfo["current_url"],
                                "worker": wname,
                                "worker_id": winfo.get("id"),
                                "scan_id": scan_id,
                                "port": scan_port,
                                "finished_date": hoje,
                                "finished_at": "",
                                "findings": findings,
                                "finding_details": finding_details,
                            })
                            log(f"  [Vulns] Scan adicionado a aba Vulns: {scan_label} | {total_achados} achado(s) | total na aba: {len(dashboard.vulns_data)}")

                winfo["busy"] = False
                winfo["current_url"] = None
                winfo.pop("scan_id", None)
                winfo.pop("scan_label", None)
                winfo.pop("report_results", None)

        # ── Fase 2: Validacao mensal — descartar URLs ja escaneadas no mes ──
        month_skipped = []
        for raw_url in url_queue:
            dns = _extract_dns(raw_url)
            if scan_tracker.is_scanned_this_month(raw_url):
                if dashboard.is_force_rescan(raw_url):
                    log(f"  {dns} ja escaneada em {month_ref}, mas marcada para RE-SCAN forcado.")
                    dashboard.remove_force_rescan(raw_url)
                else:
                    log(f"  {dns} ja escaneada em {month_ref}. Descartando...")
                    dashboard.mark_skipped(dns, f"ja escaneada em {month_ref}")
                    skipped.append(f"{dns} (ja escaneada em {month_ref})")
                    dashboard.remove_from_pending(raw_url)
                    month_skipped.append(raw_url)
        for u in month_skipped:
            url_queue.remove(u)

        # ── Fase 3: Verificar afinidade e atribuir URLs a workers ──
        # 3a. Verificar afinidade para URLs na fila que ainda nao foram checadas
        for raw_url in url_queue:
            dns = _extract_dns(raw_url)
            if dns in url_preferred_worker:
                continue  # Ja verificado
            preferred = scan_tracker.find_last_worker_for_url(dns)
            if preferred:
                url_preferred_worker[dns] = preferred
                log(f"  [Afinidade] {dns} -> ultimo scan em: {preferred}")
            else:
                url_preferred_worker[dns] = ""  # Marca como verificado, sem historico
                log(f"  [Afinidade] {dns} -> sem historico (qualquer worker livre)")

        # 3b. Atribuir URLs a workers respeitando afinidade
        assignments = _assign_urls_to_workers(
            url_queue, workers, url_preferred_worker, urls_em_scan,
        )

        for raw_url, wname, wid in assignments:
            winfo = workers[wname]
            dns = _extract_dns(raw_url)

            # Log da atribuicao com motivo
            if url_preferred_worker.get(dns):
                log(f"  {wname}: {dns} (afinidade - ultimo scan foi neste worker)")
            else:
                log(f"  {wname}: {dns} (sem historico - worker livre atribuido)")

            log(f"  {wname}: Validando portas para {dns}...")
            dashboard.remove_from_pending(raw_url)

            url, port, dns_err, port_details = resolve_port(dns)

            if dns_err:
                skipped.append(f"{dns} (erro DNS)")
                log(f"  {wname}: {dns_err}. Pulando...")
                dns_details = f"Erro DNS: {dns_err}"
                dashboard.mark_skipped(dns, "Erro DNS", dns_details)
                continue

            # Log dos detalhes da validacao
            p443 = port_details[443]
            p80 = port_details[80]
            port_info = f"443: {p443.status} [{p443.remote_address}] | 80: {p80.status} [{p80.remote_address}]"
            if p443.tcp_test_succeeded:
                log(f"    443: OK [{p443.remote_address}] | 80: {p80.status} [{p80.remote_address}]")
            elif p80.tcp_test_succeeded:
                log(f"    443: Falha | 80: OK [{p80.remote_address}]")
            else:
                log(f"    443: Falha | 80: Falha -> Default porta 80")

            # Registrar URLs que nao responderam em nenhuma porta (apenas acompanhamento)
            if not p443.tcp_test_succeeded and not p80.tcp_test_succeeded:
                dashboard.mark_warning(dns, "Portas 443/80 sem resposta (scan enviado com default 80)", port_info)

            log(f"  {wname}: Atualizando URL para {url}...")
            updated = qualys_service.update_scan_url(wid, url)
            if not updated:
                skipped.append(dns)
                log(f"  {wname}: ERRO ao atualizar URL para {url}. Pulando...")
                dashboard.mark_skipped(dns, "erro ao atualizar URL")
                continue

            time.sleep(10)

            scan_label = f"{hoje_compact} {dns} {port}"
            log(f"  {wname}: Lancando scan {scan_label}...")
            scan_id = qualys_service.launch_scan(wid, scan_label, scan_profile_id)
            if scan_id:
                winfo["busy"] = True
                winfo["current_url"] = url
                winfo["scan_id"] = scan_id
                winfo["scan_label"] = scan_label
                urls_em_scan.add(dns.lower())
                log(f"  {wname}: Scan lancado -> {scan_label} (ID: {scan_id})")
                dashboard.mark_scanning(
                    wname, url, port,
                    scan_label=scan_label,
                    scan_id=scan_id,
                    worker_id=wid,
                )
            else:
                skipped.append(dns)
                log(f"  {wname}: ERRO ao lancar scan para {url}. Pulando...")
                dashboard.mark_skipped(dns, "erro ao lancar scan")

        # Aguardar antes de verificar novamente
        if url_queue or any(w["busy"] for w in workers.values()):
            interval_min = SCAN_CHECK_INTERVAL // 60
            log(f"  ... Aguardando {interval_min}min (fila: {len(url_queue)} | ativos: "
                f"{sum(1 for w in workers.values() if w['busy'])})")
            time.sleep(SCAN_CHECK_INTERVAL)

    # Validacao pos-loop: verificar reports no disco e tentar re-download
    log("\n[Validacao] Verificando integridade dos reports...")
    validation = _validate_and_recover_reports(qualys_service)
    dashboard.set_report_validation(validation)
    if validation.get("still_missing_count", 0) > 0:
        log(f"  ATENCAO: {validation['still_missing_count']} report(s) nao puderam "
            f"ser recuperados. Verifique o dashboard para detalhes.")

    # Gerar export CSV dos resultados
    export_csv = generate_export_csv()
    dashboard.set_export_data(export_csv)

    # Resumo final
    dashboard.set_phase(dashboard.PHASE_FINISHED)
    log("\n" + "=" * 60)
    log("  CONCLUIDO!")
    log(f"  Scans realizados: {processed}")
    if skipped:
        log(f"  URLs ignoradas ({len(skipped)}):")
        for s in skipped:
            log(f"    - {s}")
    log("  Export dos resultados disponivel no dashboard.")
    log("  Clique em 'Iniciar Nova Rotina' para executar novamente.")
    log("=" * 60)

    # Salvar logs do ciclo em arquivo txt
    _save_cycle_logs()


def _save_cycle_logs() -> str | None:
    """
    Salva todos os logs do ciclo atual em um arquivo txt.
    Nome do arquivo inclui data e hora: qualys_log_YYYY-MM-DD_HHMMSS.txt
    Retorna o filepath gerado ou None em caso de erro.
    """
    from datetime import datetime
    os.makedirs(LOG_OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    filename = f"qualys_log_{timestamp}.txt"
    filepath = os.path.join(LOG_OUTPUT_DIR, filename)

    state = dashboard.get_state()
    logs = state.get("logs", [])
    if not logs:
        return None

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            for entry in logs:
                ts = entry.get("timestamp", "")
                msg = entry.get("message", "")
                f.write(f"[{ts}] {msg}\n")
        log(f"  Logs salvos em: {filepath}")
        return filepath
    except OSError as e:
        log(f"  Erro ao salvar logs: {e}")
        return None


def _assign_urls_to_workers(
    url_queue: list[str],
    workers: dict[str, dict],
    url_preferred_worker: dict[str, str],
    urls_em_scan: set[str],
) -> list[tuple[str, str, str]]:
    """
    Atribui URLs da fila a workers livres, respeitando afinidade estrita.

    Regras:
      1. URL com afinidade → so roda no worker preferido. Se ocupado, fica na fila.
      2. URL sem afinidade → usa qualquer worker livre.
      3. Se URL ja esta em scan ativo, pula (fica na fila).

    Retorna lista de (raw_url, worker_name, worker_id) para processar.
    Remove as URLs atribuidas da url_queue.
    """
    free_workers = {
        wname for wname, winfo in workers.items()
        if not winfo["busy"]
    }

    assignments: list[tuple[str, str, str]] = []
    skipped_indices: set[int] = set()

    for i, raw_url in enumerate(url_queue):
        if not free_workers:
            break

        dns = _extract_dns(raw_url)

        # URL ja em scan ativo em outro worker — manter na fila
        if dns in urls_em_scan:
            continue

        preferred = url_preferred_worker.get(dns)

        if preferred:
            # Afinidade definida: so usar o worker preferido
            if preferred in free_workers:
                assignments.append((raw_url, preferred, workers[preferred]["id"]))
                free_workers.discard(preferred)
                skipped_indices.add(i)
            # Se preferido esta ocupado, URL fica na fila (nao marca indice)
        else:
            # Sem afinidade: usar qualquer worker livre
            worker_name = next(iter(free_workers))
            assignments.append((raw_url, worker_name, workers[worker_name]["id"]))
            free_workers.discard(worker_name)
            skipped_indices.add(i)

    # Remover URLs atribuidas da fila (de tras para frente)
    for i in sorted(skipped_indices, reverse=True):
        url_queue.pop(i)

    return assignments


def generate_export_csv() -> str:
    """Gera CSV com resultados dos scans, incluindo vulnerabilidades por criticidade."""
    state = dashboard.get_state()
    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")
    severity_cols = ["Urgent", "High", "Medium", "Low", "Minimal"]
    writer.writerow([
        "Nome do Scan", "URL", "Porta", "Worker", "Worker ID",
        "Scan ID", "Status", "Data Finalizado", "Horario",
        *severity_cols, "Total Vulns", "Sensitive", "Info Gathered", "Total Achados",
    ])

    vulns_data: list[dict] = []

    for item in state["completed"]:
        scan_label = item.get("scan_label", "")
        # Ler vulnerabilidades do CSV de report no disco
        findings = {}
        if scan_label:
            csv_path = safe_filepath(REPORT_OUTPUT_DIR, f"{safe_filename(scan_label)}.csv")
            if os.path.isfile(csv_path):
                findings = _parse_csv_report_findings(csv_path)

        # Coletar dados de vulnerabilidades para o dashboard vulns
        vulns_data.append({
            "scan_label": scan_label,
            "url": item.get("url", ""),
            "worker": item.get("worker", ""),
            "worker_id": item.get("worker_id"),
            "scan_id": item.get("scan_id", ""),
            "port": item.get("port"),
            "finished_date": item.get("finished_date", ""),
            "finished_at": item.get("finished_at", ""),
            "findings": findings,
        })

        totals = findings.get("_totals", {})
        severity_values = [
            findings.get(sev, {}).get("vulns", "") for sev in severity_cols
        ]
        writer.writerow([
            scan_label,
            item.get("url", ""),
            item.get("port", ""),
            item.get("worker", ""),
            item.get("worker_id", ""),
            item.get("scan_id", ""),
            "Concluido",
            item.get("finished_date", ""),
            item.get("finished_at", ""),
            *severity_values,
            totals.get("vulns", ""),
            totals.get("sensitive", ""),
            totals.get("info", ""),
            totals.get("total", ""),
        ])

    # Mesclar com dados historicos ja carregados no vulns_data (via API background loader)
    # Evitar duplicatas: scans do ciclo atual tem prioridade
    current_labels = {v["scan_label"] for v in vulns_data if v.get("scan_label")}
    current_scan_ids = {v["scan_id"] for v in vulns_data if v.get("scan_id")}
    existing_vulns = state.get("vulns_data", [])
    hist_count = 0

    for existing in existing_vulns:
        label = existing.get("scan_label", "")
        sid = existing.get("scan_id", "")
        if label in current_labels or sid in current_scan_ids:
            continue
        vulns_data.append(existing)
        hist_count += 1

    log(f"  [Vulns] Merge final: {len(vulns_data) - hist_count} ciclo atual + {hist_count} historico(s) = {len(vulns_data)} total")

    # Armazenar dados de vulnerabilidades no estado do dashboard
    dashboard.set_vulns_data(vulns_data)

    empty_severity = [""] * len(severity_cols)
    for item in state["skipped"]:
        details = item.get("details", "")
        reason_full = item.get("reason", "")
        if details:
            reason_full = f"{reason_full} | {details}"
        writer.writerow([
            "",
            item.get("url", ""),
            "",
            "",
            "",
            "",
            f"Erro/Ignorado: {reason_full}",
            "",
            "",
            *empty_severity,
            "", "", "", "",
        ])

    return output.getvalue()


if __name__ == "__main__":
    main()
