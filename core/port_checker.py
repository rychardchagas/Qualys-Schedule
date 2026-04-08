"""
Modulo de validacao de portas de rede.
Detecta automaticamente o ambiente (Windows/Linux):
  - Windows: usa PowerShell Test-NetConnection (detalhes completos)
  - Linux/Docker: usa socket.create_connection (compativel com containers)
Captura informacoes de conectividade (IP, interface, etc).
Detecta erros de DNS para diferenciar de timeout de porta.
Inclui sanitizacao de hostname para prevenir command injection.
Inclui protecao contra SSRF (bloqueia IPs internos/reservados).
"""
import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

PORTS_TO_CHECK = [443, 80]

# Regex para hostname valido (RFC 952/1123)
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$")
_MAX_HOSTNAME_LEN = 253

# Redes internas/reservadas bloqueadas (protecao contra SSRF)
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / AWS metadata
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("100.64.0.0/10"),      # Shared address space
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 private
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
]

# Hostnames bloqueados (SSRF)
_BLOCKED_HOSTNAMES = {
    "localhost", "metadata", "metadata.google.internal",
    "instance-data", "169.254.169.254",
}


def _is_internal_ip(ip_str: str) -> bool:
    """Verifica se um IP pertence a uma rede interna/reservada."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _BLOCKED_NETWORKS)
    except ValueError:
        return False

# Timeout para teste de porta via socket (segundos)
_SOCKET_TIMEOUT = 10

# Detectar SO uma vez
_IS_WINDOWS = platform.system() == "Windows"


def _sanitize_hostname(host: str) -> str:
    """
    Valida e sanitiza hostname para prevenir command injection no PowerShell.
    Aceita apenas caracteres validos de hostname (letras, numeros, hifens, pontos).
    """
    host = host.strip().lower()

    # Remover protocolo se presente
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix):]

    # Remover path se presente
    host = host.split("/")[0]

    # Remover porta se presente (ex: host:8080)
    if ":" in host:
        host = host.rsplit(":", 1)[0]

    if not host:
        raise ValueError("Hostname vazio")

    if len(host) > _MAX_HOSTNAME_LEN:
        raise ValueError(f"Hostname muito longo ({len(host)} > {_MAX_HOSTNAME_LEN})")

    if not _HOSTNAME_RE.match(host):
        raise ValueError(f"Hostname com caracteres invalidos: {host!r}")

    # Protecao SSRF: bloquear hostnames internos conhecidos
    if host in _BLOCKED_HOSTNAMES:
        raise ValueError(f"Hostname bloqueado por politica de seguranca: {host!r}")

    return host


def _validate_port(port: int) -> int:
    """Valida que a porta esta no range valido."""
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError(f"Porta invalida: {port}")
    return port


@dataclass
class PortDetail:
    """Detalhes completos de conectividade de uma porta."""
    port: int
    computer_name: str = ""
    remote_address: str = ""
    remote_port: str = ""
    interface_alias: str = ""
    source_address: str = ""
    tcp_test_succeeded: bool = False
    dns_error: bool = False
    dns_error_message: str = ""

    @property
    def status(self) -> str:
        if self.dns_error:
            return "Erro DNS"
        return "OK" if self.tcp_test_succeeded else "Falha"


def _check_port_socket(host: str, port: int) -> PortDetail:
    """
    Testa conectividade TCP usando socket puro do Python.
    Compativel com qualquer SO (Linux, Docker, Windows).
    """
    detail = PortDetail(port=port, computer_name=host)

    try:
        # Resolver DNS primeiro para detectar erros de DNS
        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if addr_info:
            resolved_ip = addr_info[0][4][0]
            detail.remote_address = resolved_ip
            # Protecao SSRF: bloquear IPs internos/reservados apos resolucao DNS
            if _is_internal_ip(resolved_ip):
                detail.dns_error = True
                detail.dns_error_message = f"Bloqueado: '{host}' resolve para IP interno ({resolved_ip})"
                return detail
    except socket.gaierror:
        detail.dns_error = True
        detail.dns_error_message = f"Erro DNS: nao foi possivel resolver '{host}'"
        return detail

    try:
        sock = socket.create_connection((host, port), timeout=_SOCKET_TIMEOUT)
        sock.close()
        detail.tcp_test_succeeded = True
        detail.remote_port = str(port)
    except (socket.timeout, TimeoutError):
        pass
    except ConnectionRefusedError:
        pass
    except OSError:
        pass

    return detail


def _check_port_powershell(host: str, port: int) -> PortDetail:
    """Testa conectividade TCP via PowerShell Test-NetConnection (Windows)."""
    # Usar lista de argumentos (sem shell=True) para prevenir injection
    cmd = [
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        f"Test-NetConnection -ComputerName '{host}' -Port {port} -WarningAction SilentlyContinue",
    ]
    detail = PortDetail(port=port, computer_name=host)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        # Detectar erros de DNS no stderr ou stdout
        dns_error_indicators = [
            "resolve the remote name",
            "No such host is known",
            "DNS name does not exist",
            "could not be resolved",
            "Name resolution",
            "getaddrinfo",
        ]

        combined_output = (stdout + " " + stderr).lower()
        for indicator in dns_error_indicators:
            if indicator.lower() in combined_output:
                detail.dns_error = True
                detail.dns_error_message = f"Erro DNS: nao foi possivel resolver '{host}'"
                return detail

        # Verificar se RemoteAddress esta vazio (outro indicador de DNS falho)
        has_remote_address = False

        for line in stdout.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()

            if key == "ComputerName":
                detail.computer_name = value
            elif key == "RemoteAddress":
                detail.remote_address = value
                if value:
                    has_remote_address = True
            elif key == "RemotePort":
                detail.remote_port = value
            elif key == "InterfaceAlias":
                detail.interface_alias = value
            elif key == "SourceAddress":
                detail.source_address = value
            elif key == "TcpTestSucceeded":
                detail.tcp_test_succeeded = value == "True"

        # Se nao tem RemoteAddress e TcpTest falhou, pode ser DNS
        if not has_remote_address and not detail.tcp_test_succeeded:
            detail.dns_error = True
            detail.dns_error_message = f"Erro DNS: nao foi possivel resolver '{host}'"

    except subprocess.TimeoutExpired:
        detail.dns_error_message = f"Timeout ao verificar '{host}:{port}'"
    except Exception:
        pass

    return detail


def check_port_full(host: str, port: int) -> PortDetail:
    """
    Testa conectividade TCP e captura todos os campos.
    Detecta automaticamente o SO:
      - Windows: usa PowerShell Test-NetConnection
      - Linux/Docker: usa socket.create_connection
    """
    safe_host = _sanitize_hostname(host)
    safe_port = _validate_port(port)

    if _IS_WINDOWS:
        return _check_port_powershell(safe_host, safe_port)
    else:
        return _check_port_socket(safe_host, safe_port)


def validate_all_ports(host: str) -> dict[int, PortDetail]:
    """
    Testa TODAS as portas configuradas (80 e 443) para um host em paralelo.
    Retorna dicionario {porta: PortDetail} com detalhes completos de cada uma.
    """
    results = {}
    with ThreadPoolExecutor(max_workers=len(PORTS_TO_CHECK)) as executor:
        futures = {
            executor.submit(check_port_full, host, port): port
            for port in PORTS_TO_CHECK
        }
        for future in futures:
            port = futures[future]
            results[port] = future.result()
    return results


def resolve_port(host: str) -> tuple[str | None, int | None, str | None, dict[int, PortDetail]]:
    """
    Resolve a URL e porta para um host.
    Retorna (url, porta, erro, detalhes_portas).
    - Se 443 responde: (https://host, 443, None, details)
    - Se 80 responde: (http://host, 80, None, details)
    - Se nenhuma responde mas sem erro DNS: (http://host, 80, None, details) -> default porta 80
    - Se erro DNS: (None, None, mensagem_erro, details)
    """
    safe_host = _sanitize_hostname(host)
    ports = validate_all_ports(safe_host)
    p443 = ports[443]
    p80 = ports[80]

    # Verificar erro de DNS em qualquer porta
    if p443.dns_error or p80.dns_error:
        msg = p443.dns_error_message or p80.dns_error_message
        return None, None, msg, ports

    if p443.tcp_test_succeeded:
        return f"https://{safe_host}", 443, None, ports

    if p80.tcp_test_succeeded:
        return f"http://{safe_host}", 80, None, ports

    # Nenhuma porta respondeu, mas sem erro de DNS -> default porta 80
    return f"http://{safe_host}", 80, None, ports
