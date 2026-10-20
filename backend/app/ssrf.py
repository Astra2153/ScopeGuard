import ipaddress
import re
import socket
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from app.config import settings


class TargetRejected(Exception):
    """The target URL or address is not allowed by the safety policy."""


MAX_URL_LEN = 2000
DEFAULT_PORTS = {"http": 80, "https": 443}
USER_AGENT = "ScopeGuard-Verifier/0.1"

# Never reachable, not even in lab mode (link-local covers 169.254.169.254, the cloud metadata address).
_ALWAYS_BLOCKED = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
        "fd00:ec2::/32",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "2001::/32",
        "2002::/16",
    )
]

# Extra ranges allowed only in lab mode.
_LAB_ALLOWED = [
    ipaddress.ip_network(n)
    for n in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7")
]

_HOST_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*")


def lab_mode_enabled() -> bool:
    return bool(settings.allow_private_targets) and settings.app_env == "development"


def is_allowed_ip(value: str, *, lab_mode: bool) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 must be judged as 127.0.0.1
    if any(ip in net for net in _ALWAYS_BLOCKED):
        return False
    if lab_mode and any(ip in net for net in _LAB_ALLOWED):
        return True
    return ip.is_global


@dataclass(frozen=True)
class Origin:
    scheme: str
    host: str
    port: int

    @property
    def host_is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False

    @property
    def host_header(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        if self.port == DEFAULT_PORTS[self.scheme]:
            return host
        return f"{host}:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host_header}"


def _normalize_hostname(host: str) -> str:
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise TargetRejected("invalid host")
    if len(ascii_host) > 253 or not _HOST_RE.fullmatch(ascii_host):
        raise TargetRejected("invalid host")
    last_label = ascii_host.rsplit(".", 1)[-1]
    if last_label.isdigit() or last_label.startswith("0x"):
        # 127.1, 2130706433, 0x7f.0.0.1 and friends: ambiguous numeric forms are refused outright.
        raise TargetRejected("ambiguous numeric host")
    return ascii_host


def parse_origin(raw: str) -> Origin:
    """Validate a user-supplied URL and reduce it to scheme + host + port."""
    if not isinstance(raw, str) or not raw or len(raw) > MAX_URL_LEN:
        raise TargetRejected("invalid url")
    if any(ord(c) <= 0x20 or ord(c) == 0x7F or c == "\\" for c in raw):
        raise TargetRejected("invalid characters in url")
    try:
        parts = urlsplit(raw)
        port = parts.port
        host = parts.hostname
    except ValueError:
        raise TargetRejected("invalid url")
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise TargetRejected("only http and https are allowed")
    if "@" in parts.netloc:
        raise TargetRejected("credentials in url are not allowed")
    if not host or "%" in host:
        raise TargetRejected("invalid host")
    if port == 0:
        raise TargetRejected("invalid port")
    port = port or DEFAULT_PORTS[scheme]
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = _normalize_hostname(host)
    return Origin(scheme, host, port)


def resolve_and_validate(host: str, port: int) -> list[str]:
    """Resolve ONCE and require every address to be allowed. The caller connects to these IPs."""
    lab = lab_mode_enabled()
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        raise TargetRejected("host cannot be resolved")
    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise TargetRejected("host cannot be resolved")
    for ip in ips:
        if not is_allowed_ip(ip, lab_mode=lab):
            raise TargetRejected("target address is not allowed")
    return ips


@dataclass
class FetchResult:
    status: int
    body: bytes
    truncated: bool
    headers: dict | None = None
    set_cookies: list | None = None


def safe_get(origin_url: str, path: str, *, max_bytes: int = 65536, timeout: float = 5.0, extra_headers: dict | None = None, auth_headers: dict | None = None) -> FetchResult:
    """GET only. Validated and pinned address, no redirects, size and time limits."""
    origin = parse_origin(origin_url)
    if not path.startswith("/") or any(ord(c) <= 0x20 or ord(c) == 0x7F or c == "\\" for c in path):
        raise TargetRejected("invalid path")
    ips = resolve_and_validate(origin.host, origin.port)
    headers = {
        "Host": origin.host_header,
        "User-Agent": USER_AGENT,
        "Accept": "text/plain, */*;q=0.1",
        "Accept-Encoding": "identity",
    }
    if extra_headers:
        # Only Origin may be added; Host and everything else stay under our control.
        headers.update({k: v for k, v in extra_headers.items() if k.lower() == "origin"})
    if auth_headers:
        for name, value in auth_headers.items():
            if (
                name.lower() not in ("authorization", "cookie")
                or not isinstance(value, str)
                or not value.isascii()
                or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)
            ):
                raise TargetRejected("invalid auth header")
            headers[name] = value  # sent only to the validated, pinned address; redirects are off
    extensions = {}
    if origin.scheme == "https" and not origin.host_is_ip:
        extensions["sni_hostname"] = origin.host  # certificate is checked against the real name
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    for ip in ips[:2]:
        ip_host = f"[{ip}]" if ":" in ip else ip
        url = f"{origin.scheme}://{ip_host}:{origin.port}{path}"
        try:
            with httpx.Client(
                timeout=httpx.Timeout(timeout, connect=3.0),
                follow_redirects=False,  # a redirect could point somewhere internal
                trust_env=False,  # ignore proxy environment variables
            ) as client:
                with client.stream("GET", url, headers=headers, extensions=extensions) as resp:
                    chunks: list[bytes] = []
                    total = 0
                    truncated = False
                    for chunk in resp.iter_raw():
                        if time.monotonic() > deadline:
                            raise httpx.ReadTimeout("total time limit exceeded")
                        chunks.append(chunk)
                        total += len(chunk)
                        if total > max_bytes:
                            truncated = True
                            break
                    return FetchResult(resp.status_code, b"".join(chunks)[:max_bytes], truncated, dict(resp.headers), resp.headers.get_list("set-cookie"))
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            last_error = exc
            continue
    raise last_error


