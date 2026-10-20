import re
import socket
import ssl
import time
from dataclasses import dataclass, field

import httpx

from app.ssrf import Origin, TargetRejected, parse_origin, resolve_and_validate, safe_get

CORS_PROBE_ORIGIN = "https://scopeguard-cors-probe.invalid"
EXPOSED_PATHS = [
    ("git_repo", "/.git/HEAD"),
    ("env_file", "/.env"),
    ("server_status", "/server-status"),
]


@dataclass(frozen=True)
class CheckFinding:
    key: str
    title: str
    severity: str
    description: str


def safe_label(value: str, limit: int = 50) -> str:
    """Names that come from the target are untrusted: keep only harmless characters."""
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "", value)[:limit]
    return cleaned or "unnamed"


def safe_text(value: str, limit: int = 80) -> str:
    return re.sub(r"[^\x20-\x7E]", "", value)[:limit]


def lower_headers(headers: dict | None) -> dict:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def check_transport(origin: Origin) -> list[CheckFinding]:
    if origin.scheme == "http":
        return [
            CheckFinding(
                "plain_http",
                "Target is served over plain HTTP",
                "medium",
                "Traffic to this target is not encrypted, so it can be read or modified in transit. "
                "Serve the API over HTTPS and redirect HTTP to HTTPS.",
            )
        ]
    return []


def check_security_headers(h: dict, https: bool) -> list[CheckFinding]:
    out: list[CheckFinding] = []
    csp = h.get("content-security-policy", "")
    if not csp:
        out.append(CheckFinding(
            "missing_csp", "Missing Content-Security-Policy header", "low",
            "No Content-Security-Policy header was returned. A restrictive policy limits the damage of "
            "cross-site scripting. Add a policy that only allows the sources the application needs.",
        ))
    if h.get("x-content-type-options", "").strip().lower() != "nosniff":
        out.append(CheckFinding(
            "missing_nosniff", "Missing X-Content-Type-Options header", "low",
            "Without 'X-Content-Type-Options: nosniff', browsers may guess content types and run "
            "content as script. Add the header with the value nosniff.",
        ))
    if "x-frame-options" not in h and "frame-ancestors" not in csp.lower():
        out.append(CheckFinding(
            "missing_clickjacking", "No clickjacking protection (X-Frame-Options or frame-ancestors)", "low",
            "The response can be embedded in a frame on another site. Add X-Frame-Options: DENY or a "
            "Content-Security-Policy frame-ancestors directive.",
        ))
    if "referrer-policy" not in h:
        out.append(CheckFinding(
            "missing_referrer", "Missing Referrer-Policy header", "info",
            "No Referrer-Policy header was returned. Consider 'no-referrer' or "
            "'strict-origin-when-cross-origin' to limit URL leakage.",
        ))
    if https and "strict-transport-security" not in h:
        out.append(CheckFinding(
            "missing_hsts", "Missing Strict-Transport-Security header", "low",
            "HTTPS is used but HSTS is not set, so browsers may still try plain HTTP first. "
            "Add a Strict-Transport-Security header with a long max-age.",
        ))
    return out


def parse_set_cookie(raw: str) -> tuple[str, dict]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip().lower()
    return name, attrs


def check_cookies(set_cookies: list[str], https: bool) -> list[CheckFinding]:
    out: list[CheckFinding] = []
    for raw in set_cookies[:20]:
        name, attrs = parse_set_cookie(raw)
        label = safe_label(name)
        if "httponly" not in attrs:
            out.append(CheckFinding(
                f"cookie_httponly:{label}", f"Cookie '{label}' missing HttpOnly flag", "low",
                "Script running on the page can read this cookie. If it holds a session or token, "
                "set the HttpOnly flag.",
            ))
        if https and "secure" not in attrs:
            out.append(CheckFinding(
                f"cookie_secure:{label}", f"Cookie '{label}' missing Secure flag", "low",
                "The cookie may be sent over plain HTTP. Set the Secure flag.",
            ))
        if "samesite" not in attrs:
            out.append(CheckFinding(
                f"cookie_samesite:{label}", f"Cookie '{label}' missing SameSite attribute", "low",
                "Without SameSite the browser may send this cookie on cross-site requests, which "
                "helps CSRF. Set SameSite=Lax or Strict.",
            ))
    return out


def check_cors(h: dict, sent_origin: str) -> list[CheckFinding]:
    acao = h.get("access-control-allow-origin", "").strip()
    credentials = h.get("access-control-allow-credentials", "").strip().lower() == "true"
    if acao == sent_origin and credentials:
        return [CheckFinding(
            "cors_reflect_credentials", "CORS reflects any origin with credentials allowed", "high",
            "The server echoed back an arbitrary Origin and allowed credentials, so any website can "
            "read authenticated responses. Use an allow-list of trusted origins.",
        )]
    if acao == sent_origin:
        return [CheckFinding(
            "cors_reflect", "CORS reflects arbitrary origins", "low",
            "The server echoed back an arbitrary Origin. Without credentials the impact is limited, "
            "but an allow-list of trusted origins is safer.",
        )]
    if acao.lower() == "null" and credentials:
        return [CheckFinding(
            "cors_null", "CORS allows the null origin with credentials", "medium",
            "The null origin can be produced by sandboxed pages, so allowing it with credentials is "
            "unsafe. Remove it from the allowed origins.",
        )]
    return []


def check_info_disclosure(h: dict) -> list[CheckFinding]:
    out: list[CheckFinding] = []
    server = h.get("server", "")
    if re.search(r"\d+\.\d+", server):
        out.append(CheckFinding(
            "server_version", "Server header discloses version information", "low",
            f"The Server header reveals a software version ('{safe_text(server)}'), which helps "
            "attackers pick known exploits. Remove the version from the header.",
        ))
    powered = h.get("x-powered-by", "")
    if powered:
        out.append(CheckFinding(
            "powered_by", "X-Powered-By header discloses technology", "low",
            f"The X-Powered-By header reveals the technology in use ('{safe_text(powered)}'). "
            "Remove the header.",
        ))
    return out


EXPOSED_FINDINGS = {
    "git_repo": CheckFinding(
        "exposed_git_repo", "Exposed Git repository metadata (/.git/HEAD)", "high",
        "Git metadata is reachable over HTTP, which can allow the source code and its history to "
        "be downloaded. Block access to the .git directory and remove it from the web root.",
    ),
    "env_file": CheckFinding(
        "exposed_env_file", "Exposed environment file (/.env)", "critical",
        "A file that looks like an environment file is reachable over HTTP and may contain "
        "secrets. Remove it from the web root and rotate every secret it contained. "
        "ScopeGuard does not store the file contents.",
    ),
    "server_status": CheckFinding(
        "exposed_server_status", "Exposed server status page (/server-status)", "medium",
        "A server status page is reachable and can reveal internal request details. Restrict it "
        "to trusted addresses.",
    ),
}


def looks_exposed(key: str, status: int, body: bytes) -> bool:
    """Content signatures, so a generic 200 page does not count as an exposure."""
    if status != 200:
        return False
    text = body[:4096].decode("utf-8", "ignore")
    if key == "git_repo":
        return text.startswith("ref:") or re.fullmatch(r"[0-9a-f]{40}\s*", text) is not None
    if key == "env_file":
        return re.search(r"(?m)^[A-Z][A-Z0-9_]{2,}=.+$", text) is not None
    if key == "server_status":
        return "Apache Server Status" in text or "Total accesses" in text
    return False


def check_certificate_days(days_left: float) -> list[CheckFinding]:
    if days_left < 0:
        return [CheckFinding(
            "tls_cert_expired", "TLS certificate has expired", "high",
            "The certificate is past its expiry date, so clients will reject or distrust the "
            "connection. Renew it and automate renewal.",
        )]
    if days_left < 14:
        return [CheckFinding(
            "tls_cert_expiring", "TLS certificate expires within 14 days", "low",
            "The certificate expires soon. Renew it and automate renewal.",
        )]
    return []


def tls_findings(origin: Origin) -> list[CheckFinding]:
    if origin.scheme != "https" or origin.host_is_ip:
        return []
    ips = resolve_and_validate(origin.host, origin.port)  # same address policy as every request
    ctx = ssl.create_default_context()  # verifies the chain and hostname, TLS 1.2 or newer
    try:
        with socket.create_connection((ips[0], origin.port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=origin.host) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        reason = (exc.verify_message or "").lower()
        if "expired" in reason:
            return check_certificate_days(-1)
        if "host" in reason:
            return [CheckFinding(
                "tls_cert_hostname", "TLS certificate does not match the hostname", "medium",
                "The certificate was not issued for this hostname. Install a certificate that covers it.",
            )]
        if "self" in reason:
            return [CheckFinding(
                "tls_cert_self_signed", "TLS certificate is self-signed", "medium",
                "The certificate is not signed by a trusted authority. Use a certificate from a trusted CA.",
            )]
        return [CheckFinding(
            "tls_cert_untrusted", "TLS certificate is not trusted", "medium",
            "The certificate chain could not be verified. Install the full chain from a trusted CA.",
        )]
    except ssl.SSLError:
        return [CheckFinding(
            "tls_handshake_failed", "TLS handshake failed with a modern client", "medium",
            "A secure handshake (TLS 1.2 or newer) could not be completed. Enable TLS 1.2 and 1.3 "
            "and disable older protocols.",
        )]
    except OSError:
        return []  # unreachable: the HTTP request already reports that
    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
    return check_certificate_days((not_after - time.time()) / 86400)


class ScanAborted(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class ScanReport:
    findings: dict[str, CheckFinding] = field(default_factory=dict)
    requests: int = 0
    incomplete: bool = False


def run_checks(base_url: str, budget: float = 30.0) -> ScanReport:
    report = ScanReport()
    started = time.monotonic()

    def add(items):
        for item in items:
            report.findings.setdefault(item.key, item)

    def out_of_time() -> bool:
        if time.monotonic() - started > budget:
            report.incomplete = True
            return True
        return False

    def fetch(path: str, extra: dict | None = None):
        report.requests += 1
        return safe_get(origin.url, path, max_bytes=4096, extra_headers=extra)

    try:
        origin = parse_origin(base_url)
        https = origin.scheme == "https"
        add(check_transport(origin))
        res = fetch("/")
    except TargetRejected:
        raise ScanAborted("target_not_allowed")
    except (httpx.HTTPError, httpx.InvalidURL, OSError):
        raise ScanAborted("target_unreachable")

    headers = lower_headers(res.headers)
    add(check_security_headers(headers, https))
    add(check_cookies(res.set_cookies or [], https))
    add(check_info_disclosure(headers))

    try:
        if not out_of_time():
            cors = fetch("/", {"Origin": CORS_PROBE_ORIGIN})
            add(check_cors(lower_headers(cors.headers), CORS_PROBE_ORIGIN))
        for key, path in EXPOSED_PATHS:
            if out_of_time():
                break
            probe = fetch(path)
            if looks_exposed(key, probe.status, probe.body):
                add([EXPOSED_FINDINGS[key]])  # only a fixed description is stored, never the body
        if not out_of_time():
            add(tls_findings(origin))
    except (TargetRejected, httpx.HTTPError, httpx.InvalidURL, OSError):
        report.incomplete = True
    return report
