import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass, field

import httpx

from app.checks import CheckFinding
from app.ssrf import FetchResult, TargetRejected, parse_origin, safe_get

PATH_RE = re.compile(r"/[A-Za-z0-9_./{}-]{0,199}")
PARAM_RE = re.compile(r"\{([A-Za-z][A-Za-z0-9_]{0,40})\}")
NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,40}")
ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
AUTH_HEADERS = {"authorization": "Authorization", "cookie": "Cookie"}
MAX_ENDPOINTS = 20
MAX_REQUESTS = 80
MAX_AUTH_VALUE = 4096


class MatrixError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _OutOfBudget(Exception):
    pass


@dataclass(frozen=True)
class Endpoint:
    path: str
    params: tuple


def extract_endpoints(spec) -> list[Endpoint]:
    """GET endpoints with path parameters. Anything odd in a path is skipped, never guessed at."""
    paths = spec.get("paths") if isinstance(spec, dict) else None
    if not isinstance(paths, dict):
        return []
    found = []
    for path in sorted(p for p in paths if isinstance(p, str)):
        item = paths[path]
        if not isinstance(item, dict) or "get" not in item:
            continue
        if not PATH_RE.fullmatch(path) or ".." in path or "//" in path:
            continue
        params = PARAM_RE.findall(path)
        if not params or re.search(r"[{}]", PARAM_RE.sub("", path)):
            continue
        found.append(Endpoint(path, tuple(params)))
    return found


def validate_auth(raw) -> dict:
    """Only Authorization and Cookie are accepted, as plain printable ASCII."""
    if not isinstance(raw, dict) or not raw or len(raw) > 2:
        raise MatrixError("invalid_credentials")
    out = {}
    for name, value in raw.items():
        canonical = AUTH_HEADERS.get(str(name).lower())
        if (
            canonical is None
            or not isinstance(value, str)
            or not value
            or len(value) > MAX_AUTH_VALUE
            or not value.isascii()
            or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)
        ):
            raise MatrixError("invalid_credentials")
        out[canonical] = value
    return out


def validate_object_ids(raw) -> dict:
    """IDs go into URL paths, so they are restricted to a safe alphabet."""
    if not isinstance(raw, dict) or not raw or len(raw) > 10:
        raise MatrixError("invalid_object_ids")
    out = {}
    for name, value in raw.items():
        if not NAME_RE.fullmatch(str(name)) or not isinstance(value, str) or not ID_RE.fullmatch(value):
            raise MatrixError("invalid_object_ids")
        out[str(name)] = value
    return out


def fill(path: str, values: dict) -> str:
    return PARAM_RE.sub(lambda m: values[m.group(1)], path)


def is_ok(res: FetchResult) -> bool:
    return 200 <= res.status < 300


def canonical_body(body: bytes):
    try:
        return json.dumps(json.loads(body.decode("utf-8")), sort_keys=True, separators=(",", ":"))
    except (ValueError, UnicodeDecodeError):
        return body


def same(a: FetchResult, b: FetchResult) -> bool:
    """The deterministic verifier: both succeeded, both have content, and the content is identical."""
    return is_ok(a) and is_ok(b) and len(a.body) > 0 and len(b.body) > 0 and (
        canonical_body(a.body) == canonical_body(b.body)
    )


@dataclass
class EndpointResult:
    path: str
    outcome: str
    anonymous: bool | None


@dataclass
class MatrixReport:
    results: list = field(default_factory=list)
    findings: dict = field(default_factory=dict)
    requests: int = 0
    incomplete: bool = False


def _digest(path: str) -> str:
    return hashlib.sha256(path.encode()).hexdigest()[:16]


def findings_for(path: str, outcome: str, anonymous: bool | None) -> dict:
    out = {}
    if outcome == "confirmed_bola":
        key = f"bola:{_digest(path)}"
        out[key] = CheckFinding(
            key,
            f"Broken object level authorization: GET {path}",
            "high",
            "A second test identity was able to read an object that belongs to the first identity, "
            "and a request for a non-existent object did not return the same data. The server does "
            "not check that the object belongs to the caller. Check ownership on the server for "
            "every request, and return 404 or 403 for objects the caller does not own.",
        )
    if anonymous:
        key = f"anon:{_digest(path)}"
        out[key] = CheckFinding(
            key,
            f"Endpoint reachable without authentication: GET {path}",
            "high",
            "A request with no credentials returned the same data as the authenticated owner, and a "
            "request for a non-existent object did not. Require authentication on this endpoint.",
        )
    return out


def _test_endpoint(fetch, ep: Endpoint, object_ids: dict, auth_a: dict, auth_b: dict):
    real = fill(ep.path, object_ids)
    a = fetch(real, auth_a)
    if not is_ok(a):
        return "baseline_failed", None
    cache: list[bool] = []

    def catch_all() -> bool:
        # Control: the owner asks for an object that does not exist. If the endpoint still returns the
        # same data, it ignores the ID entirely, so matches elsewhere prove nothing.
        if not cache:
            junk = "sg-" + secrets.token_hex(8)
            cache.append(same(a, fetch(fill(ep.path, {p: junk for p in ep.params}), auth_a)))
        return cache[0]

    b = fetch(real, auth_b)
    if same(a, b):
        outcome = "inconclusive_catch_all" if catch_all() else "confirmed_bola"
    else:
        outcome = "denied"
    anon = fetch(real, None)
    anonymous = (not catch_all()) if same(a, anon) else False
    return outcome, anonymous


def run_matrix(base_url, endpoints, auth_a, auth_b, object_ids, budget: float = 60.0) -> MatrixReport:
    report = MatrixReport()
    started = time.monotonic()
    try:
        origin = parse_origin(base_url)
    except TargetRejected:
        raise MatrixError("target_not_allowed")

    def fetch(path, auth):
        if report.requests >= MAX_REQUESTS or time.monotonic() - started > budget:
            report.incomplete = True
            raise _OutOfBudget()
        report.requests += 1
        return safe_get(origin.url, path, max_bytes=65536, auth_headers=auth)

    if len(endpoints) > MAX_ENDPOINTS:
        report.incomplete = True
    completed = 0
    for ep in endpoints[:MAX_ENDPOINTS]:
        if any(p not in object_ids for p in ep.params):
            report.results.append(EndpointResult(ep.path, "skipped_missing_ids", None))
            continue
        try:
            outcome, anonymous = _test_endpoint(fetch, ep, object_ids, auth_a, auth_b)
        except _OutOfBudget:
            break
        except TargetRejected:
            raise MatrixError("target_not_allowed")
        except (httpx.HTTPError, httpx.InvalidURL, OSError):
            if completed == 0:
                raise MatrixError("target_unreachable")
            report.incomplete = True
            report.results.append(EndpointResult(ep.path, "error", None))
            continue
        completed += 1
        report.results.append(EndpointResult(ep.path, outcome, anonymous))
        report.findings.update(findings_for(ep.path, outcome, anonymous))
    return report
