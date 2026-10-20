import pytest

from app.checks import (
    CORS_PROBE_ORIGIN,
    check_certificate_days,
    check_cookies,
    check_cors,
    check_info_disclosure,
    check_security_headers,
    check_transport,
    looks_exposed,
    parse_set_cookie,
    safe_label,
    safe_text,
)
from app.ssrf import parse_origin

GOOD_HEADERS = {
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=31536000",
}


def keys(findings):
    return {f.key for f in findings}


def test_plain_http_is_reported_https_is_not():
    assert keys(check_transport(parse_origin("http://example.com"))) == {"plain_http"}
    assert check_transport(parse_origin("https://example.com")) == []


def test_all_security_headers_present_gives_no_findings():
    assert check_security_headers(GOOD_HEADERS, https=True) == []


def test_missing_security_headers_reported():
    assert keys(check_security_headers({}, https=True)) == {
        "missing_csp", "missing_nosniff", "missing_clickjacking", "missing_referrer", "missing_hsts",
    }


def test_hsts_only_expected_on_https():
    assert "missing_hsts" not in keys(check_security_headers({}, https=False))


def test_frame_ancestors_counts_as_clickjacking_protection():
    h = dict(GOOD_HEADERS)
    del h["x-frame-options"]
    h["content-security-policy"] = "default-src 'self'; frame-ancestors 'none'"
    assert check_security_headers(h, https=True) == []


def test_nosniff_must_have_the_right_value():
    h = dict(GOOD_HEADERS)
    h["x-content-type-options"] = "wrong"
    assert keys(check_security_headers(h, https=True)) == {"missing_nosniff"}


def test_cookie_parsing_and_flags():
    assert parse_set_cookie("sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax") == (
        "sid", {"path": "/", "httponly": "", "secure": "", "samesite": "lax"},
    )
    assert check_cookies(["sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax"], https=True) == []
    assert keys(check_cookies(["sid=abc"], https=True)) == {
        "cookie_httponly:sid", "cookie_secure:sid", "cookie_samesite:sid",
    }


def test_secure_flag_only_expected_on_https():
    assert "cookie_secure:sid" not in keys(check_cookies(["sid=abc; HttpOnly; SameSite=Lax"], https=False))


def test_cookie_names_from_the_target_are_sanitised():
    found = check_cookies(["a b<script>alert(1)</script>=x"], https=False)
    assert found and all("<" not in f.title and "<" not in f.key for f in found)
    assert safe_label("<<>>") == "unnamed"
    assert len(safe_label("x" * 500)) == 50


def test_safe_text_strips_control_characters():
    assert safe_text("nginx/1.0\r\nX-Evil: 1") == "nginx/1.0X-Evil: 1"
    assert len(safe_text("a" * 500)) == 80


def test_cors_reflection_with_credentials_is_high():
    f = check_cors(
        {"access-control-allow-origin": CORS_PROBE_ORIGIN, "access-control-allow-credentials": "true"},
        CORS_PROBE_ORIGIN,
    )
    assert keys(f) == {"cors_reflect_credentials"} and f[0].severity == "high"


def test_cors_reflection_without_credentials_is_low():
    f = check_cors({"access-control-allow-origin": CORS_PROBE_ORIGIN}, CORS_PROBE_ORIGIN)
    assert keys(f) == {"cors_reflect"} and f[0].severity == "low"


def test_cors_null_origin_with_credentials():
    f = check_cors(
        {"access-control-allow-origin": "null", "access-control-allow-credentials": "true"},
        CORS_PROBE_ORIGIN,
    )
    assert keys(f) == {"cors_null"}


def test_cors_safe_configurations_not_flagged():
    assert check_cors({}, CORS_PROBE_ORIGIN) == []
    assert check_cors({"access-control-allow-origin": "https://app.example.com"}, CORS_PROBE_ORIGIN) == []
    assert check_cors({"access-control-allow-origin": "*"}, CORS_PROBE_ORIGIN) == []


def test_version_disclosure():
    assert keys(check_info_disclosure({"server": "nginx/1.18.0"})) == {"server_version"}
    assert check_info_disclosure({"server": "nginx"}) == []
    assert keys(check_info_disclosure({"x-powered-by": "Express"})) == {"powered_by"}


@pytest.mark.parametrize(
    "key,status,body,expected",
    [
        ("git_repo", 200, b"ref: refs/heads/main\n", True),
        ("git_repo", 200, b"a" * 40 + b"\n", True),
        ("git_repo", 200, b"<html>Welcome</html>", False),
        ("git_repo", 404, b"ref: refs/heads/main", False),
        ("env_file", 200, b"DB_PASSWORD=hunter2\nDEBUG=true\n", True),
        ("env_file", 200, b"<html>Not found</html>", False),
        ("env_file", 403, b"DB_PASSWORD=hunter2", False),
        ("server_status", 200, b"<title>Apache Server Status for host</title>", True),
        ("server_status", 200, b"<html>home</html>", False),
    ],
)
def test_exposed_file_signatures_avoid_false_positives(key, status, body, expected):
    assert looks_exposed(key, status, body) is expected


def test_certificate_expiry_thresholds():
    assert keys(check_certificate_days(-1)) == {"tls_cert_expired"}
    assert keys(check_certificate_days(5)) == {"tls_cert_expiring"}
    assert check_certificate_days(30) == []
