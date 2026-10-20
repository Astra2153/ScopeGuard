import socket

import httpx
import pytest

from app.config import settings
from app.ssrf import (
    TargetRejected,
    is_allowed_ip,
    parse_origin,
    resolve_and_validate,
    safe_get,
)

BLOCKED = [
    "127.0.0.1", "10.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.169.254", "0.0.0.0",
    "100.64.0.1", "100.100.100.200", "224.0.0.1", "240.0.0.1", "255.255.255.255", "198.18.0.1",
    "::1", "fe80::1", "fc00::1", "fd00:ec2::254", "::",
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
    "64:ff9b::7f00:1", "2002:7f00:1::", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
    "not-an-ip",
]


@pytest.mark.parametrize("ip", BLOCKED)
def test_non_public_addresses_are_blocked(ip):
    assert is_allowed_ip(ip, lab_mode=False) is False


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(ip):
    assert is_allowed_ip(ip, lab_mode=False) is True


def test_lab_mode_allows_loopback_and_private_but_never_metadata():
    for ip in ("127.0.0.1", "10.1.2.3", "192.168.0.5", "::1", "fc00::1"):
        assert is_allowed_ip(ip, lab_mode=True) is True
    for ip in ("169.254.169.254", "0.0.0.0", "::ffff:169.254.169.254", "fd00:ec2::254", "224.0.0.1"):
        assert is_allowed_ip(ip, lab_mode=True) is False


BAD_URLS = [
    "",
    "ftp://example.com",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "http://",
    "http://user:pass@example.com",
    "http://example.com:80@evil.com",
    "http://exa mple.com",
    "http://example.com\\@evil.com",
    "http://example.com:99999",
    "http://example.com:0",
    "http://[::1",
    "http://%65xample.com",
    "http://2130706433/",
    "http://0x7f.0.0.1/",
    "http://127.1/",
    "http://017700000001/",
    "http://example.com./",
    "http://" + "a" * 300 + ".com",
    "http://example.com/" + "a" * 2100,
]


@pytest.mark.parametrize("raw", BAD_URLS)
def test_parse_origin_rejects_bad_input(raw):
    with pytest.raises(TargetRejected):
        parse_origin(raw)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://Example.COM/api/v1?x=1#f", "https://example.com"),
        ("http://example.com:80/x", "http://example.com"),
        ("https://example.com:443", "https://example.com"),
        ("http://example.com:8080", "http://example.com:8080"),
        ("https://[2606:4700:4700::1111]:8443/", "https://[2606:4700:4700::1111]:8443"),
        ("http://b\u00fccher.example/", "http://xn--bcher-kva.example"),
        ("http://127.0.0.1:3000/rest", "http://127.0.0.1:3000"),
    ],
)
def test_parse_origin_normalizes_to_origin_only(raw, expected):
    assert parse_origin(raw).url == expected


def fake_dns(monkeypatch, mapping, calls=None):
    """mapping: host -> list of answers (one per call; the last repeats). An answer is a list of IPs or 'NXDOMAIN'."""
    real = socket.getaddrinfo
    count = {}

    def fake(host, port, *args, **kwargs):
        if host not in mapping:
            return real(host, port, *args, **kwargs)
        if calls is not None:
            calls.append(host)
        n = count.get(host, 0)
        count[host] = n + 1
        answers = mapping[host]
        answer = answers[min(n, len(answers) - 1)]
        if answer == "NXDOMAIN":
            raise socket.gaierror("no such host")
        return [
            (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))
            for ip in answer
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake)


def test_hostname_resolving_to_private_address_is_blocked(monkeypatch):
    fake_dns(monkeypatch, {"intranet.test": [["10.0.0.5"]]})
    with pytest.raises(TargetRejected):
        resolve_and_validate("intranet.test", 80)


def test_one_bad_address_blocks_the_whole_host(monkeypatch):
    fake_dns(monkeypatch, {"mixed.test": [["8.8.8.8", "10.0.0.1"]]})
    with pytest.raises(TargetRejected):
        resolve_and_validate("mixed.test", 80)


def test_public_hostname_is_accepted(monkeypatch):
    fake_dns(monkeypatch, {"api.test": [["8.8.8.8"]]})
    assert resolve_and_validate("api.test", 443) == ["8.8.8.8"]


def test_unresolvable_host_is_rejected(monkeypatch):
    fake_dns(monkeypatch, {"nowhere.test": ["NXDOMAIN"]})
    with pytest.raises(TargetRejected):
        resolve_and_validate("nowhere.test", 80)


def test_localhost_name_is_blocked():
    with pytest.raises(TargetRejected):
        resolve_and_validate("localhost", 80)


def test_loopback_server_refused_without_lab_mode(lab_server):
    with pytest.raises(TargetRejected):
        safe_get(lab_server.origin, "/ok")
    assert lab_server.hits == []  # nothing was ever sent


def test_lab_flag_is_ignored_outside_development(lab_mode, lab_server, monkeypatch):
    monkeypatch.setattr(settings, "app_env", "production")
    with pytest.raises(TargetRejected):
        safe_get(lab_server.origin, "/ok")
    assert lab_server.hits == []


def test_lab_mode_fetch_works_and_uses_get_only(lab_mode, lab_server):
    res = safe_get(lab_server.origin, "/ok")
    assert res.status == 200 and res.body == b"hello" and res.truncated is False
    assert {h[0] for h in lab_server.hits} == {"GET"}


def test_redirects_are_not_followed(lab_mode, lab_server):
    res = safe_get(lab_server.origin, "/redir")
    assert res.status == 302
    assert len(lab_server.hits) == 1  # the metadata address in Location was never contacted


def test_response_size_is_capped(lab_mode, lab_server):
    res = safe_get(lab_server.origin, "/big", max_bytes=1000)
    assert res.status == 200 and res.truncated is True and len(res.body) == 1000


def test_slow_server_times_out(lab_mode, lab_server):
    with pytest.raises(httpx.TimeoutException):
        safe_get(lab_server.origin, "/slow", timeout=1.0)


def test_dns_is_resolved_once_and_connection_is_pinned(lab_mode, lab_server, monkeypatch):
    calls = []
    # A rebinding attacker would answer 127.0.0.1 first and something else on a second lookup.
    fake_dns(monkeypatch, {"lab.test": [["127.0.0.1"], ["10.0.0.9"]]}, calls)
    res = safe_get(f"http://lab.test:{lab_server.port}", "/ok")
    assert res.status == 200 and res.body == b"hello"
    assert len(calls) == 1
    assert lab_server.hits[-1][2] == f"lab.test:{lab_server.port}"  # original Host header kept


def test_proxy_environment_variables_are_ignored(lab_mode, lab_server, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    assert safe_get(lab_server.origin, "/ok").status == 200
