"""End-to-end ScopeGuard demo: find, fix, retest, signed report.

Needs the API on port 8000 and tools/lab_target.py on port 8081 (see the README).
Run it from the ScopeGuard folder: python tools/demo.py
"""
import os
import secrets
import subprocess
import sys
from pathlib import Path

import httpx

API = os.environ.get("SCOPEGUARD_API", "http://127.0.0.1:8000")
LAB = "http://127.0.0.1:8081"
HERE = Path(__file__).resolve().parent
STATE = HERE / "lab_state"
OUT = HERE / "demo_output"
SPEC = {"openapi": "3.0.0", "paths": {"/api/orders/{orderId}": {"get": {}}}}
ALICE = {"authorization": "Bearer alice-token"}
BOB = {"authorization": "Bearer bob-token"}
RANK = ["critical", "high", "medium", "low", "info"]


def say(text):
    print()
    print("== " + text)


def fail(message):
    sys.exit("FAILED: " + message)


def set_state(name, value):
    STATE.mkdir(exist_ok=True)
    (STATE / name).write_text(value, encoding="ascii")


class Api:
    def __init__(self):
        self.client = httpx.Client(base_url=API, timeout=60)
        self.csrf = None

    def call(self, method, path, body=None, expect=(200, 201, 204)):
        headers = {"X-CSRF-Token": self.csrf} if self.csrf else {}
        r = self.client.request(method, path, json=body, headers=headers)
        if r.status_code not in expect:
            hint = " (rate limit: wait a minute and run again)" if r.status_code == 429 else ""
            fail(f"{method} {path} returned {r.status_code}: {r.text[:300]}{hint}")
        return r


def check_up():
    try:
        httpx.get(API + "/health", timeout=5).raise_for_status()
    except httpx.HTTPError:
        fail("the ScopeGuard API is not running on " + API)
    try:
        httpx.get(LAB + "/", timeout=5)
    except httpx.HTTPError:
        fail("the lab target is not running on " + LAB)


def show_findings(api, engagement):
    rows = api.call("GET", f"/engagements/{engagement}/findings").json()
    rows.sort(key=lambda f: (RANK.index(f["severity"]), f["title"]))
    for f in rows:
        print(f"  {f['status']:<16} {f['severity']:<9} {f['source']:<8} {f['title']}")
    return rows


def save_report(api, engagement, label):
    report = api.call("POST", f"/engagements/{engagement}/reports").json()
    download = api.call("GET", f"/reports/{report['id']}/download")
    path = OUT / f"report-{label}.md"
    path.write_bytes(download.content)
    return path, download.headers["x-report-signature"]


def verify_offline(path, signature, public_key):
    result = subprocess.run(
        [sys.executable, str(HERE / "verify_report.py"), str(path), signature, public_key],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() or result.stderr.strip()


def main():
    check_up()
    OUT.mkdir(exist_ok=True)
    set_state("mode", "vulnerable")
    set_state("token", "")
    api = Api()

    say("1. Create a demo user and log in")
    email = f"demo_{secrets.token_hex(4)}@demo.test"
    password = "Demo-" + secrets.token_urlsafe(16)
    api.call("POST", "/auth/register", {"email": email, "password": password})
    login = api.call("POST", "/auth/login", {"email": email, "password": password}).json()
    api.csrf = login["csrf_token"]
    print("  logged in (the password is random and is never printed)")

    say("2. Create an engagement and register the target")
    engagement = api.call("POST", "/engagements", {"name": "Demo: Acme Orders API"}).json()["id"]
    target = api.call("POST", f"/engagements/{engagement}/targets", {"base_url": LAB}).json()
    print("  target registered, ownership not yet proven:", target["verified"])

    say("3. Prove ownership by publishing the token on the target")
    set_state("token", target["verification_token"])
    verified = api.call("POST", f"/targets/{target['id']}/verify").json()
    print("  target verified:", verified["verified"])

    say("4. Safe configuration scan")
    scan = api.call("POST", f"/targets/{target['id']}/scan").json()
    print(f"  created={scan['created']} requests={scan['requests']} incomplete={scan['incomplete']}")

    say("5. Authorization matrix: can Bob read Alice's order?")
    authz_body = {
        "confirm_authorized": True,
        "spec": SPEC,
        "auth_a": ALICE,
        "auth_b": BOB,
        "object_ids": {"orderId": "1001"},
    }
    authz = api.call("POST", f"/targets/{target['id']}/authz-scan", authz_body).json()
    for r in authz["results"]:
        print(f"  {r['path']}: {r['outcome']} (anonymous access: {r['anonymous_access']})")
    print(f"  created={authz['created']} requests={authz['requests']}")

    say("6. Findings before the fix")
    show_findings(api, engagement)
    report1, sig1 = save_report(api, engagement, "1-before-fix")
    print("  signed report saved:", report1)

    say("7. The client 'fixes' the target and claims every finding is fixed")
    set_state("mode", "fixed")
    for f in api.call("GET", f"/engagements/{engagement}/findings").json():
        if f["status"] == "open":
            api.call("PATCH", f"/findings/{f['id']}", {"status": "fixed"})

    say("8. Retest: scan again")
    rescan = api.call("POST", f"/targets/{target['id']}/scan").json()
    reauthz = api.call("POST", f"/targets/{target['id']}/authz-scan", authz_body).json()
    print(f"  scan: created={rescan['created']} reopened={rescan['reopened']}")
    for r in reauthz["results"]:
        print(f"  authorization check: {r['path']}: {r['outcome']}")

    say("9. Findings after the retest")
    show_findings(api, engagement)
    report2, sig2 = save_report(api, engagement, "2-after-retest")
    print("  signed report saved:", report2)

    say("10. Verify the signatures offline (no ScopeGuard server involved)")
    public_key = api.call("GET", "/reports/public-key").json()["public_key"]
    (OUT / "public_key.txt").write_text(public_key, encoding="ascii")
    print("  report 1:", verify_offline(report1, sig1, public_key))
    print("  report 2:", verify_offline(report2, sig2, public_key))
    tampered = OUT / "report-2-tampered.md"
    tampered.write_bytes(report2.read_bytes().replace(b"Security", b"Secur1ty", 1))
    print("  tampered copy:", verify_offline(tampered, sig2, public_key))

    say("Done")
    print("  Reports are in", OUT)
    print("  Expected story: BOLA and the header issues are fixed; plain HTTP is still not_fixed.")


if __name__ == "__main__":
    main()

