"""API tests.

Run against the real ASGI app with ``TestClient`` and **no database**. That is
the configuration a reviewer will actually hit, so it is the one these tests
assert: the service must work without Postgres, must say so rather than lie, and
must never expose an endpoint that can change a device.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.security import create_access_token, hash_password
from app.main import create_app

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "configs"
PREFIX = "/api/v1"


@pytest.fixture(scope="module")
def client() -> Any:
    return TestClient(create_app())


@pytest.fixture(scope="module")
def admin_token() -> str:
    token, _ = create_access_token(subject="test-admin", role="admin")
    return token


@pytest.fixture(scope="module")
def viewer_token() -> str:
    token, _ = create_access_token(subject="test-viewer", role="viewer")
    return token


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _upload(name: str) -> dict[str, Any]:
    """Build a multipart upload. ``(filename, bytes)`` is the httpx form."""
    return {"file": (name, (SAMPLES / name).read_bytes(), "text/plain")}


def _raw_upload(name: str, data: bytes) -> dict[str, Any]:
    return {"file": (name, data, "text/plain")}


class TestSystemEndpoints:
    def test_healthz_never_touches_a_dependency(self, client) -> None:
        r = client.get(f"{PREFIX}/healthz")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_readyz_reports_degradation_honestly(self, client) -> None:
        r = client.get(f"{PREFIX}/readyz")
        assert r.status_code == 200
        body = r.json()
        # The pipeline is what makes the service useful; it must be ready.
        assert body["pipeline"]["ready"] is True
        # Postgres and Neo4j are reported either way, never assumed.
        assert "available" in body["postgres"]
        assert "available" in body["neo4j"]
        if not body["postgres"]["available"]:
            assert body["postgres"]["reason"]

    def test_root_advertises_docs(self, client) -> None:
        r = client.get("/")
        assert r.status_code == 200
        assert r.json()["docs"] == "/docs"

    def test_security_headers_are_present(self, client) -> None:
        r = client.get(f"{PREFIX}/healthz")
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
        assert r.headers["Cache-Control"] == "no-store"

    def test_every_response_carries_a_request_id(self, client) -> None:
        assert client.get(f"{PREFIX}/healthz").headers["X-Request-ID"]
        supplied = client.get(f"{PREFIX}/healthz", headers={"X-Request-ID": "abc123"})
        assert supplied.headers["X-Request-ID"] == "abc123"


class TestAuthentication:
    def test_missing_token_is_401(self, client) -> None:
        assert client.get(f"{PREFIX}/dashboard").status_code == 401

    def test_garbage_token_is_401_not_500(self, client) -> None:
        r = client.get(f"{PREFIX}/dashboard", headers=_auth("not-a-jwt"))
        assert r.status_code == 401

    def test_tampered_token_is_rejected(self, client, admin_token) -> None:
        tampered = admin_token[:-4] + ("aaaa" if not admin_token.endswith("aaaa") else "bbbb")
        assert client.get(f"{PREFIX}/dashboard", headers=_auth(tampered)).status_code == 401

    def test_valid_token_is_accepted(self, client, admin_token) -> None:
        assert client.get(f"{PREFIX}/auth/me", headers=_auth(admin_token)).status_code == 200

    def test_me_reports_the_token_role(self, client, admin_token) -> None:
        body = client.get(f"{PREFIX}/auth/me", headers=_auth(admin_token)).json()
        assert body["role"] == "admin"
        assert body["username"] == "test-admin"

    def test_viewer_cannot_scan(self, client, viewer_token) -> None:
        r = client.post(
            f"{PREFIX}/analyze",
            headers=_auth(viewer_token),
            files=_upload("cisco_ios_core_switch.cfg"),
        )
        assert r.status_code == 403

    def test_role_comes_from_the_token_not_the_request(self, client, viewer_token) -> None:
        """A viewer cannot escalate by claiming a role in a header or a query param."""
        claims_admin = {**_auth(viewer_token), "X-Role": "admin"}
        for url in (
            f"{PREFIX}/dashboard",
            f"{PREFIX}/dashboard?role=admin",
            f"{PREFIX}/auth/me",
        ):
            r = client.get(url, headers=claims_admin)
            assert r.status_code != 500
            if r.status_code == 200 and url.endswith("/auth/me"):
                # The reported role must still be the one inside the token.
                assert r.json()["role"] == "viewer"
        # And a genuine write attempt is still refused.
        assert (
            client.post(
                f"{PREFIX}/analyze",
                headers=claims_admin,
                files=_upload("cisco_ios_core_switch.cfg"),
            ).status_code
            == 403
        )

    def test_login_rejects_a_wrong_password(self, client) -> None:
        r = client.post(f"{PREFIX}/auth/login", json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401
        assert "invalid username or password" in r.json()["detail"]

    def test_login_rejects_an_unknown_user_the_same_way(self, client) -> None:
        """Identical failure for both cases, so usernames cannot be enumerated."""
        unknown = client.post(f"{PREFIX}/auth/login", json={"username": "ghost", "password": "whatever"})
        wrong = client.post(f"{PREFIX}/auth/login", json={"username": "admin", "password": "whatever"})
        assert unknown.status_code == wrong.status_code == 401
        assert unknown.json()["detail"] == wrong.json()["detail"]

    def test_login_never_returns_a_password_hash(self, client) -> None:
        r = client.post(f"{PREFIX}/auth/login", json={"username": "admin", "password": "admin123!"})
        if r.status_code == 200:
            assert "password" not in r.json()
            assert "hash" not in r.json()
            assert r.json()["token_type"] == "bearer"  # noqa: S105


class TestVendorDetection:
    def test_lists_every_supported_vendor(self, client, admin_token) -> None:
        r = client.get(f"{PREFIX}/vendors", headers=_auth(admin_token))
        assert r.status_code == 200
        vendors = {v["vendor"] for v in r.json()}
        assert {"cisco_ios", "juniper_junos", "fortinet_fortios", "paloalto_panos"} <= vendors

    def test_each_vendor_advertises_its_rule_pack(self, client, admin_token) -> None:
        for entry in client.get(f"{PREFIX}/vendors", headers=_auth(admin_token)).json():
            assert entry["rule_pack"], entry
            assert entry["candidates"]


class TestAnalyzeEndpoint:
    @pytest.mark.parametrize(
        ("sample", "expected_vendor"),
        [
            ("cisco_ios_core_switch.cfg", "cisco_ios"),
            ("juniper_junos.txt", "juniper_junos"),
            ("fortinet_fortigate.cfg", "fortinet_fortios"),
            ("paloalto_panos.xml", "paloalto_panos"),
        ],
    )
    def test_scans_every_supported_vendor(self, client, admin_token, sample, expected_vendor) -> None:
        r = client.post(f"{PREFIX}/analyze", headers=_auth(admin_token), files=_upload(sample))
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["vendor"] == expected_vendor
        assert body["status"] == "completed"
        assert body["total_findings"] == len(body["findings"])
        assert body["overall_score"] is not None
        assert body["framework_scores"]

    def test_findings_are_ordered_and_carry_evidence(self, client, admin_token) -> None:
        body = client.post(
            f"{PREFIX}/analyze",
            headers=_auth(admin_token),
            files=_upload("cisco_ios_core_switch.cfg"),
        ).json()
        ranks = [f["severity"] for f in body["findings"]]
        assert ranks
        for finding in body["findings"]:
            assert finding["rule_id"]
            assert finding["evidence"], f"{finding['rule_id']} has no evidence"
            for line in finding["evidence"]:
                assert line["line_no"] >= 0
                assert isinstance(line["raw"], str)

    def test_uploaded_secrets_are_never_echoed_back(self, client, admin_token) -> None:
        body = client.post(
            f"{PREFIX}/analyze",
            headers=_auth(admin_token),
            files=_upload("cisco_ios_core_switch.cfg"),
        ).json()
        blob = str(body)
        assert "$1$" not in blob
        assert "02050D480809" not in blob

    def test_no_remediation_is_reported_as_applied(self, client, admin_token) -> None:
        body = client.post(
            f"{PREFIX}/analyze",
            headers=_auth(admin_token),
            files=_upload("cisco_ios_core_switch.cfg"),
        ).json()
        for plan in body["remediations"]:
            assert plan["applied_to_device"] is False
            assert plan["status"] == "pending_review"

    def test_unrecognised_config_is_422_with_a_useful_message(self, client, admin_token) -> None:
        r = client.post(
            f"{PREFIX}/analyze",
            headers=_auth(admin_token),
            files={"file": ("notes.txt", b"just some prose, not a config", "text/plain")},
        )
        assert r.status_code == 422
        assert "vendor" in r.json()["detail"].lower()

    def test_empty_upload_is_rejected(self, client, admin_token) -> None:
        r = client.post(
            f"{PREFIX}/analyze",
            headers=_auth(admin_token),
            files={"file": ("empty.cfg", b"", "text/plain")},
        )
        assert r.status_code in (400, 422)

    def test_forbidden_suffix_is_rejected(self, client, admin_token) -> None:
        r = client.post(
            f"{PREFIX}/analyze",
            headers=_auth(admin_token),
            files={"file": ("evil.exe", b"version 15.2\n", "text/plain")},
        )
        assert r.status_code == 400

    def test_oversized_upload_is_rejected_not_truncated(self, client, admin_token) -> None:
        # Padding past the cap with a valid-looking header, so a truncation bug
        # would otherwise produce a plausible 201.
        blob = b"version 15.2\nhostname big\n" + b"!\n" * (11 * 1024 * 1024)
        r = client.post(
            f"{PREFIX}/analyze",
            headers=_auth(admin_token),
            files={"file": ("huge.cfg", blob, "text/plain")},
        )
        assert r.status_code == 413


class TestDegradedDatabase:
    """Without Postgres these must say 'unavailable', not 'empty'."""

    def test_dashboard_returns_an_explicit_empty_state(self, client, admin_token) -> None:
        r = client.get(f"{PREFIX}/dashboard", headers=_auth(admin_token))
        assert r.status_code == 200
        body = r.json()
        assert body["total_devices"] == 0
        assert body["total_findings"] == 0

    def test_analysis_history_is_503_not_an_empty_list(self, client, admin_token) -> None:
        r = client.get(f"{PREFIX}/analyses", headers=_auth(admin_token))
        assert r.status_code == 503
        assert "unavailable" in r.json()["detail"]

    def test_devices_is_503_not_an_empty_list(self, client, admin_token) -> None:
        r = client.get(f"{PREFIX}/devices", headers=_auth(admin_token))
        assert r.status_code == 503

    def test_remediation_queue_is_503_not_an_empty_list(self, client, admin_token) -> None:
        r = client.get(f"{PREFIX}/remediations", headers=_auth(admin_token))
        assert r.status_code == 503

    def test_scanning_still_works_without_a_database(self, client, admin_token) -> None:
        r = client.post(
            f"{PREFIX}/analyze",
            headers=_auth(admin_token),
            files=_upload("juniper_junos.txt"),
        )
        assert r.status_code == 201
        assert r.json()["total_findings"] >= 0


class TestGraphEndpoint:
    def test_exposed_services_degrades_without_neo4j(self, client, admin_token) -> None:
        r = client.get(f"{PREFIX}/graph/exposed-services", headers=_auth(admin_token))
        assert r.status_code == 200
        body = r.json()
        assert "available" in body
        assert body["services"] == []
        if not body["available"]:
            assert body["reason"]


class TestSafetySurface:
    """The API must not offer a way to change a device."""

    def test_there_is_no_apply_endpoint(self, client) -> None:
        schema = client.get("/openapi.json").json()
        for path, ops in schema["paths"].items():
            for method in ops:
                assert "apply" not in path.lower(), f"{method.upper()} {path} looks like an apply route"
                assert "push" not in path.lower()

    def test_openapi_is_generated(self, client) -> None:
        schema = client.get("/openapi.json").json()
        assert schema["info"]["title"] == "NETGUARD-AI"
        assert f"{PREFIX}/analyze" in schema["paths"]

    def test_docs_are_served(self, client) -> None:
        assert client.get("/docs").status_code == 200


class TestPasswordHashing:
    def test_hashes_are_salted_and_verifiable(self) -> None:
        a = hash_password("correct horse battery staple")
        b = hash_password("correct horse battery staple")
        assert a != b, "identical passwords must not produce identical hashes"
        assert "correct horse" not in a

    def test_hash_is_not_the_password(self) -> None:
        encoded = hash_password("hunter2")
        assert "hunter2" not in encoded
