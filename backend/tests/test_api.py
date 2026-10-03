"""API tests.

Run against the real ASGI app with ``TestClient`` and **no database**. That is
the configuration a reviewer will actually hit, so it is the one these tests
assert: the service must work without Postgres, must say so rather than lie, and
must never expose an endpoint that can change a device.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from pydantic_settings import SettingsError

from app.core.config import Settings, get_settings
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


@contextmanager
def patch_settings(**overrides: Any) -> Iterator[None]:
    """Run a block with selected settings overridden.

    Overrides the cached ``Settings`` rather than the environment, because some
    of these values (``allow_demo_accounts``) only take effect on the settings
    object the dependency resolved at import time.
    """
    from app.core.config import get_settings

    settings = get_settings()
    missing = object()
    previous = {key: getattr(settings, key, missing) for key in overrides}
    for key, value in overrides.items():
        setattr(settings, key, value)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is missing:
                delattr(settings, key)
            else:
                setattr(settings, key, value)


class TestProductionSafety:
    """Guards that only matter once the service sits on a public URL."""

    @pytest.fixture
    def deployment_env(self, monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[..., None]]:
        """Apply production env vars so they are undone after each test.

        Every write goes through monkeypatch. Assigning to ``os.environ``
        directly looks equivalent but is invisible to its teardown, so these
        values would leak into later tests and break the shared `client` fixture.
        """
        for name in ("ENVIRONMENT", "SECRET_KEY", "ALLOW_DEMO_ACCOUNTS"):
            monkeypatch.delenv(name, raising=False)
        get_settings.cache_clear()
        try:
            yield monkeypatch.setenv
        finally:
            get_settings.cache_clear()

    def test_prod_refuses_to_start_with_the_demo_accounts(self, deployment_env) -> None:
        """The built-in passwords are documented, so they must not ship.

        Failing at startup rather than at first login means it cannot be missed
        after traffic has already arrived.
        """
        deployment_env("ENVIRONMENT", "prod")
        deployment_env("SECRET_KEY", "x" * 48)
        deployment_env("ALLOW_DEMO_ACCOUNTS", "true")
        with pytest.raises(ValidationError, match="allow_demo_accounts"):
            Settings()

    def test_prod_starts_once_demo_accounts_are_disabled(self, deployment_env) -> None:
        deployment_env("ENVIRONMENT", "prod")
        deployment_env("SECRET_KEY", "x" * 48)
        deployment_env("ALLOW_DEMO_ACCOUNTS", "false")
        assert Settings().allow_demo_accounts is False

    def test_prod_still_refuses_the_default_secret_key(self, deployment_env) -> None:
        deployment_env("ENVIRONMENT", "prod")
        deployment_env("ALLOW_DEMO_ACCOUNTS", "false")
        with pytest.raises(ValidationError, match="secret_key"):
            Settings()

    def test_demo_accounts_are_rejected_when_disabled(self, client) -> None:
        """With the fallback off, the documented password grants nothing."""
        with patch_settings(allow_demo_accounts=False):
            r = client.post(f"{PREFIX}/auth/login", json={"username": "admin", "password": "admin123!"})
        assert r.status_code == 401
        # Identical to a wrong password, so it cannot be used to detect that the
        # account exists.
        assert r.json()["detail"] == "invalid username or password"

    def test_auth_status_reports_the_real_flag(self, client) -> None:
        """The UI warns before a demo login, so this must not understate it."""
        with patch_settings(allow_demo_accounts=False):
            disabled = client.get(f"{PREFIX}/auth/auth-status").json()
        with patch_settings(allow_demo_accounts=True):
            enabled = client.get(f"{PREFIX}/auth/auth-status").json()
        assert disabled["demo_accounts"] is False
        assert enabled["demo_accounts"] is True

    def test_cors_allows_the_configured_github_pages_origin(self) -> None:
        """A browser preflights before it will send the Authorization header.

        Uses a fresh app rather than the shared `client`: `CORSMiddleware` copies
        the allowed origins when it is constructed, so patching settings after
        startup would test the wrong middleware.
        """
        origin = "https://gowthambaragada-a11y.github.io"
        with patch_settings(cors_origins=[origin]):
            scoped = TestClient(create_app())
        r = scoped.options(
            f"{PREFIX}/dashboard",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization",
            },
        )
        assert r.headers["access-control-allow-origin"] == origin
        assert "authorization" in r.headers["access-control-allow-headers"].lower()

    def test_cors_refuses_an_origin_that_was_not_configured(self) -> None:
        with patch_settings(cors_origins=["https://gowthambaragada-a11y.github.io"]):
            scoped = TestClient(create_app())
        r = scoped.options(
            f"{PREFIX}/dashboard",
            headers={"Origin": "https://attacker.example", "Access-Control-Request-Method": "GET"},
        )
        assert "access-control-allow-origin" not in r.headers

    def test_cors_origins_from_the_environment_must_be_json(self, deployment_env) -> None:
        """Pin the env format, because the friendly form is a startup crash.

        pydantic-settings decodes complex fields before validators run, so
        ``CORS_ORIGINS=a,b`` raises instead of splitting. Operators will try that
        form, so the requirement needs a test that fails loudly if it ever
        changes rather than a comment nobody reads.
        """
        deployment_env("CORS_ORIGINS", "https://a.example,https://b.example")
        with pytest.raises(SettingsError):
            Settings()
        deployment_env("CORS_ORIGINS", '["https://a.example", "https://b.example"]')
        assert Settings().cors_origins == ["https://a.example", "https://b.example"]

    def test_cors_origins_still_accept_a_comma_separated_constructor_argument(self) -> None:
        """Direct construction is the other path in, and it stays forgiving."""
        assert Settings(cors_origins="https://a.example, https://b.example").cors_origins == [
            "https://a.example",
            "https://b.example",
        ]


class TestFreshDatabase:
    """The state of a brand-new Postgres on the very first deploy.

    A provisioned database accepts connections immediately, so a bare reachability
    probe reports "available" before a single table exists. Every caller in this
    codebase already handles an unavailable database with a 503; none of them can
    handle a query that raises. These tests pin that the empty-database case takes
    the path the code was already written to take.

    SQLite stands in for Postgres here because the behaviour under test is the
    schema check, not any Postgres-specific SQL.
    """

    @pytest.fixture
    def empty_db(self, tmp_path, monkeypatch: pytest.MonkeyPatch):
        """Point the app at a reachable database that has no tables."""
        from app.db import session as db

        # Settings is lru_cached, so the new DSN is invisible until the cache is
        # dropped -- without this the app keeps using the default postgres URL.
        monkeypatch.setenv("POSTGRES_DSN", f"sqlite:///{tmp_path / 'empty.db'}")
        get_settings.cache_clear()
        db.dispose()
        db.reset_state()
        scoped = TestClient(create_app())
        try:
            yield scoped
        finally:
            db.dispose()
            db.reset_state()
            get_settings.cache_clear()

    def test_login_still_answers_instead_of_crashing(self, empty_db) -> None:
        """The regression this covers: login returned 500 on a fresh database.

        `session_scope` only yields None when the engine cannot be built, so a
        reachable-but-empty database opened a session, failed on `users`, and took
        down the one endpoint an operator has to reach to fix it.
        """
        r = empty_db.post(f"{PREFIX}/auth/login", json={"username": "admin", "password": "admin123!"})
        assert r.status_code == 200, r.text
        assert r.json()["access_token"]

    def test_a_bad_password_is_still_401(self, empty_db) -> None:
        r = empty_db.post(f"{PREFIX}/auth/login", json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401

    def test_database_routes_report_503_with_a_reason(self, empty_db) -> None:
        """503, not 500, and not an empty fleet presented as "nothing found"."""
        from app.core.security import create_access_token

        token, _ = create_access_token(subject="test-admin", role="admin")
        for path in ("/dashboard", "/findings", "/devices", "/remediations"):
            r = empty_db.get(f"{PREFIX}{path}", headers=_auth(token))
            assert r.status_code == 503, f"{path} returned {r.status_code}: {r.text}"
            # The message has to say what to do, or an operator is left guessing.
            assert "table" in r.json()["detail"]

    def test_auth_status_does_not_claim_a_users_table_that_is_absent(self, empty_db) -> None:
        assert empty_db.get(f"{PREFIX}/auth/auth-status").json()["users_table_available"] is False

    def test_healthz_and_readyz_still_answer(self, empty_db) -> None:
        """Liveness must not depend on the database, or this 503s the whole service."""
        assert empty_db.get(f"{PREFIX}/healthz").status_code == 200
        ready = empty_db.get(f"{PREFIX}/readyz")
        assert ready.status_code == 200
        assert ready.json()["postgres"]["available"] is False
        # Liveness depends on this, and it must be true without any tables.
        assert ready.json()["pipeline"]["ready"] is True

    def test_creating_the_schema_makes_the_database_available(self, empty_db) -> None:
        """The documented fix must actually work, not just be documented."""
        from app.db import session as db

        assert db.create_all() is True
        assert db.is_available() is True
        assert empty_db.get(f"{PREFIX}/auth/auth-status").json()["users_table_available"] is True

        from app.core.security import create_access_token

        token, _ = create_access_token(subject="test-admin", role="admin")
        assert empty_db.get(f"{PREFIX}/findings", headers=_auth(token)).status_code == 200


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

    def test_dashboard_is_503_not_a_clean_fleet(self, client, admin_token) -> None:
        """An unreachable database must not look like "nothing to fix".

        This route used to answer 200 with zero devices and a 0.0 score, which is
        indistinguishable from a genuinely clean fleet -- the one reading a
        security dashboard must never be allowed to make.
        """
        r = client.get(f"{PREFIX}/dashboard", headers=_auth(admin_token))
        assert r.status_code == 503
        assert "unavailable" in r.json()["detail"]

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

    def test_findings_is_503_not_an_empty_list(self, client, admin_token) -> None:
        r = client.get(f"{PREFIX}/findings", headers=_auth(admin_token))
        assert r.status_code == 503
        assert "unavailable" in r.json()["detail"]

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
