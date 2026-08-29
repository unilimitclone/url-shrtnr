"""
Account deletion endpoints — DELETE /api/v1/me and POST /auth/restore.

Route tests run a REAL AccountDeletionService over an AsyncMock user
repository (the re-auth and status-guard logic lives in the service, and
"the account stayed ACTIVE" is provable as "the guarded transition was
never called"). The login/OAuth status gates are covered at the service
layer next to the other credential/OAuth service tests; here the login
route pins the wire contract (403 + ``X-Error-Code``).

All DB / Redis / external-service calls are eliminated via
dependency_overrides and a mock lifespan — no real infrastructure needed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

from dependencies import (
    CurrentUser,
    get_account_deletion_service,
    get_credential_service,
    require_jwt,
)
from errors import AccountPendingDeletionError, AuthenticationError
from infrastructure.crypto import hash_password
from routes.api_v1 import router as api_v1_router
from routes.auth import router as auth_router
from schemas.models.user import UserDoc
from services.account_deletion_service import AccountDeletionService
from tests.conftest import build_test_app

# ── Helpers ──────────────────────────────────────────────────────────────────

USER_OID = ObjectId("aaaaaaaaaaaaaaaaaaaaaaaa")
PASSWORD = "CorrectHorse1!"
GRACE_DAYS = 9
PURGE_AFTER = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def make_user_doc(
    email="test@example.com",
    email_verified=True,
    password_set=False,
    password_hash=None,
    status="ACTIVE",
    purge_after=None,
):
    return UserDoc.from_mongo(
        {
            "_id": USER_OID,
            "email": email,
            "email_verified": email_verified,
            "password_hash": password_hash,
            "password_set": password_set,
            "user_name": "Test User",
            "pfp": None,
            "auth_providers": [],
            "plan": "free",
            "signup_ip": None,
            "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
            "updated_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
            "status": status,
            "purge_after": purge_after,
        }
    )


class RecordingMailer:
    """ErasureMailer stand-in that records the grace-period notices."""

    def __init__(self):
        self.requested: list[tuple[str, datetime]] = []

    async def send_deletion_requested(self, email, purge_after):
        self.requested.append((email, purge_after))

    async def send_erasure_confirmation(self, email):
        return None


def make_service(user, *, mailer=None, mark_result=True):
    """Real AccountDeletionService over a mocked user repository.

    ``find_by_id`` answers *user* first (the re-auth fetch), then the
    post-flip read-back with ``purge_after`` stamped.
    """
    repo = AsyncMock()
    pending = make_user_doc(
        email=user.email,
        password_set=user.password_set,
        password_hash=user.password_hash,
        status="PENDING_DELETION",
        purge_after=PURGE_AFTER,
    )
    repo.find_by_id.side_effect = [user, pending]
    repo.find_by_email.return_value = user
    repo.mark_pending_deletion.return_value = mark_result
    repo.restore.return_value = True
    svc = AccountDeletionService(repo, mailer=mailer, grace_days=GRACE_DAYS)
    return svc, repo


def _make_jwt_user() -> CurrentUser:
    return CurrentUser(user_id=USER_OID, email_verified=True, api_key_doc=None)


def _client(svc: AccountDeletionService) -> TestClient:
    app = build_test_app(
        api_v1_router,
        overrides={
            require_jwt: _make_jwt_user,
            get_account_deletion_service: lambda: svc,
        },
    )
    return TestClient(app, raise_server_exceptions=False)


def _auth_client(svc: AccountDeletionService) -> TestClient:
    app = build_test_app(
        auth_router, overrides={get_account_deletion_service: lambda: svc}
    )
    return TestClient(app, raise_server_exceptions=False)


# ── DELETE /api/v1/me — password accounts ────────────────────────────────────


def test_delete_me_wrong_password_403_and_account_stays_active():
    user = make_user_doc(password_set=True, password_hash=hash_password(PASSWORD))
    svc, repo = make_service(user)

    resp = _client(svc).request(
        "DELETE", "/api/v1/me", json={"password": "WrongPass1!"}
    )

    assert resp.status_code == 403
    # The guarded transition never ran — the account is still ACTIVE.
    repo.mark_pending_deletion.assert_not_awaited()


def test_delete_me_missing_reauth_403():
    user = make_user_doc(password_set=True, password_hash=hash_password(PASSWORD))
    svc, repo = make_service(user)

    resp = _client(svc).request("DELETE", "/api/v1/me", json={})

    assert resp.status_code == 403
    repo.mark_pending_deletion.assert_not_awaited()


def test_delete_me_correct_password_200_with_purge_after():
    user = make_user_doc(password_set=True, password_hash=hash_password(PASSWORD))
    mailer = RecordingMailer()
    svc, repo = make_service(user, mailer=mailer)

    resp = _client(svc).request("DELETE", "/api/v1/me", json={"password": PASSWORD})

    assert resp.status_code == 200
    assert resp.json() == {"purge_after": PURGE_AFTER.isoformat()}
    # The flip used the configured grace period.
    assert repo.mark_pending_deletion.await_args.args == (USER_OID, GRACE_DAYS)
    # The grace-period notice went out with the stored deadline.
    assert mailer.requested == [(user.email, PURGE_AFTER)]


def test_delete_me_confirm_email_rejected_for_password_account():
    """A hijacked session must not bypass the password with the typed email."""
    user = make_user_doc(password_set=True, password_hash=hash_password(PASSWORD))
    svc, repo = make_service(user)

    resp = _client(svc).request(
        "DELETE", "/api/v1/me", json={"confirm_email": user.email}
    )

    assert resp.status_code == 403
    repo.mark_pending_deletion.assert_not_awaited()


# ── DELETE /api/v1/me — OAuth-only accounts ──────────────────────────────────


def test_delete_me_oauth_only_confirm_email_succeeds():
    user = make_user_doc(password_set=False, password_hash=None)
    svc, _repo = make_service(user)

    resp = _client(svc).request(
        "DELETE", "/api/v1/me", json={"confirm_email": "test@example.com"}
    )

    assert resp.status_code == 200
    assert resp.json()["purge_after"] == PURGE_AFTER.isoformat()


def test_delete_me_oauth_only_wrong_confirm_email_403():
    user = make_user_doc(password_set=False, password_hash=None)
    svc, repo = make_service(user)

    resp = _client(svc).request(
        "DELETE", "/api/v1/me", json={"confirm_email": "other@example.com"}
    )

    assert resp.status_code == 403
    repo.mark_pending_deletion.assert_not_awaited()


def test_delete_me_oauth_only_password_path_rejected():
    """No password exists — supplying one must never re-authenticate."""
    user = make_user_doc(password_set=False, password_hash=None)
    svc, repo = make_service(user)

    resp = _client(svc).request("DELETE", "/api/v1/me", json={"password": "AnyPass1!"})

    assert resp.status_code == 403
    repo.mark_pending_deletion.assert_not_awaited()


# ── DELETE /api/v1/me — repeat + auth ────────────────────────────────────────


def test_delete_me_second_request_409():
    user = make_user_doc(
        password_set=True,
        password_hash=hash_password(PASSWORD),
        status="PENDING_DELETION",
        purge_after=PURGE_AFTER,
    )
    svc, repo = make_service(user)

    resp = _client(svc).request("DELETE", "/api/v1/me", json={"password": PASSWORD})

    assert resp.status_code == 409
    repo.mark_pending_deletion.assert_not_awaited()


def test_delete_me_lost_race_409():
    """Guarded transition returns False (concurrent request won) → 409."""
    user = make_user_doc(password_set=True, password_hash=hash_password(PASSWORD))
    svc, _repo = make_service(user, mark_result=False)

    resp = _client(svc).request("DELETE", "/api/v1/me", json={"password": PASSWORD})

    assert resp.status_code == 409


def test_delete_me_requires_auth():
    def _raise_unauth() -> CurrentUser:
        raise AuthenticationError("Authentication required")

    app = build_test_app(
        api_v1_router,
        overrides={
            require_jwt: _raise_unauth,
            get_account_deletion_service: lambda: AsyncMock(),
        },
    )
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.request("DELETE", "/api/v1/me", json={"password": PASSWORD})

    assert resp.status_code == 401


# ── Login while pending — wire contract ──────────────────────────────────────


def test_login_while_pending_403_with_error_code_header():
    credential_svc = AsyncMock()
    credential_svc.login.side_effect = AccountPendingDeletionError(
        "this account is scheduled for deletion"
    )
    app = build_test_app(
        auth_router, overrides={get_credential_service: lambda: credential_svc}
    )

    # Context-managed: the login route reads jwt config off app.state,
    # which only exists once the (mock) lifespan has run.
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post(
            "/auth/login", json={"email": "test@example.com", "password": PASSWORD}
        )

    assert resp.status_code == 403
    assert resp.headers["X-Error-Code"] == "ACCOUNT_PENDING_DELETION"
    assert resp.json()["code"] == "ACCOUNT_PENDING_DELETION"


# ── POST /auth/restore ───────────────────────────────────────────────────────


def _pending_user(password_hash):
    return make_user_doc(
        password_set=True,
        password_hash=password_hash,
        status="PENDING_DELETION",
        purge_after=PURGE_AFTER,
    )


def test_restore_happy_path_reactivates_account():
    hashed = hash_password(PASSWORD)
    svc, repo = make_service(_pending_user(hashed))
    repo.find_by_email.return_value = _pending_user(hashed)
    client = _auth_client(svc)

    resp = client.post(
        "/auth/restore", json={"email": "test@example.com", "password": PASSWORD}
    )

    assert resp.status_code == 200
    assert resp.json()["success"] is True
    assert repo.restore.await_args.args == (USER_OID,)


def test_restore_failures_are_uniform_403():
    """Wrong password, not-pending, unknown email, and purged all answer
    with an identical 403 body — no account enumeration."""
    hashed = hash_password(PASSWORD)
    bodies = []

    # Wrong password.
    svc, repo = make_service(_pending_user(hashed))
    repo.find_by_email.return_value = _pending_user(hashed)
    resp = _auth_client(svc).post(
        "/auth/restore", json={"email": "test@example.com", "password": "Wrong1!"}
    )
    assert resp.status_code == 403
    repo.restore.assert_not_awaited()
    bodies.append(resp.json())

    # Not pending (repo guard refuses the transition).
    svc, repo = make_service(_pending_user(hashed))
    repo.find_by_email.return_value = make_user_doc(
        password_set=True, password_hash=hashed, status="ACTIVE"
    )
    repo.restore.return_value = False
    resp = _auth_client(svc).post(
        "/auth/restore", json={"email": "test@example.com", "password": PASSWORD}
    )
    assert resp.status_code == 403
    bodies.append(resp.json())

    # Unknown email — including an account already purged by the sweep.
    svc, repo = make_service(_pending_user(hashed))
    repo.find_by_email.return_value = None
    resp = _auth_client(svc).post(
        "/auth/restore", json={"email": "gone@example.com", "password": PASSWORD}
    )
    assert resp.status_code == 403
    bodies.append(resp.json())

    assert bodies[0] == bodies[1] == bodies[2]


def test_restore_after_purge_403():
    """User doc already erased by the sweep — same uniform 403."""
    svc, repo = make_service(_pending_user(hash_password(PASSWORD)))
    repo.find_by_email.return_value = None
    client = _auth_client(svc)

    resp = client.post(
        "/auth/restore", json={"email": "test@example.com", "password": PASSWORD}
    )

    assert resp.status_code == 403
    repo.restore.assert_not_awaited()


def test_restore_oauth_only_account_403():
    """No password hash — the endpoint can't validate, uniform 403."""
    svc, repo = make_service(_pending_user(None))
    repo.find_by_email.return_value = make_user_doc(
        password_set=False, password_hash=None, status="PENDING_DELETION"
    )
    client = _auth_client(svc)

    resp = client.post(
        "/auth/restore", json={"email": "test@example.com", "password": PASSWORD}
    )

    assert resp.status_code == 403
    repo.restore.assert_not_awaited()


# ── Service seam — mail failure never blocks the request ────────────────────


class ExplodingMailer(RecordingMailer):
    async def send_deletion_requested(self, email, purge_after):
        raise RuntimeError("smtp down")


@pytest.mark.asyncio
async def test_request_deletion_survives_mail_outage():
    user = make_user_doc(password_set=True, password_hash=hash_password(PASSWORD))
    svc, _repo = make_service(user, mailer=ExplodingMailer())

    purge_after = await svc.request_deletion(
        USER_OID, password=PASSWORD, confirm_email=None
    )

    assert purge_after == PURGE_AFTER


@pytest.mark.asyncio
async def test_request_deletion_computes_deadline_when_readback_races():
    """Read-back losing a race with the sweep still yields a deadline."""
    user = make_user_doc(password_set=True, password_hash=hash_password(PASSWORD))
    repo = AsyncMock()
    repo.find_by_id.side_effect = [user, None]
    repo.mark_pending_deletion.return_value = True
    svc = AccountDeletionService(repo, grace_days=GRACE_DAYS)

    before = datetime.now(timezone.utc)
    purge_after = await svc.request_deletion(
        USER_OID, password=PASSWORD, confirm_email=None
    )

    assert purge_after >= before + timedelta(days=GRACE_DAYS, seconds=-5)


def test_get_account_deletion_service_reads_app_state():
    """The real dependency (overridden everywhere above) resolves from
    app.state, where wire_services parks the singleton."""
    from unittest.mock import MagicMock

    request = MagicMock()
    resolved = get_account_deletion_service(request)
    assert resolved is request.app.state.account_deletion_service
