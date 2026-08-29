"""Pending-deletion lifecycle against real MongoDB.

``mark_pending_deletion`` / ``claim_for_erasure`` / ``restore`` are guarded
updates whose whole behavior lives in their filters — exactly where mock
evaluators drift from the server. These run the real predicates.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

LEASE_SECONDS = 900


async def _insert_active_user(real_db, email: str):
    result = await real_db["users"].insert_one(
        {
            "email": email,
            "email_verified": True,
            "status": "ACTIVE",
            "created_at": datetime(2026, 7, 1, 9, 0, 0),
        }
    )
    return result.inserted_id


async def test_mark_pending_deletion_flips_only_active(real_db, user_repo):
    uid = await _insert_active_user(real_db, "lifecycle-a@example.com")
    now = datetime.now(timezone.utc)

    assert await user_repo.mark_pending_deletion(uid, grace_days=30, now=now)
    doc = await real_db["users"].find_one({"_id": uid})
    assert doc["status"] == "PENDING_DELETION"
    assert doc["deletion_requested_at"] == doc["purge_after"] - timedelta(days=30)

    # Repeat request is a no-op — the guarded filter matches ACTIVE only.
    assert not await user_repo.mark_pending_deletion(uid, grace_days=30, now=now)


async def test_claim_for_erasure_lease_semantics(real_db, user_repo):
    uid = await _insert_active_user(real_db, "lifecycle-b@example.com")
    now = datetime.now(timezone.utc)

    assert await user_repo.mark_pending_deletion(uid, grace_days=7, now=now)

    # Not purge-due yet: the claim must refuse.
    assert not await user_repo.claim_for_erasure(
        uid, now=now, lease_seconds=LEASE_SECONDS
    )

    # Past the deadline the claim holds and flips the doc to ERASING.
    due = now + timedelta(days=7, seconds=1)
    assert await user_repo.claim_for_erasure(uid, now=due, lease_seconds=LEASE_SECONDS)
    doc = await real_db["users"].find_one({"_id": uid})
    assert doc["status"] == "ERASING"

    # A fresh claim marks a LIVE cascade — a second runner cannot steal it.
    assert not await user_repo.claim_for_erasure(
        uid, now=due + timedelta(seconds=60), lease_seconds=LEASE_SECONDS
    )

    # Once the lease expires the crashed cascade is re-claimable.
    assert await user_repo.claim_for_erasure(
        uid,
        now=due + timedelta(seconds=LEASE_SECONDS + 1),
        lease_seconds=LEASE_SECONDS,
    )

    # Claimed means final: restore must never resurrect a half-erased account.
    assert not await user_repo.restore(uid)


async def test_restore_cancels_pending_deletion(real_db, user_repo):
    uid = await _insert_active_user(real_db, "lifecycle-c@example.com")
    now = datetime.now(timezone.utc)

    assert await user_repo.mark_pending_deletion(uid, grace_days=0, now=now)
    assert await user_repo.restore(uid)

    doc = await real_db["users"].find_one({"_id": uid})
    assert doc["status"] == "ACTIVE"
    assert "purge_after" not in doc
    assert "deletion_requested_at" not in doc

    # Restored accounts are no longer claimable, even though the old
    # deadline has passed — the guarded claim matches PENDING_DELETION only.
    assert not await user_repo.claim_for_erasure(
        uid, now=now + timedelta(days=1), lease_seconds=LEASE_SECONDS
    )
