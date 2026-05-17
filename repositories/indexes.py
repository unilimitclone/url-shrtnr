"""MongoDB index + collection setup. Idempotent.

Data migrations live under ``infrastructure/bootstrap/`` and must run before
this — see lifespan ordering in app.py.
"""

from __future__ import annotations

from pymongo.asynchronous.database import AsyncDatabase
from pymongo.errors import CollectionInvalid, OperationFailure

from infrastructure.logging import get_logger

log = get_logger(__name__)


async def ensure_indexes(db: AsyncDatabase) -> None:
    users_col = db["users"]
    urls_v2_col = db["urlsV2"]
    clicks_col = db["clicks"]
    api_keys_col = db["api-keys"]
    tokens_col = db["verification-tokens"]

    # ── users ──────────────────────────────────────────────────────────────
    await users_col.create_index([("email", 1)], unique=True)
    await users_col.create_index(
        [
            ("auth_providers.provider", 1),
            ("auth_providers.provider_user_id", 1),
        ],
        unique=True,
        sparse=True,
    )
    await users_col.create_index([("auth_providers.provider", 1)])

    # ── urlsV2 ─────────────────────────────────────────────────────────────
    # Per-domain alias namespace via compound unique. Replaces the legacy
    # global ``alias_1`` unique which would collide same-alias-different-domain
    # once custom domains land.
    await urls_v2_col.create_index([("domain", 1), ("alias", 1)], unique=True)
    # Drop the obsolete global unique left over from pre-PR1 deploys.
    # Code 27 = IndexNotFound — expected on every boot after the first run,
    # so log only the actual-drop case to keep steady-state logs quiet.
    try:
        await urls_v2_col.drop_index("alias_1")
        log.info("legacy_alias_index_dropped", index="alias_1")
    except OperationFailure as e:
        if getattr(e, "code", None) != 27:
            raise
    await urls_v2_col.create_index([("owner_id", 1)])
    await urls_v2_col.create_index([("owner_id", 1), ("created_at", -1)])
    await urls_v2_col.create_index([("total_clicks", -1)])
    await urls_v2_col.create_index([("last_click", -1)])

    # ── clicks (time-series) ───────────────────────────────────────────────
    # Create the time-series collection if it doesn't exist yet.
    # Already-existing collection raises OperationFailure — swallow it.
    try:
        await db.create_collection(
            "clicks",
            timeseries={
                "timeField": "clicked_at",
                "metaField": "meta",
                "granularity": "seconds",
            },
        )
    except (CollectionInvalid, OperationFailure) as e:
        # Error code 48 = NamespaceExists (collection already exists) — expected on every
        # boot after the first. Any other OperationFailure (permissions, bad options, etc.)
        # is a real problem and should propagate.
        if isinstance(e, CollectionInvalid) or getattr(e, "code", None) == 48:
            pass
        else:
            raise

    await clicks_col.create_index([("meta.url_id", 1), ("clicked_at", -1)])
    await clicks_col.create_index([("clicked_at", -1)])
    # CRITICAL: for user-level analytics (scope=all queries)
    await clicks_col.create_index([("meta.owner_id", 1), ("clicked_at", -1)])
    # for anonymous stats (scope=anon, by short_code)
    await clicks_col.create_index([("meta.short_code", 1), ("clicked_at", -1)])
    # sparse — older buckets have no meta.domain, index stays small
    await clicks_col.create_index([("meta.domain", 1), ("clicked_at", -1)], sparse=True)

    # ── api-keys ───────────────────────────────────────────────────────────
    await api_keys_col.create_index([("user_id", 1)])
    await api_keys_col.create_index([("token_hash", 1)], unique=True)
    await api_keys_col.create_index([("expires_at", 1)], expireAfterSeconds=0)

    # ── verification-tokens ────────────────────────────────────────────────
    await tokens_col.create_index([("user_id", 1)])
    await tokens_col.create_index([("token_hash", 1)])
    await tokens_col.create_index([("token_type", 1)])
    await tokens_col.create_index([("expires_at", 1)], expireAfterSeconds=0)
    await tokens_col.create_index(
        [("user_id", 1), ("token_type", 1), ("used_at", 1), ("created_at", -1)],
        name="ix_latest_unused_by_user",
    )

    # ── app-grants ─────────────────────────────────────────────────────
    app_grants_col = db["app-grants"]
    await app_grants_col.create_index([("user_id", 1), ("app_id", 1)], unique=True)
    await app_grants_col.create_index([("user_id", 1), ("revoked_at", 1)])
    await app_grants_col.create_index([("app_id", 1), ("revoked_at", 1)])

    # ── feature-flags ──────────────────────────────────────────────────
    feature_flags_col = db["feature_flags"]
    await feature_flags_col.create_index([("name", 1)], unique=True)

    # ── custom_domains ────────────────────────────────────────────────
    custom_domains_col = db["custom_domains"]
    # Partial unique on fqdn — REVOKED docs preserved for audit don't reserve
    # the fqdn. DCV at register-time is the takeover gate.
    try:
        await custom_domains_col.drop_index("fqdn_1")
        log.info("legacy_custom_domain_fqdn_index_dropped", index="fqdn_1")
    except OperationFailure as e:
        if getattr(e, "code", None) != 27:
            raise
    await custom_domains_col.create_index(
        [("fqdn", 1)],
        unique=True,
        partialFilterExpression={
            "status": {"$in": ["pending", "verifying", "active", "suspended"]}
        },
        name="fqdn_unique_non_revoked",
    )
    await custom_domains_col.create_index([("owner_id", 1), ("created_at", -1)])
    await custom_domains_col.create_index([("status", 1), ("last_verified_at", 1)])

    log.info("mongodb_indexes_ensured")
