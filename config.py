"""
Application configuration via pydantic-settings.

All settings are loaded from environment variables (and .env file).

Decision on secret key env var: kept as SECRET_KEY for the new app, but
FLASK_SECRET_KEY is also accepted as an alias for backward compatibility
(handled in AppSettings via model_validator).
"""

from __future__ import annotations

from functools import cached_property
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    mongodb_uri: str
    db_name: str = "url-shortener"
    max_pool_size: int = 200
    min_pool_size: int = 10


class RedisSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Optional — self-hosters without Redis get degraded-but-functional behaviour
    redis_uri: str | None = None
    redis_ttl_seconds: int = 3600

    # Feature flag cache TTLs. Positive results cached for `feature_flag_ttl_seconds`
    # so flag flips propagate within that window. Negative results (unregistered
    # flag names) cached for a shorter window so newly-registered flags become
    # visible faster than the positive TTL.
    feature_flag_ttl_seconds: int = 60
    feature_flag_negative_ttl_seconds: int = 30


class JWTSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    jwt_issuer: str = "spoo.me"
    jwt_audience: str = "spoo.me.api"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 2592000
    cookie_secure: bool = True

    # RS256 keys (preferred)
    jwt_private_key: str = ""
    jwt_public_key: str = ""

    # HS256 fallback (used when RS256 keys are absent)
    jwt_secret: str = ""

    @property
    def use_rs256(self) -> bool:
        return bool(self.jwt_private_key and self.jwt_public_key)


class OAuthProviderSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    google_oauth_client_id: str = ""
    google_oauth_client_secret: str = ""
    google_oauth_redirect_uri: str = ""

    github_oauth_client_id: str = ""
    github_oauth_client_secret: str = ""
    github_oauth_redirect_uri: str = ""

    discord_oauth_client_id: str = ""
    discord_oauth_client_secret: str = ""
    discord_oauth_redirect_uri: str = ""


class EmailSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    zepto_api_token: str = ""
    zepto_from_email: str = "noreply@spoo.me"
    zepto_from_name: str = "spoo.me"


class LoggingSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    log_level: str = "INFO"
    log_format: str = "console"  # "json" in production

    # Sampling rates (0.0-1.0)
    sample_rate_redirect: float = 0.05
    sample_rate_stats: float = 0.20
    sample_rate_cache: float = 0.01
    sample_rate_export: float = 0.80


class SentrySettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    sentry_dsn: str = ""
    sentry_send_pii: bool = False
    sentry_traces_sample_rate: float = 0.1
    sentry_profile_sample_rate: float = 0.05

    @property
    def client_key(self) -> str:
        """Extract the public key from the DSN for the frontend loader script."""
        if not self.sentry_dsn:
            return ""
        try:
            return urlparse(self.sentry_dsn).username or ""
        except Exception:
            return ""


class CustomDomainSettings(BaseSettings):
    """User-bring-your-own-domain feature config.

    All fields default to safe values that keep the feature off until the
    rollout flag flips. ``enabled`` is the master switch consulted by the
    service layer (PR5+); the data plumbing (schema, repo, wiring) lands
    even when False so the rollout has a clean code path to flip.

    All env vars must be prefixed ``CUSTOM_DOMAINS_`` so generic names
    like ``ENABLED`` or ``MAX_PER_USER`` set elsewhere in the deploy
    environment don't accidentally configure this feature.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        env_prefix="CUSTOM_DOMAINS_",
    )

    # Master switch consulted by CustomDomainService. Until True, every
    # public method short-circuits with FeatureDisabledError.
    enabled: bool = False

    # Quotas. Flat for all users in v1 (no tier branching).
    # All counts must be >= 1 — a zero quota silently bricks the feature
    # (every create raises QuotaExceeded with no log signal that the cause
    # is config, not abuse). Validators below fail container startup instead.
    max_per_user: int = Field(default=1, ge=1)
    # Generous because CF's own DCV cadence can take 5-15 min per probe;
    # legitimate users may poll many times during initial activation.
    verify_attempts_per_hour: int = Field(default=60, ge=1)

    # Background re-verify worker tunables.
    # interval=0 would busy-loop the worker; batch=0 wastes a tick;
    # max_age<=0 would suspend every active domain on first tick.
    reverify_interval_seconds: int = Field(default=3600, ge=1)
    reverify_batch_size: int = Field(default=10, ge=1)
    max_verify_age_seconds: int = Field(default=7 * 24 * 3600, ge=1)
    suspend_after_consecutive_failures: int = Field(default=3, ge=1)

    # Cloudflare for SaaS Custom Hostnames. Both required when `enabled=True` —
    # the service raises FeatureDisabledError when missing so OSS forks without
    # CF still boot cleanly.
    cf_zone_id: str | None = None
    cf_api_token: str | None = None
    # CNAME target customers point their hostnames at. Proxied (orange-cloud)
    # in the spoo.me zone; CF SaaS dispatches matched traffic to the zone
    # fallback_origin (proxy-fallback.spoo.me) which lands on Caddy :443.
    cf_cname_target: str = "customers.spoo.me"
    # Per-zone delegation hostname for Delegated DCV (optional path; HTTP DCV
    # is the default). When set, customers using cf_delegated_dcv add
    # `_acme-challenge.<fqdn> CNAME <fqdn>.<this value>` so CF auto-renews
    # without re-probing. Empty disables the second-CNAME instruction.
    cf_dcv_delegation_target: str = ""
    # Retry policy for CF API calls. Three attempts with exponential backoff.
    cf_api_max_retries: int = Field(default=3, ge=1)
    cf_api_initial_backoff_seconds: float = Field(default=1.0, gt=0)

    @model_validator(mode="after")
    def _validate_cf_saas_config(self) -> CustomDomainSettings:
        if self.cf_zone_id and not self.cf_api_token:
            raise ValueError(
                "CF SaaS path requires cf_api_token when cf_zone_id is set."
            )
        return self


# Consumer groups the click worker knows how to run. Adding a new consumer =
# implement it in workers/click_worker.py and register its name here.
CLICK_WORKER_GROUPS = ("stats", "hotness")


class ClickEventsSettings(BaseSettings):
    """Click event pipeline config (lean redirect path + fanout consumers).

    Defaults keep the feature fully off: ``sink="inline"`` preserves the
    classic synchronous tracking byte-for-byte — no stream, no queue Redis,
    no worker required. Stream mode additionally requires
    ``queue_redis_uri`` pointing at a SEPARATE Redis instance from the URL
    cache: the cache runs ``allkeys-lru`` and would silently evict stream
    entries (= click loss); the queue Redis must run ``noeviction`` + AOF.

    All env vars are prefixed ``CLICK_EVENTS_`` so generic names set
    elsewhere in the deploy environment don't accidentally configure this
    feature (same convention as ``CUSTOM_DOMAINS_``).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        env_prefix="CLICK_EVENTS_",
    )

    # Master switch: "inline" = classic synchronous tracking (default),
    # "stream" = emit to the Redis Stream and let the worker consume.
    sink: Literal["inline", "stream"] = "inline"
    queue_redis_uri: str = ""

    stream: str = "events:clicks"
    dlq_stream: str = "events:clicks:dlq"
    # Acked-history tail kept in the stream (XADD ACKED MAXLEN ~, Redis 8.2+):
    # every publish sweeps entries beyond this that ALL groups have acked, so
    # consumed history self-cleans server-side (~7MB at the default). Unacked
    # backlog is never trimmed regardless of size — its only bound is the
    # queue Redis noeviction memory cap (backpressure → inline fallback).
    maxlen: int = Field(default=10_000, ge=1000)

    # Consumer tunables.
    batch_size: int = Field(default=100, ge=1)
    block_ms: int = Field(default=2000, ge=100)
    # Pending messages idle longer than claim_idle_ms are reclaimed by the
    # claimer subscriber (XAUTOCLAIM); after max_deliveries failed attempts
    # a message is dead-lettered to dlq_stream.
    claim_idle_ms: int = Field(default=60_000, ge=1000)
    max_deliveries: int = Field(default=5, ge=1)
    stats_interval_seconds: float = Field(default=30.0, gt=0)

    # Which consumer groups this worker process runs. Lets a future
    # deployment split groups across containers without code changes.
    worker_groups: list[str] = Field(default=list(CLICK_WORKER_GROUPS))

    # Hot-URL detection (fixed window counters; threshold mirrors the
    # cf-edge plan's 50 hits / 60s promotion rule).
    hotness_enabled: bool = False
    hot_threshold: int = Field(default=50, ge=2)
    hot_window_seconds: int = Field(default=60, ge=10)

    @field_validator("worker_groups")
    @classmethod
    def _known_groups_only(cls, v: list[str]) -> list[str]:
        unknown = set(v) - set(CLICK_WORKER_GROUPS)
        if unknown:
            raise ValueError(
                f"Unknown click worker group(s): {sorted(unknown)}. "
                f"Known groups: {list(CLICK_WORKER_GROUPS)}"
            )
        if not v:
            raise ValueError("worker_groups must not be empty")
        return v


class EdgeCacheSettings(BaseSettings):
    """CF edge cache for hot URLs — a deployment optimization, never a
    product requirement (design: thoughts/cf-edge-cache-v2.md).

    Fully off unless ALL THREE Cloudflare fields are set. Promotion rides
    the hotness consumer, so stream mode + hotness are prerequisites.
    Invalidation in v1 is TTL-only: entries self-expire, and
    ``wrangler kv key delete`` is the manual purge / abuse-takedown lever.

    Env vars prefixed ``EDGE_CACHE_`` (same convention as
    ``CUSTOM_DOMAINS_`` / ``CLICK_EVENTS_``).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        env_prefix="EDGE_CACHE_",
    )

    # The Workers KV REST API is account-scoped:
    # /accounts/{account_id}/storage/kv/namespaces/{namespace_id}/values/{key}
    cf_account_id: str | None = None
    cf_api_token: str | None = None  # Workers KV write scope only
    kv_namespace_id: str | None = None
    # Local-dev emulator override: point at wrangler dev's Explorer API
    # (http://host.docker.internal:8787/cdn-cgi/explorer/api), which
    # mirrors the same /storage/kv/... paths. Unset in real deployments —
    # the production URL derives from cf_account_id.
    api_base: str | None = None
    # Dev-only companion to api_base: wrangler dev validates the Host
    # header (localhost forms only), so containers reaching it through
    # host.docker.internal must present "localhost:8787".
    api_host_header: str | None = None

    # Entry lifetime at the edge. Deliberately short: with TTL-only
    # invalidation this IS the worst-case staleness bound after a URL
    # changes. Raising it trades origin load for staleness.
    ttl_seconds: int = Field(default=300, ge=60)
    # ±jitter so simultaneously-promoted URLs don't expire in lockstep
    # and stampede origin together.
    ttl_jitter_ratio: float = Field(default=0.2, ge=0.0, le=0.5)

    @property
    def enabled(self) -> bool:
        return bool(
            self.cf_api_token
            and self.kv_namespace_id
            and (self.cf_account_id or self.api_base)
        )


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Core
    secret_key: str = ""
    flask_secret_key: str = ""  # backward-compat alias
    app_version: str = "dev"  # injected by CI via the APP_VERSION build arg
    env: str = "development"
    app_url: str = "https://spoo.me"
    app_name: str = "spoo.me"

    @cached_property
    def system_default_domain(self) -> str:
        """Canonical fqdn for shorts created without an explicit custom domain."""
        # Hard fail rather than fall back — a wrong APP_URL silently
        # mis-attributes every short to the wrong host.
        parsed = urlparse(self.app_url)
        if not parsed.scheme or not parsed.hostname:
            raise ValueError(
                f"APP_URL is missing or invalid: {self.app_url!r}. "
                "Set APP_URL to your shortener's public URL (e.g. https://spoo.me)."
            )
        return parsed.hostname.lower().rstrip(".")

    @cached_property
    def blocked_self_domains(self) -> tuple[str, ...]:
        """Hostnames refused as shortener destinations (self-link prevention)."""
        return (self.system_default_domain,)

    # CORS — public API routes allow all origins (no credentials).
    # Private routes (auth, oauth, dashboard) require explicit origin allowlist.
    cors_origins: list[str] = ["*"]  # deprecated — kept for backward compat
    cors_private_origins: list[str] = []

    # Request body size limit (bytes); 1 MB default
    max_content_length: int = 1_048_576

    # GeoIP database paths (configurable for self-hosters)
    geoip_country_db: str = "misc/GeoLite2-Country.mmdb"
    geoip_city_db: str = "misc/GeoLite2-City.mmdb"

    # GitHub repository (owner/repo) — used for star count + outbound links
    github_repo: str = "spoo-me/spoo"

    # Analytics & tracking (leave empty to disable)
    clarity_id: str = ""

    # External service URLs
    contact_webhook: str = ""
    url_report_webhook: str = ""
    hcaptcha_secret: str = ""
    hcaptcha_sitekey: str = ""

    # Service limits (overridable by self-hosters via env vars)
    max_active_api_keys: int = 20
    max_date_range_days: int = 90
    http_client_timeout: float = 5.0

    # Validator constraints (overridable by self-hosters via env vars)
    blocked_url_regex_timeout: float = 0.2
    max_emoji_alias_length: int = 15
    geo_rules_max_countries: int = 50
    url_password_min_length: int = 8
    account_password_min_length: int = 8
    account_password_max_length: int = 128

    # ── Field validators for safety-critical config ────────────────────

    @field_validator(
        "max_active_api_keys",
        "max_date_range_days",
        "max_emoji_alias_length",
        "geo_rules_max_countries",
    )
    @classmethod
    def _must_be_positive_int(cls, v: int, info) -> int:
        if v < 1:
            raise ValueError(f"{info.field_name} must be >= 1, got {v}")
        return v

    @field_validator("http_client_timeout", "blocked_url_regex_timeout")
    @classmethod
    def _must_be_positive_float(cls, v: float, info) -> float:
        if v <= 0:
            raise ValueError(f"{info.field_name} must be > 0, got {v}")
        return v

    @field_validator("url_password_min_length", "account_password_min_length")
    @classmethod
    def _password_min_length_sane(cls, v: int, info) -> int:
        if v < 1:
            raise ValueError(f"{info.field_name} must be >= 1, got {v}")
        return v

    @field_validator("account_password_max_length")
    @classmethod
    def _password_max_length_sane(cls, v: int) -> int:
        if v < 1:
            raise ValueError(f"account_password_max_length must be >= 1, got {v}")
        return v

    # Sub-configs (composed via model_validator below)
    db: DatabaseSettings | None = None
    redis: RedisSettings | None = None
    jwt: JWTSettings | None = None
    oauth: OAuthProviderSettings | None = None
    email: EmailSettings | None = None
    logging: LoggingSettings | None = None
    sentry: SentrySettings | None = None
    custom_domains: CustomDomainSettings | None = None
    click_events: ClickEventsSettings | None = None
    edge_cache: EdgeCacheSettings | None = None

    @model_validator(mode="after")
    def _populate_sub_configs_and_secret(self) -> AppSettings:
        # Cross-field validation
        if self.account_password_max_length < self.account_password_min_length:
            raise ValueError(
                f"account_password_max_length ({self.account_password_max_length}) "
                f"must be >= account_password_min_length ({self.account_password_min_length})"
            )

        # Accept FLASK_SECRET_KEY as a fallback for backward compatibility
        if not self.secret_key and self.flask_secret_key:
            self.secret_key = self.flask_secret_key

        # Populate sub-configs from the same env/dotenv source
        if self.db is None:
            self.db = DatabaseSettings()
        if self.redis is None:
            self.redis = RedisSettings()
        if self.jwt is None:
            self.jwt = JWTSettings()
        if self.oauth is None:
            self.oauth = OAuthProviderSettings()
        if self.email is None:
            self.email = EmailSettings()
        if self.logging is None:
            self.logging = LoggingSettings()
        if self.sentry is None:
            self.sentry = SentrySettings()
        if self.custom_domains is None:
            self.custom_domains = CustomDomainSettings()
        if self.click_events is None:
            self.click_events = ClickEventsSettings()
        if self.edge_cache is None:
            self.edge_cache = EdgeCacheSettings()

        return self

    @property
    def is_production(self) -> bool:
        return self.env == "production"
