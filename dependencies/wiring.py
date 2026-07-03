"""
Service and repository wiring — the composition root.

Called once during app startup to build all repositories, infrastructure,
and services as singletons on ``app.state``.  This keeps the lifespan
function in app.py focused on infrastructure lifecycle (connect/disconnect)
while this module handles the object graph.
"""

from __future__ import annotations

from fastapi import FastAPI

from config import AppSettings
from infrastructure.cache.feature_flag_cache import FeatureFlagCache
from infrastructure.cache.url_cache import UrlCache
from infrastructure.captcha.hcaptcha import HCaptchaProvider
from infrastructure.cloudflare_client import CloudflareClient
from infrastructure.logging import get_logger
from infrastructure.webhook.discord import DiscordWebhookProvider
from repositories.api_key_repository import ApiKeyRepository
from repositories.app_grant_repository import AppGrantRepository
from repositories.blocked_domain_repository import BlockedDomainRepository
from repositories.blocked_url_repository import BlockedUrlRepository
from repositories.click_repository import ClickRepository
from repositories.custom_domain_repository import CustomDomainRepository
from repositories.feature_flag_repository import FeatureFlagRepository
from repositories.legacy.emoji_url_repository import EmojiUrlRepository
from repositories.legacy.legacy_url_repository import LegacyUrlRepository
from repositories.token_repository import TokenRepository
from repositories.url_repository import UrlRepository
from repositories.user_repository import UserRepository
from schemas.enums.domain_status import VerificationMethod
from services.api_key_service import ApiKeyService
from services.auth.credentials import CredentialService
from services.auth.device import DeviceAuthService
from services.auth.otp import OtpService
from services.auth.password import PasswordService
from services.auth.verification import EmailVerificationService
from services.cf_saas_backend import CfSaasBackend
from services.click import ClickService, LegacyClickHandler, V2ClickHandler
from services.click.sinks import InlineSink, RedisStreamSink
from services.contact_service import ContactService
from services.custom_domain_service import CustomDomainService
from services.export.formatters import default_formatters
from services.export.service import ExportService
from services.feature_flag_service import FeatureFlagService
from services.oauth_service import OAuthService
from services.profile_picture_service import ProfilePictureService
from services.stats_service import StatsService
from services.tenant_resolver import CachedMongoTenantResolver
from services.token_factory import TokenFactory
from services.url_service import UrlService

log = get_logger(__name__)


def build_click_service(
    click_repo: ClickRepository,
    url_repo: UrlRepository,
    legacy_repo: LegacyUrlRepository,
    emoji_repo: EmojiUrlRepository,
    geoip,
    url_cache: UrlCache,
) -> ClickService:
    """Compose the click pipeline (schema handler registry).

    Single source of truth for the schema→handler mapping, shared by the
    web app (inline sink) and the click worker (stats consumer) so both
    processes always run identical tracking logic.
    """
    return ClickService(
        {
            "v2": V2ClickHandler(click_repo, url_repo, geoip, url_cache),
            "v1": LegacyClickHandler(legacy_repo, emoji_repo, geoip),
        }
    )


def wire_services(app: FastAPI, settings: AppSettings, redis_client) -> None:
    """Build all repositories and services, store on ``app.state``.

    Called once from the lifespan after infrastructure (db, redis, geoip,
    http_client, email_provider) is ready on ``app.state``.
    """
    db = app.state.db
    http_client = app.state.http_client

    # ── Repositories ─────────────────────────────────────────────────────
    url_repo = UrlRepository(db["urlsV2"])
    legacy_repo = LegacyUrlRepository(db["urls"])
    emoji_repo = EmojiUrlRepository(db["emojis"])
    click_repo = ClickRepository(db["clicks"])
    user_repo = UserRepository(db["users"])
    token_repo = TokenRepository(db["verification-tokens"])
    api_key_repo = ApiKeyRepository(db["api-keys"])
    blocked_url_repo = BlockedUrlRepository(db["blocked-urls"])
    app_grant_repo = AppGrantRepository(db["app-grants"])
    feature_flag_repo = FeatureFlagRepository(db["feature_flags"])

    # ── Infrastructure ───────────────────────────────────────────────────
    url_cache = UrlCache(redis_client, ttl_seconds=settings.redis.redis_ttl_seconds)
    feature_flag_cache = FeatureFlagCache(
        redis_client,
        ttl_seconds=settings.redis.feature_flag_ttl_seconds,
        negative_ttl_seconds=settings.redis.feature_flag_negative_ttl_seconds,
    )
    captcha = HCaptchaProvider(settings.hcaptcha_secret, http_client)
    contact_webhook = DiscordWebhookProvider(settings.contact_webhook, http_client)
    report_webhook = DiscordWebhookProvider(settings.url_report_webhook, http_client)

    # ── Services ─────────────────────────────────────────────────────────
    app.state.url_service = UrlService(
        url_repo,
        legacy_repo,
        emoji_repo,
        blocked_url_repo,
        url_cache,
        settings.blocked_self_domains,
        system_default_domain=settings.system_default_domain,
        blocked_url_regex_timeout=settings.blocked_url_regex_timeout,
        max_emoji_alias_length=settings.max_emoji_alias_length,
    )
    app.state.stats_service = StatsService(
        click_repo,
        url_repo,
        max_date_range_days=settings.max_date_range_days,
    )
    app.state.export_service = ExportService(
        app.state.stats_service,
        default_formatters(),
    )
    app.state.api_key_service = ApiKeyService(
        api_key_repo,
        max_active_keys=settings.max_active_api_keys,
    )
    token_factory = TokenFactory(settings.jwt)
    otp_service = OtpService(token_repo)

    app.state.user_repo = user_repo
    app.state.token_factory = token_factory

    app.state.credential_service = CredentialService(
        user_repo,
        otp_service,
        app.state.email_provider,
        token_factory,
        account_password_min_length=settings.account_password_min_length,
        account_password_max_length=settings.account_password_max_length,
    )
    app.state.verification_service = EmailVerificationService(
        user_repo,
        otp_service,
        app.state.email_provider,
        token_factory,
    )
    app.state.password_service = PasswordService(
        user_repo,
        otp_service,
        app.state.email_provider,
        account_password_min_length=settings.account_password_min_length,
        account_password_max_length=settings.account_password_max_length,
    )
    app.state.device_auth_service = DeviceAuthService(
        user_repo,
        token_repo,
        token_factory,
        app_registry=getattr(app.state, "app_registry", None),
    )
    app.state.oauth_service = OAuthService(
        user_repo,
        token_factory,
        app.state.email_provider,
    )
    app.state.profile_picture_service = ProfilePictureService(user_repo)
    app.state.contact_service = ContactService(
        contact_webhook,
        report_webhook,
        captcha,
    )

    app.state.click_service = build_click_service(
        click_repo, url_repo, legacy_repo, emoji_repo, app.state.geoip, url_cache
    )

    # ── Click event sink ─────────────────────────────────────────────
    # inline (default): classic synchronous tracking, unchanged.
    # stream: XADD to the click stream; the click worker consumes it.
    # Misconfigured stream mode (missing/unreachable queue Redis) degrades
    # to inline with a startup warning — same graceful pattern as custom
    # domains and the optional cache Redis.
    inline_sink = InlineSink(app.state.click_service)
    ce_settings = settings.click_events
    queue_redis = getattr(app.state, "queue_redis", None)
    if ce_settings.sink == "stream" and queue_redis is not None:
        app.state.click_sink = RedisStreamSink(
            queue_redis,
            stream=ce_settings.stream,
            maxlen=ce_settings.maxlen,
            fallback=inline_sink,
        )
        log.info("click_sink_stream_enabled", stream=ce_settings.stream)
    else:
        if ce_settings.sink == "stream":
            log.warning(
                "click_events_stream_unconfigured",
                detail=(
                    "CLICK_EVENTS_SINK=stream but the queue Redis is missing "
                    "or unreachable — falling back to inline click tracking. "
                    "Set CLICK_EVENTS_QUEUE_REDIS_URI to a dedicated Redis."
                ),
            )
        app.state.click_sink = inline_sink

    app.state.app_grant_repo = app_grant_repo

    app.state.feature_flag_service = FeatureFlagService(
        feature_flag_repo, feature_flag_cache
    )

    # ── Custom-domains feature ───────────────────────────────────────
    # Wired unconditionally so the data plumbing is in place even when the
    # master flag is off. Mutations short-circuit inside the service via
    # ``settings.custom_domains.enabled``; the route layer further gates
    # per-user access via the FeatureFlagService.
    #
    # Backend: one CfSaasBackend instance fills all three protocol slots
    # (verifier, registrar, edge provisioner). If ``cf_zone_id`` is unset,
    # the service still constructs but its mutating paths no-op — operators
    # who haven't configured CF get a feature that registers as "off" via
    # ``custom_domains.enabled`` instead of crashing at boot.
    custom_domain_repo = CustomDomainRepository(db["custom_domains"])
    blocked_domain_repo = BlockedDomainRepository(db["blocked_domains"])
    cd_settings = settings.custom_domains

    # Surface the "enabled but unconfigured" misconfig in startup logs so
    # operators don't have to wait for a request-time 500 to find out.
    # We still boot — the feature just no-ops until creds land.
    if cd_settings.enabled and not (
        cd_settings.cf_zone_id and cd_settings.cf_api_token
    ):
        log.warning(
            "custom_domains_enabled_but_unconfigured",
            detail=(
                "custom_domains.enabled=True but cf_zone_id/cf_api_token "
                "unset — feature will fail at request time until configured."
            ),
        )

    # CloudflareClient takes Optional[str] and only raises
    # CloudflareNotConfiguredError on first request, never at construction —
    # so the operator-hasn't-set-CF-up case is fine to wire here.
    cf_client = CloudflareClient(
        http_client=http_client,
        api_token=cd_settings.cf_api_token,
        zone_id=cd_settings.cf_zone_id,
        max_retries=cd_settings.cf_api_max_retries,
        initial_backoff_seconds=cd_settings.cf_api_initial_backoff_seconds,
    )
    cf_backend = CfSaasBackend(
        cf_client=cf_client,
        custom_domain_repo=custom_domain_repo,
        cname_target=cd_settings.cf_cname_target,
        dcv_delegation_target=cd_settings.cf_dcv_delegation_target,
    )
    verifiers = {
        VerificationMethod.CF_DELEGATED_DCV: cf_backend,
        VerificationMethod.CF_HTTP_DCV: cf_backend,
    }
    edge_provisioner = cf_backend
    registrar = cf_backend

    # Build the resolver before the service so the service can take it as a dep
    tenant_resolver = CachedMongoTenantResolver(
        repo=custom_domain_repo,
        redis_client=redis_client,
        system_default_domain=settings.system_default_domain,
    )
    app.state.tenant_resolver = tenant_resolver
    app.state.custom_domain_service = CustomDomainService(
        repo=custom_domain_repo,
        verifiers=verifiers,
        edge_provisioner=edge_provisioner,
        registrar=registrar,
        settings=cd_settings,
        tenant_resolver=tenant_resolver,
        blocked_domain_repo=blocked_domain_repo,
        redis_client=redis_client,
        preflight_cname_target=cd_settings.cf_cname_target
        if cd_settings.cf_zone_id
        else None,
        url_service=app.state.url_service,
    )
