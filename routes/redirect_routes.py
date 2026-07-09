"""
Redirect routes — the hot path.

GET  /<short_code>          → resolve + redirect (rate-limit exempt)
POST /<short_code>/password → password form submission
"""

from __future__ import annotations

import time
from urllib.parse import unquote

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, Response

from dependencies import ClickSink, UrlSvc
from errors import (
    BlockedUrlError,
    ForbiddenError,
    GoneError,
    NotFoundError,
    ValidationError,
)
from infrastructure.logging import get_logger, should_sample
from infrastructure.templates import templates
from middleware.rate_limiter import Limits, limiter
from schemas.enums.domain_status import DomainStatus
from schemas.models.url import SchemaVersion
from services.click.bot_detection import should_block_bot, wants_preview
from services.click.events import ClickEvent
from services.meta_preview import build_preview_context
from shared.ip_utils import get_client_ip
from shared.url_utils import extract_hostname

log = get_logger(__name__)

router = APIRouter()

# Status-specific copy for the tenant fallback page. Maps the same status
# codes _error_page already emits today; keys must stay in sync.
_TENANT_ERROR_COPY = {
    "404": ("Not found", "This URL doesn't exist on {fqdn}."),
    "410": ("Expired", "This URL has expired and no longer redirects."),
    "451": ("Blocked", "This URL has been blocked for abuse."),
    "403": ("Access denied", "You don't have permission to view this URL."),
}
_NOINDEX_HEADER = "noindex, nofollow, noarchive"


def _error_page(request: Request, code: str, message: str, status: int) -> Response:
    """Render the error page for a resolve/redirect failure.

    Custom-tenant requests get a self-contained minimal page (no external
    asset references — `spoo.ink/static/...` would 404 on a custom domain,
    leaving the marketing template unstyled). System-default requests keep
    the original branded ``error.html``.

    On 404, an ACTIVE tenant's ``not_found_redirect`` overrides the page
    entirely so owners control the UX for unknown paths consistently with
    the middleware-level disallowed-path branch.
    """
    tenant = getattr(request.state, "tenant", None)
    is_custom = tenant is not None and not tenant.is_system_default

    if is_custom and status == 404:
        active = tenant.status == DomainStatus.ACTIVE
        if active and tenant.not_found_redirect and request.method in {"GET", "HEAD"}:
            return RedirectResponse(
                tenant.not_found_redirect,
                status_code=302,
                headers={"X-Robots-Tag": _NOINDEX_HEADER},
            )

    if is_custom:
        title, body_tpl = _TENANT_ERROR_COPY.get(
            code, ("Error", "Something went wrong.")
        )
        return templates.TemplateResponse(
            request,
            "tenant_error.html",
            {
                "error_code": code,
                "error_title": title,
                "error_message": body_tpl.format(fqdn=tenant.fqdn),
            },
            status_code=status,
            headers={"X-Robots-Tag": _NOINDEX_HEADER},
        )

    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "error_code": code,
            "error_message": message,
            "host_url": str(request.base_url),
        },
        status_code=status,
    )


@router.api_route("/{short_code}", methods=["GET", "HEAD"], include_in_schema=False)
@limiter.exempt
async def redirect_url(
    short_code: str,
    request: Request,
    url_service: UrlSvc,
    click_sink: ClickSink,
) -> Response:
    """Resolve a short code and redirect to the destination URL.

    Rate-limit exempt — this is the hot path (~400k requests/day).
    """
    short_code = unquote(short_code)
    user_ip = get_client_ip(request)
    start_time = time.perf_counter()
    host_url = str(request.base_url)

    # 1. Resolve URL (cache-first)
    resolve_start = time.perf_counter()
    tenant = getattr(request.state, "tenant", None)
    domain = tenant.fqdn if tenant else None
    try:
        url_data, schema = await url_service.resolve(short_code, domain=domain)
    except NotFoundError:
        log.info("url_not_found", short_code=short_code)
        return _error_page(request, "404", "URL NOT FOUND", 404)
    except BlockedUrlError:
        log.info("url_blocked", short_code=short_code)
        return _error_page(request, "451", "THIS URL HAS BEEN BLOCKED", 451)
    except GoneError:
        log.info("url_gone", short_code=short_code)
        return _error_page(request, "410", "SHORT URL EXPIRED", 410)
    resolve_ms = int((time.perf_counter() - resolve_start) * 1000)

    # Custom meta-tags: preview crawlers get the owner's OG card instead of
    # the redirect; everyone else falls through to the 302. This runs before
    # the password gate (bots get the card, not the 401 page — it reveals
    # only owner-written text) and returns before the click emit — a preview
    # serve is never a click.
    user_agent = request.headers.get("User-Agent", "")
    if url_data.meta_title is not None and schema == SchemaVersion.V2:
        bot_param = "bot" in request.query_params
        if wants_preview(request.method, user_agent, bot_param=bot_param):
            log.info(
                "meta_preview_served",
                short_code=short_code,
                bot_param=bot_param,
            )
            resp = templates.TemplateResponse(
                request,
                "meta_preview.html",
                build_preview_context(url_data, auto_redirect=not bot_param),
                status_code=200,
            )
            resp.headers["X-Robots-Tag"] = _NOINDEX_HEADER
            return resp

    # 2. Password check
    if url_data.password_hash:
        password = request.query_params.get("password")
        if not url_data.verify_password(password):
            log.debug("url_password_required", short_code=short_code, schema=schema)
            return templates.TemplateResponse(
                request,
                "password.html",
                {"short_code": short_code, "host_url": host_url},
                status_code=401,
            )

    # 3. Pre-emit bot block — the DECISION must run before the redirect is
    #    served (click processing may happen out-of-band); bot metadata
    #    RECORDING stays in the click pipeline.
    if should_block_bot(request.method, user_agent, url_data, schema):
        log.info("click_tracking_bot_blocked", short_code=short_code, schema=schema)
        return _error_page(request, "403", "ACCESS DENIED", 403)

    # 4. Emit click event — skip for HEAD / OPTIONS
    tracking_ms = 0
    if request.method not in ("HEAD", "OPTIONS"):
        referrer = request.headers.get("Referer")
        cf_city = request.headers.get("CF-IPCity")
        is_emoji = schema == SchemaVersion.EMOJI
        tracking_start = time.perf_counter()
        event = ClickEvent(
            short_code=short_code,
            schema_key=schema,
            is_emoji=is_emoji,
            # ClickEvent strips url.password_hash on construction (v1 hashes
            # are plaintext) — no producer-side sanitization needed.
            url=url_data,
            client_ip=user_ip,
            user_agent=user_agent,
            referrer=referrer,
            cf_city=cf_city,
            redirect_ms=int((time.perf_counter() - start_time) * 1000),
        )
        try:
            await click_sink.emit(event)
        except ValidationError:
            # Bad / missing User-Agent — skip analytics, still redirect
            log.info(
                "click_tracking_validation_error", short_code=short_code, schema=schema
            )
        except ForbiddenError as exc:
            # Inline sink, defense in depth: the legacy handler blocked a
            # bot the pre-emit check missed — block the redirect as before
            log.info(
                "click_tracking_bot_blocked", short_code=short_code, reason=str(exc)
            )
            return _error_page(request, "403", "ACCESS DENIED", 403)
        except Exception:
            log.exception("click_tracking_failed", short_code=short_code, schema=schema)
        tracking_ms = int((time.perf_counter() - tracking_start) * 1000)

    # 5. Redirect
    total_ms = int((time.perf_counter() - start_time) * 1000)
    if should_sample("url_redirect"):
        log.info(
            "url_redirect",
            short_code=short_code,
            schema=schema,
            resolve_ms=resolve_ms,
            tracking_ms=tracking_ms,
            total_ms=total_ms,
            long_url_domain=extract_hostname(url_data.long_url),
            password_protected=bool(getattr(url_data, "password_hash", None)),
            had_max_clicks=bool(getattr(url_data, "max_clicks", None)),
            max_clicks=getattr(url_data, "max_clicks", None),
            owner_id=str(getattr(url_data, "owner_id", "")) or None,
            slow=total_ms > 100,
        )
    resp = RedirectResponse(url_data.long_url, status_code=302)
    resp.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    return resp


@router.post("/{short_code}/password", include_in_schema=False)
@limiter.limit(Limits.PASSWORD_CHECK)
async def check_password(
    short_code: str,
    request: Request,
    url_service: UrlSvc,
) -> Response:
    """Verify a password for a password-protected URL.

    On success: redirect to /<short_code>?password=<password>.
    On failure: re-render password.html with error message.
    """
    short_code = unquote(short_code)
    form_data = await request.form()
    password = form_data.get("password")
    host_url = str(request.base_url)

    tenant = getattr(request.state, "tenant", None)
    domain = tenant.fqdn if tenant else None
    try:
        url_data, _schema = await url_service.resolve(short_code, domain=domain)
    except (NotFoundError, BlockedUrlError, ForbiddenError, GoneError):
        return _error_page(
            request, "400", "Invalid short code or URL not password-protected", 400
        )

    if not url_data.password_hash:
        return _error_page(
            request, "400", "Invalid short code or URL not password-protected", 400
        )

    if url_data.verify_password(password):
        log.info("url_password_verified", short_code=short_code)
        return RedirectResponse(f"/{short_code}?password={password}", status_code=302)

    # Wrong password — re-render password form with error
    log.info("url_password_incorrect", short_code=short_code)
    return templates.TemplateResponse(
        request,
        "password.html",
        {"short_code": short_code, "error": "Incorrect password", "host_url": host_url},
    )
