"""API v1 routes package."""

from fastapi import APIRouter

from routes.api_v1 import (
    apps,
    custom_domains,
    exports,
    keys,
    management,
    me,
    metadata,
    public_preview,
    public_stats,
    reports,
    shorten,
    stats,
    urls,
)

router = APIRouter(prefix="/api/v1")
router.include_router(shorten.router)
router.include_router(urls.router)
router.include_router(management.router)
router.include_router(stats.router)
router.include_router(public_stats.router)
router.include_router(exports.router)
router.include_router(keys.router)
router.include_router(apps.router)
router.include_router(custom_domains.router)
router.include_router(metadata.router)
router.include_router(me.router)
router.include_router(public_preview.router)
router.include_router(reports.router)
