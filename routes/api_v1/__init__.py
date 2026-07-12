"""API v1 routes package."""

from fastapi import APIRouter

from routes.api_v1 import (
    custom_domains,
    exports,
    keys,
    management,
    me,
    metadata,
    shorten,
    stats,
    urls,
)

router = APIRouter(prefix="/api/v1")
router.include_router(shorten.router)
router.include_router(urls.router)
router.include_router(management.router)
router.include_router(stats.router)
router.include_router(exports.router)
router.include_router(keys.router)
router.include_router(custom_domains.router)
router.include_router(metadata.router)
router.include_router(me.router)
