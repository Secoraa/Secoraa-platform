from fastapi import APIRouter
from fastapi.responses import RedirectResponse


def build_docs_router(docs_path: str) -> APIRouter:
    """
    Router that exposes convenient Swagger endpoints for testing.
    Redirects to the existing custom Swagger UI mounted at `docs_path`.
    """
    router = APIRouter(tags=["Docs"])

    @router.get("/docs", include_in_schema=False)
    async def docs_alias():
        return RedirectResponse(url=docs_path, status_code=307)

    @router.get("/swagger", include_in_schema=False)
    async def swagger_alias():
        return RedirectResponse(url=docs_path, status_code=307)

    return router

