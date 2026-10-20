from fastapi import FastAPI, Request

from app.auth import router as auth_router
from app.engagements import router as engagements_router

app = FastAPI(title="ScopeGuard", docs_url="/docs")
app.include_router(auth_router)
app.include_router(engagements_router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
def health():
    return {"status": "ok"}
