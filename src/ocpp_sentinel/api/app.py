# =============================================================================
# api/app.py — FastAPI Application Entry Point
# =============================================================================

from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse

from ocpp_sentinel import __version__, __description__
from ocpp_sentinel.api.routes import router

STATIC_DIR = Path(__file__).parent.parent / "static"

app = FastAPI(
    title="OCPP Sentinel API",
    description=__description__,
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static assets
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Include main API routes
app.include_router(router)


@app.get("/", include_in_schema=False)
async def root():
    """Serve the Demo Web UI at root."""
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return RedirectResponse(url="/docs")
