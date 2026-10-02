"""Standard uvicorn/Render entry point.

Exposes the FastAPI application built in ``app.main`` as ``app`` so any
host can start the server with ``uvicorn main:app`` from this directory.
"""

from app.main import app, create_app  # noqa: F401

__all__ = ["app", "create_app"]
