from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from playwright.sync_api import sync_playwright

app = FastAPI(title="TazoSploit DOM Renderer", version="1.0")

DEFAULT_TIMEOUT_MS = int(os.getenv("DOM_RENDER_TIMEOUT_MS", "15000"))
MAX_HTML_CHARS = int(os.getenv("DOM_RENDER_MAX_CHARS", "200000"))


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/render")
def render(url: str = Query(..., min_length=5)):
    if not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(status_code=400, detail="url must be http(s)")

    html: Optional[str] = None
    error: Optional[str] = None
    status_code: Optional[int] = None

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
            page = browser.new_page()
            resp = page.goto(url, wait_until="networkidle", timeout=DEFAULT_TIMEOUT_MS)
            if resp is not None:
                status_code = resp.status
            # Give client-side JS a brief chance to render.
            page.wait_for_timeout(1000)
            html = page.content()
            browser.close()
    except Exception as exc:
        error = str(exc)

    if html is None and error:
        return JSONResponse(status_code=502, content={"error": error, "status": status_code})

    html = html or ""
    if len(html) > MAX_HTML_CHARS:
        html = html[:MAX_HTML_CHARS]
    return {"html": html, "status": status_code}
