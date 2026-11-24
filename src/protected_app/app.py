"""
Local Vulnerable Test Application for WAF Verification.

SECURITY NOTICE:
This application is strictly for local WAF benchmark and verification testing.
It MUST bind only to 127.0.0.1 (localhost). Vulnerable behaviors (SQLi, XSS,
Path Traversal) are safely simulated without executing system commands or
modifying host filesystem state.
"""
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request, Form, Query, HTTPException, status
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel

app = FastAPI(
    title="Local Vulnerable WAF Test App",
    description="Simulated vulnerable application for local WAF integration tests only",
    version="1.0.0",
)


class LoginRequest(BaseModel):
    username: str
    password: str


class SubmitRequest(BaseModel):
    title: str
    content: str


@app.get("/", response_class=HTMLResponse)
async def index():
    """Homepage simulating a benign web application landing page."""
    return HTMLResponse(
        content="""<!DOCTYPE html>
<html>
<head><title>Local Protected App</title></head>
<body>
    <h1>Local Protected Application</h1>
    <p>Status: Online. Protected by Transformer-Based WAF.</p>
    <p>Notice: Local testing environment strictly bound to 127.0.0.1.</p>
</body>
</html>"""
    )


@app.get("/health")
async def health():
    """Standard healthcheck probe."""
    return {"status": "healthy", "service": "protected-test-app"}


@app.get("/search")
async def search(q: str = Query(default="", description="Search query string")):
    """
    Search endpoint vulnerable to simulated SQLi and XSS reflection.
    """
    # Simulate SQL query reflection safely
    simulated_results = []
    if "union" in q.lower() or "select" in q.lower():
        simulated_results = [
            {"id": 1, "record": f"Simulated SQLi match for query: {q}"},
            {"id": 2, "record": "Mock user: admin | hash: $2b$12$e8x..."},
        ]
    elif q:
        simulated_results = [
            {"id": 101, "title": f"Result matching '{q}'", "score": 0.95}
        ]

    return {
        "query": q,
        "count": len(simulated_results),
        "results": simulated_results,
    }


@app.post("/login")
async def login(request: Request):
    """
    Login endpoint receiving JSON or Form body.
    Target for POST body SQLi and sensitive credential redaction tests.
    """
    content_type = request.headers.get("content-type", "")
    username = ""
    password = ""

    if "application/json" in content_type:
        try:
            data = await request.json()
            username = str(data.get("username", ""))
            password = str(data.get("password", ""))
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
    else:
        form = await request.form()
        username = str(form.get("username", ""))
        password = str(form.get("password", ""))

    # Simulated authentication logic
    is_sqli = any(token in username.lower() or token in password.lower() for token in ("' or '", "1=1", "union select"))
    if is_sqli:
        return {
            "authenticated": True,
            "user": "admin",
            "role": "administrator",
            "notice": "Simulated authentication bypass via SQL injection pattern",
        }

    if username == "admin" and password == "password123":
        return {
            "authenticated": True,
            "user": "admin",
            "role": "administrator",
            "token": "simulated_jwt_token_abc123",
        }

    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"authenticated": False, "error": "Invalid username or password"},
    )


@app.post("/submit")
async def submit(request: Request):
    """
    Comment / submission endpoint vulnerable to simulated reflected XSS.
    """
    content_type = request.headers.get("content-type", "")
    title = ""
    content = ""

    if "application/json" in content_type:
        try:
            data = await request.json()
            title = str(data.get("title", ""))
            content = str(data.get("content", ""))
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
    else:
        form = await request.form()
        title = str(form.get("title", ""))
        content = str(form.get("content", ""))

    return {
        "status": "accepted",
        "title": title,
        "content_preview": content,
        "has_script_tag": "<script" in content.lower(),
    }


@app.get("/files")
async def get_files(name: str = Query(default="", description="Filename to retrieve")):
    """
    File retrieval endpoint simulating Path Traversal vulnerability.
    Safely mocks file contents without touching the host filesystem.
    """
    if not name:
        return {"error": "Missing 'name' query parameter"}

    # Simulate Path Traversal response safely
    if "etc/passwd" in name.lower() or "win.ini" in name.lower() or ".." in name:
        return {
            "requested_file": name,
            "status": "vulnerable_simulated_read",
            "simulated_content": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        }

    return {
        "requested_file": name,
        "status": "ok",
        "content": f"Contents of simulated benign document '{name}'",
    }


@app.get("/api/items/{item_id}")
async def get_item(item_id: int):
    """Normal benign REST API endpoint."""
    return {
        "item_id": item_id,
        "name": f"Product Item #{item_id}",
        "price": 29.99,
        "in_stock": True,
    }
