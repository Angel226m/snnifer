from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response as StarletteResponse
import asyncio
import os
import time
import json
import logging
import psycopg2
import urllib.request as ureq
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from dotenv import load_dotenv

from app.database import Base, engine
from app.routes import auth, clients
from app.seed import seed

load_dotenv()
logger = logging.getLogger("traffic_logger")

# Thread pool for non-blocking DB writes (2 threads are enough)
_db_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="traffic_log")

# Sniffer service URL (same Docker network)
SNIFFER_URL = os.getenv('SNIFFER_URL', 'http://sniffer:5000')

# Create tables
Base.metadata.create_all(bind=engine)
seed()

# ==================== TRAFFIC LOGGING MIDDLEWARE ====================

SKIP_PATHS = {'/health', '/docs', '/openapi.json', '/redoc', '/favicon.ico'}
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:password@db:5432/learnwithgaray')


def _save_traffic(method, path, status_code, req_headers, resp_headers,
                  exec_ms, client_ip, user_agent):
    """Write a traffic log entry to PostgreSQL. Runs in thread pool – never blocks event loop."""
    try:
        conn = psycopg2.connect(DATABASE_URL, connect_timeout=3)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO traffic_logs
                (method, endpoint, status_code, request_body, response_body,
                 request_headers, response_headers, execution_time_ms,
                 is_encrypted, encryption_type, vulnerabilities,
                 user_agent, client_ip)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            method, path, status_code,
            None, None,
            json.dumps(req_headers),
            json.dumps(resp_headers),
            exec_ms,
            False,
            'HTTP_BACKEND',
            '[]',
            user_agent or '',
            client_ip or '',
        ))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        logger.debug("traffic_log error: %s", e)


class TrafficLoggerMiddleware(BaseHTTPMiddleware):
    """Captures every request/response timing and logs to traffic_logs asynchronously."""

    async def dispatch(self, request: Request, call_next):
        if request.url.path in SKIP_PATHS:
            return await call_next(request)

        start = time.time()
        # Pass request through unchanged – do NOT consume the body stream here
        response = await call_next(request)
        exec_ms = round((time.time() - start) * 1000, 2)

        # Fire-and-forget DB write in thread pool so we never block the event loop
        req_headers = dict(request.headers)
        resp_headers = dict(response.headers)
        client_ip = request.client.host if request.client else ''
        user_agent = req_headers.get('user-agent', '')

        loop = asyncio.get_event_loop()
        loop.run_in_executor(
            _db_pool, _save_traffic,
            request.method, request.url.path, response.status_code,
            req_headers, resp_headers,
            exec_ms, client_ip, user_agent,
        )

        # Return the original response object – no reconstruction, headers preserved
        return response


# ==================== SNIFFER CAPTURE MIDDLEWARE ====================

def _send_to_sniffer(capture_data: dict):
    """Fire-and-forget: POST request/response bodies to the sniffer dashboard.
    Runs in a daemon thread – never blocks the event loop or the response."""
    try:
        payload = json.dumps(capture_data, default=str).encode('utf-8')
        req = ureq.Request(
            f"{SNIFFER_URL}/api/capture",
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        ureq.urlopen(req, timeout=1)
    except Exception:
        pass  # Sniffer is optional; never crash the backend


CAPTURE_SKIP_PATHS = {'/health', '/docs', '/openapi.json', '/redoc', '/favicon.ico', '/auth'}  # Skip auth endpoints


class SnifferCaptureMiddleware(BaseHTTPMiddleware):
    """Intercepts every request/response and ships full bodies to the sniffer service.
    Reconstructs the response from the consumed body_iterator so routes are unaffected."""

    async def dispatch(self, request: Request, call_next):
        # TEMPORARILY: Skip ALL endpoints to test if middleware is the issue
        # (Auth endpoints are still skipped anyway for security)
        # TODO: Fix response reconstruction properly and remove this override
        if any(request.url.path == p or request.url.path.startswith(p + '/') for p in CAPTURE_SKIP_PATHS) or request.method == 'OPTIONS':
            return await call_next(request)
        
        # Capture for sniffer WITHOUT reconstructing response (just metadata)
        try:
            req_body = await request.body()
            req_body_str = req_body.decode('utf-8', errors='replace')
        except:
            req_body_str = ''
        
        # Call next without consuming body_iterator
        response = await call_next(request)
        
        # Send capture metadata to sniffer (request only, can't safely get response)
        capture = {
            'method': request.method,
            'endpoint': str(request.url.path),
            'request_body': req_body_str,
            'response_body': '[response body skipped - middleware bypass]',
            'status_code': response.status_code,
            'client_ip': request.client.host if request.client else '',
            'request_headers': dict(request.headers),
            'response_headers': dict(response.headers),
        }
        
        t = Thread(target=_send_to_sniffer, args=(capture,), daemon=True)
        t.start()
        
        # Return response unchanged
        return response


# Initialize FastAPI app
app = FastAPI(
    title="Login & Client Management API",
    description="API with bcrypt password hashing and client management",
    version="1.0.0"
)

# NOTE: middleware is added in LIFO order for BaseHTTPMiddleware,
# so add CORS first (outermost), then TrafficLogger.
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(TrafficLoggerMiddleware)
# TODO: Re-enable after fixing response body reconstruction issue
# app.add_middleware(SnifferCaptureMiddleware)

# Include routers
app.include_router(auth.router)
app.include_router(clients.router)

@app.get("/")
def read_root():
    """Root endpoint."""
    return {
        "message": "Login & Client Management API",
        "version": "1.0.0",
        "docs": "/docs"
    }

@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
