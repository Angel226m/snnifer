from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
import asyncio
import os
import time
import json
import logging
import psycopg2
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

from app.database import Base, engine
from app.routes import auth, clients
from app.seed import seed

load_dotenv()
logger = logging.getLogger("traffic_logger")

# Thread pool for non-blocking DB writes (2 threads are enough)
_db_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="traffic_log")

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


# Initialize FastAPI app
app = FastAPI(
    title="Login & Client Management API",
    description="API with bcrypt password hashing and client management",
    version="1.0.0"
)

# NOTE: middleware is added in LIFO order for BaseHTTPMiddleware,
# so add CORS first (outermost), then TrafficLogger.
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(TrafficLoggerMiddleware)

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
