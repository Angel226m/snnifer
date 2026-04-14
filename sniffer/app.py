#!/usr/bin/env python3
"""
Network Sniffer Pro - Monitor en tiempo real
Captura y analiza el tráfico HTTP entre frontend, backend y sniffer.
"""

from flask import Flask, render_template, request, jsonify, stream_with_context
from datetime import datetime
import json
import os
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
import time
import base64
import threading
import queue

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
DATABASE_URL = os.getenv(
    'SNIFFER_DB_URL',
    'postgresql://postgres:password@db:5432/learnwithgaray'
)
BACKEND_URL = os.getenv('BACKEND_URL', 'http://backend:8000')

# ============================================================
# Decoders avanzados (opcional)
# ============================================================
try:
    from decoders import AdvancedDecoder, PayloadDecryptor
    HAS_DECODERS = True
    logger.info("Advanced decoders loaded")
except ImportError:
    HAS_DECODERS = False

# ============================================================
# Packet sniffer en background (raw - best-effort)
# ============================================================
try:
    from packet_sniffer import start_packet_sniffer
    logger.info("Initializing raw packet sniffer...")
except ImportError as e:
    start_packet_sniffer = None
    logger.warning("Packet sniffer unavailable: %s", e)

# ============================================================
# Security Analyzer
# ============================================================
class SecurityAnalyzer:
    @staticmethod
    def analyze_payload(req_body, resp_body, headers):
        vulnerabilities = []
        encryption_type = "HTTP_BACKEND"

        headers = headers or {}
        auth = headers.get('Authorization', headers.get('authorization', ''))

        # DEBIL: Bearer token - solo Base64
        if auth.startswith('Bearer '):
            token = auth[7:]
            if SecurityAnalyzer._is_base64(token):
                vulnerabilities.append({
                    'type': 'WEAK_ENCODING',
                    'severity': 'HIGH',
                    'name': 'Base64 Token (NOT Encrypted)',
                    'description': 'Token en Base64 sin encriptacion real. Decode: echo "TOKEN" | base64 -d',
                    'tool': 'CyberChef | base64 -d | Wireshark'
                })
                encryption_type = "BASE64_ONLY"

            # JWT con RS256 (FUERTE)
            if token.count('.') == 2:
                try:
                    parts = token.split('.')
                    pad = lambda s: s + '=' * (4 - len(s) % 4)
                    hdr = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
                    if hdr.get('alg') == 'RS256':
                        vulnerabilities.append({
                            'type': 'JWT_RS256',
                            'severity': 'SECURE',
                            'name': 'JWT RS256 (RSA Asymmetric)',
                            'description': 'Firmado con Private Key. No se puede falsificar. Verifica en jwt.io',
                            'tool': 'jwt.io'
                        })
                        encryption_type = "JWT_RS256"
                    else:
                        encryption_type = "JWT_" + hdr.get('alg', 'UNKNOWN')
                except Exception:
                    pass

        # DEBIL: password en plaintext
        payload_str = ""
        if req_body:
            payload_str += json.dumps(req_body) if isinstance(req_body, dict) else str(req_body)
        if resp_body:
            payload_str += json.dumps(resp_body) if isinstance(resp_body, dict) else str(resp_body)

        if 'password' in payload_str.lower() and not any(c in payload_str for c in ['$2b', '$2a', '$argon']):
            vulnerabilities.append({
                'type': 'PLAINTEXT_PASSWORD',
                'severity': 'CRITICAL',
                'name': 'Plaintext Password (HTTP)',
                'description': 'CRITICO: password sin hashear en texto plano. Capturable con tcpdump.',
                'tool': 'tcpdump -i any -A "tcp port 8000" | grep password'
            })
            encryption_type = "PLAINTEXT"

        # URL-encoded sensitive
        if 'email' in payload_str and '%' in payload_str:
            vulnerabilities.append({
                'type': 'URL_ENCODED_SENSITIVE',
                'severity': 'MEDIUM',
                'name': 'URL-Encoded Sensitive Data',
                'description': 'Datos sensibles en query string: visible en logs y Wireshark.',
                'tool': 'urldecoder.org | python urllib.parse.unquote()'
            })

        return {
            'vulnerabilities': vulnerabilities,
            'encryption_type': encryption_type,
            'risk_level': (
                'CRITICAL' if any(v['severity'] in ('CRITICAL', 'HIGH') for v in vulnerabilities)
                else 'MEDIUM' if vulnerabilities else 'LOW'
            )
        }

    @staticmethod
    def _is_base64(s: str) -> bool:
        try:
            return isinstance(s, str) and base64.b64encode(base64.b64decode(s)).decode() == s
        except Exception:
            return False


# ============================================================
# Database helpers
# ============================================================
def get_db():
    try:
        return psycopg2.connect(DATABASE_URL, connect_timeout=5)
    except Exception as e:
        logger.error("DB connection error: %s", e)
        return None


def ensure_traffic_table():
    conn = get_db()
    if not conn:
        return False
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                method VARCHAR(10),
                endpoint VARCHAR(500),
                status_code INTEGER,
                request_body JSONB,
                response_body JSONB,
                request_headers JSONB,
                response_headers JSONB,
                execution_time_ms FLOAT,
                is_encrypted BOOLEAN DEFAULT FALSE,
                encryption_type VARCHAR(50),
                vulnerabilities JSONB DEFAULT '[]',
                user_agent VARCHAR(500),
                client_ip VARCHAR(45)
            );
            CREATE INDEX IF NOT EXISTS idx_tl_ts  ON traffic_logs(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_tl_ep  ON traffic_logs(endpoint);
        """)
        conn.commit()
        cur.close()
        conn.close()
        logger.info("traffic_logs table ready")
        return True
    except Exception as e:
        logger.error("ensure_table error: %s", e)
        return False


# ============================================================
# SSE broadcast system
# ============================================================
_sse_clients: list = []
_sse_lock = threading.Lock()


def _broadcast(data: str):
    """Push JSON string to all connected SSE clients."""
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(data)
            except Exception:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)


def _db_poll_thread():
    """Background thread: poll traffic_logs for new rows every 2 s and broadcast them."""
    last_id = 0
    # Warm up: get current max id so we don't replay old data
    conn = get_db()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT COALESCE(MAX(id), 0) FROM traffic_logs")
                last_id = cur.fetchone()[0]
        except Exception:
            pass
        conn.close()

    while True:
        time.sleep(2)
        try:
            conn = get_db()
            if not conn:
                continue
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute(
                "SELECT * FROM traffic_logs WHERE id > %s ORDER BY id ASC LIMIT 20",
                (last_id,)
            )
            rows = cur.fetchall()
            cur.close()
            conn.close()

            for row in rows:
                item = dict(row)
                last_id = max(last_id, item['id'])
                # Convert datetime to string for JSON serialisation
                if item.get('timestamp') and hasattr(item['timestamp'], 'isoformat'):
                    item['timestamp'] = item['timestamp'].isoformat()
                # Parse JSON fields stored as strings
                for field in ('request_body', 'response_body', 'request_headers',
                              'response_headers', 'vulnerabilities'):
                    if field in item and isinstance(item[field], str):
                        try:
                            item[field] = json.loads(item[field])
                        except Exception:
                            pass
                payload = json.dumps({'type': 'new_packet', 'packet': item}, default=str)
                _broadcast(payload)
        except Exception as e:
            logger.debug("poll_thread error: %s", e)


# ============================================================
# Flask Routes
# ============================================================

@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/api/traffic', methods=['GET', 'DELETE'])
def traffic():
    if request.method == 'DELETE':
        conn = get_db()
        if not conn:
            return jsonify({'error': 'DB unavailable'}), 500
        try:
            cur = conn.cursor()
            cur.execute("TRUNCATE TABLE traffic_logs RESTART IDENTITY")
            conn.commit()
            cur.close()
            conn.close()
            return jsonify({'status': 'cleared'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    conn = get_db()
    if not conn:
        return jsonify({'error': 'DB unavailable'}), 500

    try:
        limit  = min(int(request.args.get('limit', 200)), 500)
        since  = request.args.get('since')    # optional: only rows with id > since
        method = request.args.get('method')
        status = request.args.get('status')

        cur = conn.cursor(cursor_factory=RealDictCursor)

        where_clauses = []
        params = []
        if since:
            where_clauses.append("id > %s")
            params.append(int(since))
        if method:
            where_clauses.append("method = %s")
            params.append(method.upper())
        if status:
            where_clauses.append("status_code::text LIKE %s")
            params.append(status + '%')

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        cur.execute(f"""
            SELECT * FROM traffic_logs
            {where_sql}
            ORDER BY timestamp DESC
            LIMIT %s
        """, params + [limit])

        traffic_list = []
        for row in cur.fetchall():
            item = dict(row)
            if item.get('timestamp') and hasattr(item['timestamp'], 'isoformat'):
                item['timestamp'] = item['timestamp'].isoformat()
            for field in ('request_body', 'response_body', 'request_headers',
                          'response_headers', 'vulnerabilities'):
                if field in item and isinstance(item[field], str):
                    try:
                        item[field] = json.loads(item[field])
                    except Exception:
                        pass
            traffic_list.append(item)

        # Aggregate stats
        cur.execute("""
            SELECT
                COUNT(*)                                          AS total,
                COUNT(DISTINCT endpoint)                         AS unique_endpoints,
                AVG(execution_time_ms)                           AS avg_ms,
                SUM(CASE WHEN is_encrypted      THEN 1 ELSE 0 END) AS encrypted,
                SUM(CASE WHEN NOT is_encrypted  THEN 1 ELSE 0 END) AS plaintext,
                SUM(CASE WHEN status_code BETWEEN 200 AND 299 THEN 1 ELSE 0 END) AS ok_count,
                SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS err_count
            FROM traffic_logs
        """)
        stats = dict(cur.fetchone())
        stats = {k: (float(v) if isinstance(v, float) else int(v) if v is not None else 0)
                 for k, v in stats.items()}
        stats['avg_ms'] = round(stats.get('avg_ms', 0), 1)

        cur.close()
        conn.close()

        return jsonify({
            'total':   stats.get('total', 0),
            'stats':   stats,
            'traffic': traffic_list,
        })

    except Exception as e:
        logger.error("traffic() error: %s", e)
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats')
def api_stats():
    conn = get_db()
    if not conn:
        return jsonify({'error': 'DB unavailable'}), 500
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT
                COUNT(*)                     AS total,
                COUNT(DISTINCT endpoint)     AS endpoints,
                AVG(execution_time_ms)       AS avg_ms,
                MAX(execution_time_ms)       AS max_ms,
                MIN(timestamp)               AS first_seen,
                MAX(timestamp)               AS last_seen
            FROM traffic_logs
        """)
        stats = dict(cur.fetchone())
        cur.execute("SELECT method, COUNT(*) cnt FROM traffic_logs GROUP BY method ORDER BY cnt DESC")
        by_method = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT status_code, COUNT(*) cnt FROM traffic_logs GROUP BY status_code ORDER BY cnt DESC LIMIT 15")
        by_status = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT endpoint, COUNT(*) cnt FROM traffic_logs GROUP BY endpoint ORDER BY cnt DESC LIMIT 10")
        top_ep = [dict(r) for r in cur.fetchall()]
        cur.close()
        conn.close()
        for k, v in list(stats.items()):
            if hasattr(v, 'isoformat'):
                stats[k] = v.isoformat()
            elif isinstance(v, float):
                stats[k] = round(v, 2)
        return jsonify({'stats': stats, 'by_method': by_method, 'by_status': by_status, 'top_endpoints': top_ep})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================
# Intercept / MITM proxy system
# ============================================================
_intercept_mode: bool = False
_icept_queue: dict = {}   # str(id) -> entry dict
_icept_lock = threading.Lock()
_icept_seq = 0


def _icept_next_id() -> str:
    global _icept_seq
    _icept_seq += 1
    return str(_icept_seq)


@app.route('/api/intercept/toggle', methods=['POST'])
def intercept_toggle():
    global _intercept_mode
    _intercept_mode = not _intercept_mode
    logger.info("Intercept mode: %s", _intercept_mode)
    _broadcast(json.dumps({'type': 'intercept_mode', 'enabled': _intercept_mode}))
    return jsonify({'intercept_mode': _intercept_mode})


@app.route('/api/intercept/queue')
def intercept_queue():
    with _icept_lock:
        items = [
            {k: v for k, v in entry.items() if k != 'event'}
            for entry in _icept_queue.values()
        ]
    return jsonify({'intercept_mode': _intercept_mode, 'queue': items})


@app.route('/api/intercept/forward', methods=['POST'])
def intercept_forward():
    data = request.get_json() or {}
    req_id = data.get('id')
    with _icept_lock:
        entry = _icept_queue.get(req_id)
    if not entry:
        return jsonify({'error': 'Not found'}), 404
    entry['action'] = 'forward'
    entry['modified_body'] = data.get('body', entry.get('body'))
    entry['modified_headers'] = data.get('headers', {})
    entry['event'].set()
    return jsonify({'status': 'forwarded'})


@app.route('/api/intercept/drop', methods=['POST'])
def intercept_drop():
    data = request.get_json() or {}
    req_id = data.get('id')
    with _icept_lock:
        entry = _icept_queue.get(req_id)
    if not entry:
        return jsonify({'error': 'Not found'}), 404
    entry['action'] = 'drop'
    entry['event'].set()
    return jsonify({'status': 'dropped'})


@app.route('/proxy/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/proxy/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy_forward(path):
    """Intercepting reverse proxy.
    Frontend → sniffer:5000/proxy/<path> → backend:8000/<path>
    Set VITE_API_URL=http://localhost:5000/proxy to enable MITM.
    """
    import requests as _req
    method = request.method
    endpoint = '/' + path
    qs = request.query_string.decode()
    full_endpoint = endpoint + ('?' + qs if qs else '')

    fwd_headers = {k: v for k, v in request.headers
                   if k.lower() not in ('host', 'content-length', 'transfer-encoding')}
    req_body = request.get_json(force=True, silent=True)
    raw_data = None
    if req_body is None and request.content_length:
        raw_data = request.get_data()

    # --- Intercept hold ---
    if _intercept_mode and method not in ('OPTIONS',):
        req_id = _icept_next_id()
        evt = threading.Event()
        entry = {
            'id': req_id,
            'method': method,
            'endpoint': full_endpoint,
            'headers': dict(fwd_headers),
            'body': req_body,
            'event': evt,
            'action': None,
            'modified_body': req_body,
            'modified_headers': {},
            'timestamp': datetime.utcnow().isoformat(),
        }
        with _icept_lock:
            _icept_queue[req_id] = entry
        _broadcast(json.dumps({'type': 'intercepted', 'id': req_id,
                                'method': method, 'endpoint': full_endpoint,
                                'body': req_body, 'headers': dict(fwd_headers)}))
        evt.wait(timeout=60)
        with _icept_lock:
            action = entry.get('action') or 'timeout'
            req_body = entry.get('modified_body', req_body)
            fwd_headers.update(entry.get('modified_headers', {}))
            _icept_queue.pop(req_id, None)
        if action == 'drop':
            return jsonify({'error': 'Request dropped by interceptor'}), 403

    # --- Forward to backend ---
    url = BACKEND_URL + full_endpoint
    t0 = time.time()
    try:
        resp = _req.request(
            method=method, url=url,
            json=req_body if isinstance(req_body, (dict, list)) else None,
            data=raw_data if req_body is None else None,
            headers=fwd_headers, timeout=30, allow_redirects=False
        )
        elapsed = round((time.time() - t0) * 1000, 1)
        try:
            resp_body = resp.json()
        except Exception:
            resp_body = resp.text[:4000]

        # Log to traffic_logs
        try:
            analysis = SecurityAnalyzer.analyze_payload(req_body, resp_body, fwd_headers)
            conn = get_db()
            if conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO traffic_logs
                    (method, endpoint, status_code, request_body, response_body,
                     request_headers, response_headers, execution_time_ms,
                     is_encrypted, encryption_type, vulnerabilities, client_ip, user_agent)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    method, endpoint, resp.status_code,
                    json.dumps(req_body) if req_body is not None else None,
                    json.dumps(resp_body) if resp_body is not None else None,
                    json.dumps(dict(fwd_headers)), json.dumps(dict(resp.headers)),
                    elapsed, False, 'HTTP_PROXY',
                    json.dumps(analysis['vulnerabilities']),
                    request.remote_addr, fwd_headers.get('User-Agent', '')
                ))
                conn.commit(); cur.close(); conn.close()
        except Exception as ex:
            logger.debug("proxy log err: %s", ex)

        return jsonify(resp_body), resp.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 502


# ============================================================
# Packet injection / replay
# ============================================================
@app.route('/api/inject', methods=['POST'])
def api_inject():
    import requests as _req
    try:
        data     = request.get_json(force=True) or {}
        method   = data.get('method', 'GET').upper()
        endpoint = data.get('endpoint', '/')
        payload  = data.get('payload')
        extra_h  = data.get('headers', {})

        if not endpoint.startswith('/'):
            endpoint = '/' + endpoint

        url = BACKEND_URL + endpoint
        headers = {'Content-Type': 'application/json', 'X-Sniffed-Replay': 'true'}
        headers.update(extra_h)

        resp = _req.request(method=method, url=url,
                            json=payload or None, headers=headers,
                            timeout=10, allow_redirects=True)
        try:
            resp_body = resp.json()
        except Exception:
            resp_body = resp.text[:4000]

        return jsonify({
            'status':           resp.status_code,
            'url':              url,
            'method':           method,
            'response':         resp_body,
            'response_headers': dict(resp.headers),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================
# Advanced decoder endpoints
# ============================================================
@app.route('/api/decode', methods=['POST'])
def api_decode():
    if not HAS_DECODERS:
        return jsonify({'error': 'Decoders not available'}), 503
    try:
        data    = request.get_json() or {}
        payload = data.get('payload', '')
        result  = AdvancedDecoder.auto_decode(payload)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/decode/base64', methods=['POST'])
def api_decode_b64():
    if not HAS_DECODERS:
        return jsonify({'error': 'Decoders not available'}), 503
    try:
        data = request.get_json() or {}
        ok, result = AdvancedDecoder.decode_base64(data.get('payload', ''))
        return jsonify({'success': ok, 'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/decode/url', methods=['POST'])
def api_decode_url():
    if not HAS_DECODERS:
        return jsonify({'error': 'Decoders not available'}), 503
    try:
        data = request.get_json() or {}
        ok, result = AdvancedDecoder.decode_url(data.get('payload', ''))
        return jsonify({'success': ok, 'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/decode/hex', methods=['POST'])
def api_decode_hex():
    if not HAS_DECODERS:
        return jsonify({'error': 'Decoders not available'}), 503
    try:
        data = request.get_json() or {}
        ok, result = AdvancedDecoder.decode_hex(data.get('payload', ''))
        return jsonify({'success': ok, 'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/decode/analyze', methods=['POST'])
def api_decode_analyze():
    if not HAS_DECODERS:
        return jsonify({'error': 'Decoders not available'}), 503
    try:
        data = request.get_json() or {}
        return jsonify(AdvancedDecoder.analyze_payload_advanced(data.get('payload', '')))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/decode/extract-tokens', methods=['POST'])
def api_extract_tokens():
    if not HAS_DECODERS:
        return jsonify({'error': 'Decoders not available'}), 503
    try:
        data    = request.get_json() or {}
        payload = data.get('payload', '')
        tokens  = AdvancedDecoder.extract_base64_tokens(payload)
        decoded = {}
        for tok in tokens[:10]:
            ok, res = AdvancedDecoder.decode_base64(tok)
            if ok:
                decoded[tok[:30] + '...'] = res[:100]
        return jsonify({'found_tokens': len(tokens), 'tokens': tokens[:10], 'decoded': decoded})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/decode/extract-sensitive', methods=['POST'])
def api_extract_sensitive():
    if not HAS_DECODERS:
        return jsonify({'error': 'Decoders not available'}), 503
    try:
        data    = request.get_json() or {}
        payload = data.get('payload', '')
        return jsonify({
            'emails':   AdvancedDecoder.extract_emails(payload),
            'urls':     AdvancedDecoder.extract_urls(payload),
            'api_keys': AdvancedDecoder.extract_api_keys(payload),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/decode/try-all', methods=['POST'])
def api_try_all_decodings():
    if not HAS_DECODERS:
        return jsonify({'error': 'Decoders not available'}), 503
    try:
        data    = request.get_json() or {}
        payload = data.get('payload', '')
        results = PayloadDecryptor.try_all_decodings(payload)
        return jsonify({'original': payload[:200], 'decodings': results, 'total_layers': len(results)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/security-report')
def security_report():
    conn = get_db()
    if not conn:
        return jsonify({'error': 'DB unavailable'}), 500
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT timestamp, method, endpoint, encryption_type, vulnerabilities, status_code
            FROM traffic_logs
            WHERE vulnerabilities IS NOT NULL AND vulnerabilities::text != '[]'
            ORDER BY timestamp DESC LIMIT 50
        """)
        vulns = []
        for row in cur.fetchall():
            r = dict(row)
            if hasattr(r.get('timestamp'), 'isoformat'):
                r['timestamp'] = r['timestamp'].isoformat()
            if isinstance(r.get('vulnerabilities'), str):
                try:
                    r['vulnerabilities'] = json.loads(r['vulnerabilities'])
                except Exception:
                    pass
            vulns.append(r)

        cur.execute("""
            SELECT encryption_type, COUNT(*) cnt
            FROM traffic_logs GROUP BY encryption_type ORDER BY cnt DESC
        """)
        types = [dict(r) for r in cur.fetchall()]
        cur.close()
        conn.close()

        return jsonify({
            'encryption_types': types,
            'vulnerabilities':  vulns,
            'recommendations': {
                'weak_encoding': 'Use JWT RS256 or TLS 1.3 AEAD',
                'plaintext_password': 'CRITICAL: Implement bcrypt + HTTPS + TLS 1.3',
                'url_encoded_sensitive': 'Never send sensitive data in URL. Use POST + TLS 1.3'
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================
# SSE endpoint
# ============================================================
@app.route('/api/stream')
def sse_stream():
    def generate():
        q: queue.Queue = queue.Queue(maxsize=100)
        with _sse_lock:
            _sse_clients.append(q)
        try:
            yield 'data: {"ping":true}\n\n'
            while True:
                try:
                    msg = q.get(timeout=25)
                    yield 'data: ' + msg + '\n\n'
                except queue.Empty:
                    yield ': keep-alive\n\n'
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                if q in _sse_clients:
                    _sse_clients.remove(q)

    return app.response_class(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


# ============================================================
# Health check
# ============================================================
@app.route('/health')
def health():
    try:
        conn = get_db()
        if conn:
            conn.close()
            return jsonify({'status': 'ok', 'db': 'connected'})
    except Exception:
        pass
    return jsonify({'status': 'error', 'db': 'disconnected'}), 500


# ============================================================
# App startup
# ============================================================
def startup():
    ensure_traffic_table()

    # Start raw packet sniffer background thread
    if start_packet_sniffer:
        try:
            start_packet_sniffer()
            logger.info("Raw packet sniffer started")
        except Exception as e:
            logger.warning("Could not start raw packet sniffer: %s", e)

    # Start DB polling thread for SSE
    t = threading.Thread(target=_db_poll_thread, daemon=True, name="db-poll")
    t.start()
    logger.info("DB poll thread started - SSE live updates active")


startup()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False, threaded=True)
