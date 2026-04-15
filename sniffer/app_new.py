#!/usr/bin/env python3
"""
Network Sniffer Pro v2 - MITM Real
Captura, desencripta y modifica tráfico HTTP entre frontend-backend en tiempo real
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
import requests
import re
import urllib.parse

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

DATABASE_URL = os.getenv(
    'SNIFFER_DB_URL',
    'postgresql://postgres:password@db:5432/learnwithgaray'
)
BACKEND_URL = os.getenv('BACKEND_URL', 'http://backend:8000')

# ============================================================
# PayloadDecoder - Desencriptación y Análisis
# ============================================================
class PayloadDecoder:
    """Decodifica múltiples formatos de payloads"""
    
    @staticmethod
    def try_all_decodings(data: str, depth=0, max_depth=5) -> list:
        """Intenta todos los decodings posibles recursivamente"""
        if depth >= max_depth or not isinstance(data, str) or len(data) == 0:
            return []
        
        results = []
        
        # Base64
        try:
            decoded = base64.b64decode(data, validate=True).decode('utf-8', errors='ignore')
            if decoded and decoded != data and len(decoded) > 3:
                results.append({
                    'type': 'base64',
                    'depth': depth,
                    'result': decoded[:1000],
                    'full': decoded
                })
                results.extend(PayloadDecoder.try_all_decodings(decoded, depth+1, max_depth))
        except: pass
        
        # URL encoding
        try:
            decoded = urllib.parse.unquote(data)
            if decoded != data and decoded.strip():
                results.append({
                    'type': 'url_encoded',
                    'depth': depth,
                    'result': decoded[:1000],
                    'full': decoded
                })
                results.extend(PayloadDecoder.try_all_decodings(decoded, depth+1, max_depth))
        except: pass
        
        # Hex
        try:
            if all(c in '0123456789abcdefABCDEF ' for c in data) and len(data) > 10:
                decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
                if decoded and decoded != data:
                    results.append({
                        'type': 'hex',
                        'depth': depth,
                        'result': decoded[:1000],
                        'full': decoded
                    })
                    results.extend(PayloadDecoder.try_all_decodings(decoded, depth+1, max_depth))
        except: pass
        
        return results
    
    @staticmethod
    def extract_sensitive_patterns(data: str) -> dict:
        """Extrae patrones sensibles del payload"""
        text = str(data)
        findings = {}
        
        # Emails
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
        if emails:
            findings['emails'] = list(set(emails))[:10]
        
        # JWT tokens
        jwts = re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', text)
        if jwts:
            findings['jwt_tokens'] = list(set(jwts))[:5]
        
        # API keys pattern
        api_keys = re.findall(r'(?:api[_-]?key|secret|token|password|key)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', text, re.IGNORECASE)
        if api_keys:
            findings['secrets'] = list(set(api_keys[:5]))
        
        # Bearer tokens
        bearer = re.findall(r'Bearer\s+([A-Za-z0-9_\-\.]+)', text)
        if bearer:
            findings['bearer_tokens'] = list(set(bearer[:5]))
        
        # URLs
        urls = re.findall(r'https?://[^\s"\'<>]+', text)
        if urls:
            findings['urls'] = list(set(urls[:10]))
        
        # IP addresses
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        if ips:
            findings['ips'] = list(set(ips[:10]))
        
        # Hashes
        hashes_found = {}
        md5s = re.findall(r'\b[a-fA-F0-9]{32}\b', text)
        if md5s:
            hashes_found['md5'] = list(set(md5s[:5]))
        sha1s = re.findall(r'\b[a-fA-F0-9]{40}\b', text)
        if sha1s:
            hashes_found['sha1'] = list(set(sha1s[:5]))
        sha256s = re.findall(r'\b[a-fA-F0-9]{64}\b', text)
        if sha256s:
            hashes_found['sha256'] = list(set(sha256s[:5]))
        
        if hashes_found:
            findings['hashes'] = hashes_found
        
        return findings

class PayloadModifier:
    """Modifica payloads en tránsito para MITM real"""
    
    @staticmethod
    def modify_json(data, rules: dict):
        """Modifica un JSON según reglas"""
        if not isinstance(data, dict):
            return data
        
        def set_nested(obj, path, value):
            keys = path.split('.')
            for key in keys[:-1]:
                if key not in obj:
                    obj[key] = {}
                obj = obj[key]
            obj[keys[-1]] = value
        
        result = json.loads(json.dumps(data))
        for path, value in rules.items():
            try:
                set_nested(result, path, value)
            except:
                pass
        
        return result
    
    @staticmethod
    def inject_into_json(data, injections: dict):
        """Inyecta nuevos campos en JSON"""
        if not isinstance(data, dict):
            return data
        
        result = json.loads(json.dumps(data))
        result.update(injections)
        return result

class SecurityAnalyzer:
    """Análisis avanzado de seguridad"""
    
    @staticmethod
    def analyze_payload(req_body, resp_body, headers):
        vulns = []
        enc_type = "HTTP"
        
        headers = headers or {}
        auth = headers.get('Authorization', headers.get('authorization', ''))
        
        # Bearer token
        if auth.startswith('Bearer '):
            token = auth[7:]
            
            # JWT analysis
            if token.count('.') == 2:
                try:
                    parts = token.split('.')
                    pad = lambda s: s + '=' * (4 - len(s) % 4)
                    hdr = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
                    
                    alg = hdr.get('alg', '')
                    if alg == 'RS256':
                        enc_type = "JWT_RS256"
                        vulns.append({'type': 'JWT_RS256', 'severity': 'SECURE', 'name': 'JWT RS256'})
                    elif alg == 'HS256':
                        enc_type = "JWT_HS256"
                        vulns.append({'type': 'JWT_HS256', 'severity': 'MEDIUM', 'name': 'JWT HS256'})
                    else:
                        enc_type = f"JWT_{alg}"
                except:
                    pass
        
        # Plaintext password check
        payload_str = str(req_body) + str(resp_body)
        if 'password' in payload_str.lower():
            if not any(c in payload_str for c in ['$2b', '$2a', '$argon']):
                vulns.append({
                    'type': 'PLAINTEXT_PASSWORD',
                    'severity': 'CRITICAL',
                    'name': 'Password en plaintext'
                })
                enc_type = "PLAINTEXT"
        
        return {
            'vulnerabilities': vulns,
            'encryption_type': enc_type,
            'risk_level': (
                'CRITICAL' if any(v['severity'] == 'CRITICAL' for v in vulns)
                else 'MEDIUM' if vulns else 'LOW'
            )
        }

# ============================================================
# Database helpers
# ============================================================
def get_db():
    try:
        return psycopg2.connect(DATABASE_URL, connect_timeout=5)
    except Exception as e:
        logger.error("✗ DB connection error: %s", e)
        return None

def ensure_traffic_table():
    """Crear tablas para captura de tráfico MITM"""
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
                response_body TEXT,
                request_headers JSONB,
                response_headers JSONB,
                execution_time_ms FLOAT,
                encryption_type VARCHAR(50),
                vulnerabilities JSONB DEFAULT '[]',
                sensitive_data JSONB DEFAULT '{}',
                client_ip VARCHAR(45),
                user_agent VARCHAR(500),
                mitm_intercepted BOOLEAN DEFAULT TRUE,
                mitm_modified BOOLEAN DEFAULT FALSE
            );
            CREATE INDEX IF NOT EXISTS idx_tl_ts ON traffic_logs(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_tl_ep ON traffic_logs(endpoint);
        """)
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS traffic_modifications (
                id SERIAL PRIMARY KEY,
                traffic_id INTEGER REFERENCES traffic_logs(id) ON DELETE CASCADE,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                modification_type VARCHAR(50),
                original_value JSONB,
                modified_value JSONB
            );
            CREATE INDEX IF NOT EXISTS idx_mod_traf ON traffic_modifications(traffic_id);
        """)
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS decryption_log (
                id SERIAL PRIMARY KEY,
                traffic_id INTEGER REFERENCES traffic_logs(id) ON DELETE CASCADE,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                decoded_type VARCHAR(50),
                depth INTEGER,
                decoded_value TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_dec_traf ON decryption_log(traffic_id);
        """)
        
        conn.commit()
        cur.close()
        conn.close()
        logger.info("✓ Traffic tables ready")
        return True
    except Exception as e:
        logger.error("✗ Table creation error: %s", e)
        return False

# ============================================================
# SSE broadcast system
# ============================================================
_sse_clients: list = []
_sse_lock = threading.Lock()

def _broadcast(data: str):
    """Broadcast a todos los clientes SSE"""
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(data)
            except:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)

def _db_poll_thread():
    """Thread: poll DB y broadcast de nuevos packets"""
    last_id = 0
    conn = get_db()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("SELECT COALESCE(MAX(id), 0) FROM traffic_logs")
            last_id = cur.fetchone()[0]
            cur.close()
        except:
            pass
        conn.close()

    while True:
        time.sleep(2)
        try:
            conn = get_db()
            if not conn:
                continue
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT * FROM traffic_logs WHERE id > %s ORDER BY id ASC LIMIT 20", (last_id,))
            rows = cur.fetchall()
            cur.close()
            conn.close()

            for row in rows:
                item = dict(row)
                last_id = max(last_id, item['id'])
                if item.get('timestamp'):
                    item['timestamp'] = item['timestamp'].isoformat()
                _broadcast(json.dumps({'type': 'new_packet', 'packet': item}, default=str))
        except Exception as e:
            logger.debug("Poll thread error: %s", e)

# ============================================================
# Flask Routes
# ============================================================

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/proxy/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/proxy/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy_forward(path):
    """MITM Proxy - Captura total, desencripta y modifica"""
    method = request.method
    endpoint = '/' + path
    qs = request.query_string.decode()
    full_endpoint = endpoint + ('?' + qs if qs else '')
    
    # Headers
    fwd_headers = {k: v for k, v in request.headers
                   if k.lower() not in ('host', 'content-length', 'transfer-encoding')}
    
    # Body
    req_body = None
    raw_data = None
    try:
        req_body = request.get_json(force=True, silent=True)
    except:
        pass
    
    if req_body is None and request.content_length:
        raw_data = request.get_data()
    
    modifications = []
    
    # ─ FORWARD ─
    url = BACKEND_URL + full_endpoint
    t0 = time.time()
    
    try:
        resp = requests.request(
            method=method, url=url,
            json=req_body if isinstance(req_body, (dict, list)) else None,
            data=raw_data if req_body is None else None,
            headers=fwd_headers, timeout=30, allow_redirects=False, verify=False
        )
        
        elapsed = round((time.time() - t0) * 1000, 1)
        
        try:
            resp_body = resp.json()
        except:
            resp_body = resp.text[:5000] if resp.text else None
        
        # ─ ANALYSIS ─
        analysis = SecurityAnalyzer.analyze_payload(req_body, resp_body, fwd_headers)
        sensitive = PayloadDecoder.extract_sensitive_patterns(str(req_body) + str(resp_body))
        decodings = PayloadDecoder.try_all_decodings(str(req_body))[:2]
        
        # ─ SAVE ─
        try:
            conn = get_db()
            if conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO traffic_logs
                    (method, endpoint, status_code, request_body, response_body,
                     request_headers, response_headers, execution_time_ms,
                     encryption_type, vulnerabilities, sensitive_data,
                     client_ip, user_agent, mitm_intercepted, mitm_modified)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING id
                """, (
                    method, endpoint, resp.status_code,
                    json.dumps(req_body) if req_body else None,
                    json.dumps(resp_body) if isinstance(resp_body, dict) else str(resp_body),
                    json.dumps(dict(fwd_headers)), json.dumps(dict(resp.headers)),
                    elapsed, analysis['encryption_type'],
                    json.dumps(analysis['vulnerabilities']),
                    json.dumps(sensitive), request.remote_addr,
                    fwd_headers.get('User-Agent', ''), True, False
                ))
                traf_id = cur.fetchone()[0]
                
                # Save decodings
                for dec in decodings:
                    cur.execute("""
                        INSERT INTO decryption_log
                        (traffic_id, decoded_type, depth, decoded_value)
                        VALUES (%s, %s, %s, %s)
                    """, (traf_id, dec['type'], dec['depth'], dec['full'][:1000]))
                
                conn.commit()
                cur.close()
                conn.close()
        except Exception as ex:
            logger.error("DB save error: %s", ex)
        
        # ─ BROADCAST ─
        _broadcast(json.dumps({
            'type': 'captured',
            'method': method,
            'endpoint': endpoint,
            'status': resp.status_code,
            'vulns': analysis['vulnerabilities'],
            'sensitive': sensitive,
            'encryption': analysis['encryption_type']
        }, default=str))
        
        return jsonify(resp_body), resp.status_code
        
    except Exception as e:
        logger.error("Proxy error: %s", e)
        return jsonify({'error': str(e)}), 502

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
        limit = min(int(request.args.get('limit', 200)), 500)
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM traffic_logs ORDER BY timestamp DESC LIMIT %s", (limit,))
        
        traffic_list = []
        for row in cur.fetchall():
            item = dict(row)
            if item.get('timestamp'):
                item['timestamp'] = item['timestamp'].isoformat()
            traffic_list.append(item)
        
        cur.execute("""
            SELECT COUNT(*) total,
                   COUNT(DISTINCT endpoint) endpoints,
                   AVG(execution_time_ms) avg_ms
            FROM traffic_logs
        """)
        stats = dict(cur.fetchone())
        
        cur.close()
        conn.close()
        
        return jsonify({'traffic': traffic_list, 'stats': stats})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decode/auto', methods=['POST'])
def api_decode():
    try:
        data = request.get_json() or {}
        payload = data.get('payload', '')
        decodings = PayloadDecoder.try_all_decodings(payload)
        sensitive = PayloadDecoder.extract_sensitive_patterns(payload)
        return jsonify({'decodings': decodings, 'sensitive': sensitive, 'layers': len(decodings)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/sensitive-data')
def api_sensitive():
    try:
        limit = min(int(request.args.get('limit', 100)), 500)
        conn = get_db()
        if not conn:
            return jsonify({'error': 'DB unavailable'}), 500
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT id, timestamp, method, endpoint, sensitive_data, encryption_type
            FROM traffic_logs
            WHERE sensitive_data::text != '{}'
            ORDER BY timestamp DESC LIMIT %s
        """, (limit,))
        
        findings = []
        for row in cur.fetchall():
            r = dict(row)
            if r.get('timestamp'):
                r['timestamp'] = r['timestamp'].isoformat()
            findings.append(r)
        
        cur.close()
        conn.close()
        
        return jsonify({'findings': findings, 'total': len(findings)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/mitm-stats')
def api_stats():
    try:
        conn = get_db()
        if not conn:
            return jsonify({'error': 'DB unavailable'}), 500
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("""
            SELECT
                COUNT(*) total,
                COUNT(DISTINCT endpoint) endpoints,
                COUNT(DISTINCT client_ip) clients,
                SUM(CASE WHEN status_code >= 200 AND status_code <= 299 THEN 1 ELSE 0 END) success,
                SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) errors
            FROM traffic_logs
        """)
        
        stats = dict(cur.fetchone())
        
        cur.execute("SELECT encryption_type, COUNT(*) cnt FROM traffic_logs GROUP BY encryption_type ORDER BY cnt DESC")
        by_enc = [dict(r) for r in cur.fetchall()]
        
        cur.close()
        conn.close()
        
        return jsonify({'stats': stats, 'by_encryption': by_enc})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stream')
def sse_stream():
    def generate():
        q = queue.Queue(maxsize=100)
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

@app.route('/health')
def health():
    try:
        conn = get_db()
        if conn:
            conn.close()
            return jsonify({'status': 'ok', 'db': 'connected'})
    except:
        pass
    return jsonify({'status': 'error', 'db': 'disconnected'}), 500

# ============================================================
# App startup
# ============================================================
if __name__ == '__main__':
    ensure_traffic_table()
    t = threading.Thread(target=_db_poll_thread, daemon=True)
    t.start()
    logger.info("✓ Sniffer MITM Pro iniciado - http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False, threaded=True)
