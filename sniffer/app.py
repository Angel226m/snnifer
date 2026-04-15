#!/usr/bin/env python3
"""
Network Sniffer Pro v2 - MITM Real
Captura, desencripta y modifica tráfico HTTP entre frontend-backend en tiempo real
"""

from flask import Flask, render_template, request, jsonify, stream_with_context, Response
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
import hashlib
import hmac
import re
import urllib.parse
from functools import wraps
import ssl
import socket

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
# Advanced Decoders & Payload Analysis
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
            if decoded and decoded != data:
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
        
        # JSON pretty print
        try:
            if isinstance(data, str):
                parsed = json.loads(data)
                pretty = json.dumps(parsed, indent=2)
                if pretty != data:
                    results.append({
                        'type': 'json_formatted',
                        'depth': depth,
                        'result': pretty[:1000],
                        'full': pretty
                    })
        except: pass
        
        return results
    
    @staticmethod
    def extract_sensitive_patterns(data: str) -> dict:
        """Extrae patrones sensibles"""
        text = str(data)
        findings = {}
        
        # Emails
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
        if emails:
            findings['emails'] = list(set(emails))
        
        # JWT tokens
        jwts = re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', text)
        if jwts:
            findings['jwt_tokens'] = list(set(jwts))
        
        # API keys
        api_keys = re.findall(r'(?:api[_-]?key|auth[_-]?token|secret|password)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', text, re.IGNORECASE)
        if api_keys:
            findings['api_keys'] = list(set(api_keys[:5]))
        
        # Bearer tokens
        bearer = re.findall(r'Bearer\s+([A-Za-z0-9_\-\.]+)', text)
        if bearer:
            findings['bearer_tokens'] = list(set(bearer))
        
        # URLs
        urls = re.findall(r'https?://[^\s"\'<>]+', text)
        if urls:
            findings['urls'] = list(set(urls[:10]))
        
        # IP addresses
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        if ips:
            findings['ips'] = list(set(ips))
        
        # Hashes (MD5, SHA1, SHA256)
        hashes = {
            'md5': re.findall(r'\b[a-fA-F0-9]{32}\b', text),
            'sha1': re.findall(r'\b[a-fA-F0-9]{40}\b', text),
            'sha256': re.findall(r'\b[a-fA-F0-9]{64}\b', text),
        }
        for hash_type, found in hashes.items():
            if found:
                findings[f'{hash_type}_hashes'] = list(set(found[:5]))
        
        return findings

class PayloadModifier:
    """Modifica payloads en tránsito"""
    
    @staticmethod
    def modify_json(data, rules: dict):
        """Modifica un JSON según reglas
        rules = {'path.to.field': 'new_value', ...}
        """
        if not isinstance(data, dict):
            return data
        
        def set_nested(obj, path, value):
            keys = path.split('.')
            for key in keys[:-1]:
                if key not in obj:
                    obj[key] = {}
                obj = obj[key]
            obj[keys[-1]] = value
        
        result = json.loads(json.dumps(data))  # Deep copy
        for path, value in rules.items():
            set_nested(result, path, value)
        
        return result
    
    @staticmethod
    def inject_into_json(data, injections: dict):
        """Inyecta nuevos campos en JSON"""
        if not isinstance(data, dict):
            return data
        
        result = json.loads(json.dumps(data))
        result.update(injections)
        return result
    
    @staticmethod
    def remove_from_json(data, keys: list):
        """Elimina campos de JSON"""
        if not isinstance(data, dict):
            return data
        
        result = json.loads(json.dumps(data))
        for key in keys:
            result.pop(key, None)
        return result

class SecurityAnalyzer:
    """Análisis avanzado de seguridad"""
    
    @staticmethod
    def analyze_payload(req_body, resp_body, headers):
        vulnerabilities = []
        encryption_type = "HTTP_BACKEND"
        
        headers = headers or {}
        auth = headers.get('Authorization', headers.get('authorization', ''))
        
        # Bearer token analysis
        if auth.startswith('Bearer '):
            token = auth[7:]
            
            # JWT RS256
            if token.count('.') == 2:
                try:
                    parts = token.split('.')
                    pad = lambda s: s + '=' * (4 - len(s) % 4)
                    hdr = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
                    payload_part = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
                    
                    if hdr.get('alg') == 'RS256':
                        encryption_type = "JWT_RS256"
                        vulnerabilities.append({
                            'type': 'JWT_RS256',
                            'severity': 'SECURE',
                            'name': 'JWT RS256 (RSA)',
                            'description': 'Firmado con clave privada - Seguro'
                        })
                    elif hdr.get('alg') == 'HS256':
                        encryption_type = "JWT_HS256"
                        vulnerabilities.append({
                            'type': 'JWT_HS256',
                            'severity': 'MEDIUM',
                            'name': 'JWT HS256 (HMAC)',
                            'description': 'HMAC simétrico - verificar secret strength'
                        })
                    else:
                        encryption_type = f"JWT_{hdr.get('alg', 'UNKNOWN')}"
                except Exception:
                    pass
            elif SecurityAnalyzer._is_base64(token):
                encryption_type = "BASE64_ONLY"
                vulnerabilities.append({
                    'type': 'WEAK_ENCODING',
                    'severity': 'HIGH',
                    'name': 'Base64 Token SIN Encriptación',
                    'description': 'Token solo codificado en Base64 - Fácil de decodificar'
                })
        
        # Password plaintext
        payload_str = str(req_body) + str(resp_body)
        if 'password' in payload_str.lower() and not any(c in payload_str for c in ['$2b', '$2a', '$argon']):
            vulnerabilities.append({
                'type': 'PLAINTEXT_PASSWORD',
                'severity': 'CRITICAL',
                'name': 'Contraseña en Plaintext',
                'description': 'CRÍTICO: Contraseña sin hashear en texto plano'
            })
            encryption_type = "PLAINTEXT"
        
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
    """Crear tablas para captura y modificación de tráfico"""
    conn = get_db()
    if not conn:
        return False
    try:
        cur = conn.cursor()
        
        # Tabla principal de tráfico
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
                encryption_type VARCHAR(50),
                vulnerabilities JSONB DEFAULT '[]',
                sensitive_data JSONB DEFAULT '{}',
                client_ip VARCHAR(45),
                user_agent VARCHAR(500),
                mitm_intercepted BOOLEAN DEFAULT FALSE,
                mitm_modified BOOLEAN DEFAULT FALSE
            );
            CREATE INDEX IF NOT EXISTS idx_tl_ts ON traffic_logs(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_tl_ep ON traffic_logs(endpoint);
            CREATE INDEX IF NOT EXISTS idx_tl_mitm ON traffic_logs(mitm_intercepted);
        """)
        
        # Tabla de modificaciones en tránsito
        cur.execute("""
            CREATE TABLE IF NOT EXISTS traffic_modifications (
                id SERIAL PRIMARY KEY,
                traffic_id INTEGER REFERENCES traffic_logs(id) ON DELETE CASCADE,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                modification_type VARCHAR(50),
                original_value JSONB,
                modified_value JSONB,
                rule_applied VARCHAR(500),
                success BOOLEAN DEFAULT TRUE
            );
            CREATE INDEX IF NOT EXISTS idx_mod_traffic ON traffic_modifications(traffic_id);
        """)
        
        # Tabla de intentos de desencriptación
        cur.execute("""
            CREATE TABLE IF NOT EXISTS decryption_attempts (
                id SERIAL PRIMARY KEY,
                traffic_id INTEGER REFERENCES traffic_logs(id) ON DELETE CASCADE,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                decoded_type VARCHAR(50),
                depth INTEGER,
                original_value TEXT,
                decoded_value TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_dec_traffic ON decryption_attempts(traffic_id);
        """)
        
        conn.commit()
        cur.close()
        conn.close()
        logger.info("✓ Traffic tables ready")
        return True
    except Exception as e:
        logger.error("✗ ensure_table error: %s", e)
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
    """MITM Proxy real - Intercepta, desencripta y modifica tráfico en vivo"""
    method = request.method
    endpoint = '/' + path
    qs = request.query_string.decode()
    full_endpoint = endpoint + ('?' + qs if qs else '')
    
    # Headers filtrados
    fwd_headers = {k: v for k, v in request.headers
                   if k.lower() not in ('host', 'content-length', 'transfer-encoding')}
    
    # Parse request body
    req_body = None
    raw_data = None
    try:
        req_body = request.get_json(force=True, silent=True)
    except:
        pass
    
    if req_body is None and request.content_length:
        raw_data = request.get_data()
    
    # ─────────────────────────────────────────
    # INTERCEPCIÓN REAL EN TRÁNSITO
    # ─────────────────────────────────────────
    modifications = []
    
    # Aplicar modificaciones si existen reglas
    if req_body and isinstance(req_body, dict):
        # Ejemplo: cambiar password en /login
        if endpoint == '/login' and 'password' in req_body:
            # Desencriptado para análisis
            pass
        
        # Modificaciones basadas en reglas de intercepción
        modification_rules = request.headers.get('X-Sniff-Modify', '')
        if modification_rules:
            try:
                rules = json.loads(urllib.parse.unquote(modification_rules))
                req_body = PayloadModifier.modify_json(req_body, rules)
                modifications.append({
                    'type': 'json_modification',
                    'rules': rules,
                    'modified': True
                })
            except Exception as e:
                logger.warning("Modification parse error: %s", e)
    
    # Forward to backend
    url = BACKEND_URL + full_endpoint
    t0 = time.time()
    
    try:
        resp = requests.request(
            method=method,
            url=url,
            json=req_body if isinstance(req_body, (dict, list)) else None,
            data=raw_data if req_body is None else None,
            headers=fwd_headers,
            timeout=30,
            allow_redirects=False,
            verify=False
        )
        
        elapsed = round((time.time() - t0) * 1000, 1)
        
        # Parse response
        try:
            resp_body = resp.json()
        except:
            resp_body = resp.text[:5000]
        
        # ─────────────────────────────────────────
        # ANÁLISIS DE SEGURIDAD
        # ─────────────────────────────────────────
        analysis = SecurityAnalyzer.analyze_payload(req_body, resp_body, fwd_headers)
        sensitive_patterns = PayloadDecoder.extract_sensitive_patterns(
            str(req_body) + str(resp_body) + str(fwd_headers)
        )
        
        # ─────────────────────────────────────────
        # GUARDAR EN DATABASE
        # ─────────────────────────────────────────
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
                    json.dumps(req_body) if req_body is not None else None,
                    json.dumps(resp_body) if isinstance(resp_body, dict) else str(resp_body),
                    json.dumps(dict(fwd_headers)),
                    json.dumps(dict(resp.headers)),
                    elapsed,
                    analysis['encryption_type'],
                    json.dumps(analysis['vulnerabilities']),
                    json.dumps(sensitive_patterns),
                    request.remote_addr,
                    fwd_headers.get('User-Agent', ''),
                    True,  # MITM intercepted
                    len(modifications) > 0
                ))
                
                traffic_id = cur.fetchone()[0]
                
                # Guardar modificaciones
                for mod in modifications:
                    cur.execute("""
                        INSERT INTO traffic_modifications
                        (traffic_id, modification_type, original_value, modified_value, rule_applied)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (
                        traffic_id,
                        mod.get('type'),
                        json.dumps({}),
                        json.dumps(req_body),
                        json.dumps(mod.get('rules'))
                    ))
                
                # Guardar intentos de desencriptación si hay datos complejos
                for decoded in PayloadDecoder.try_all_decodings(str(req_body))[:3]:
                    cur.execute("""
                        INSERT INTO decryption_attempts
                        (traffic_id, decoded_type, depth, original_value, decoded_value)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (
                        traffic_id,
                        decoded['type'],
                        decoded['depth'],
                        str(req_body)[:500],
                        decoded['full'][:1000]
                    ))
                
                conn.commit()
                cur.close()
                conn.close()
                
        except Exception as ex:
            logger.error("DB logging error: %s", ex)
        
        # Broadcast a clientes SSE
        _broadcast(json.dumps({
            'type': 'packet_captured',
            'method': method,
            'endpoint': endpoint,
            'status': resp.status_code,
            'vulnerabilities': analysis['vulnerabilities'],
            'sensitive_data': sensitive_patterns,
            'modified': len(modifications) > 0,
            'encryption_type': analysis['encryption_type']
        }, default=str))
        
        return jsonify(resp_body), resp.status_code
        
    except Exception as e:
        logger.error("Proxy error: %s", e)
        return jsonify({'error': str(e), 'type': 'proxy_error'}), 502
        return jsonify({'error': str(e)}), 502


# ============================================================
# API Endpoints - Decodificación Avanzada
# ============================================================

@app.route('/api/decode/auto', methods=['POST'])
def api_auto_decode():
    """Intenta todos los decodings posibles"""
    try:
        data = request.get_json() or {}
        payload = data.get('payload', '')
        
        results = PayloadDecoder.try_all_decodings(payload)
        sensitive = PayloadDecoder.extract_sensitive_patterns(str(results))
        
        return jsonify({
            'decodings': results,
            'sensitive_patterns': sensitive,
            'total_layers': len(results)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/analyze/payload', methods=['POST'])
def api_analyze_payload():
    """Análisis completo de payload"""
    try:
        data = request.get_json() or {}
        payload = data.get('payload', '')
        
        decodings = PayloadDecoder.try_all_decodings(payload)
        sensitive = PayloadDecoder.extract_sensitive_patterns(payload)
        
        # Intentar parsear como JSON
        json_parsed = None
        try:
            json_parsed = json.loads(payload)
        except:
            pass
        
        return jsonify({
            'original': payload[:500],
            'decodings': decodings,
            'sensitive_patterns': sensitive,
            'json_parsed': json_parsed,
            'size_bytes': len(payload.encode('utf-8')),
            'encoding_detected': 'base64' if PayloadDecoder.try_all_decodings(payload) else 'plaintext'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/sensitive-data')
def api_sensitive_data():
    """Reporte de datos sensibles capturados"""
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
            ORDER BY timestamp DESC
            LIMIT %s
        """, (limit,))
        
        findings = []
        for row in cur.fetchall():
            r = dict(row)
            if hasattr(r.get('timestamp'), 'isoformat'):
                r['timestamp'] = r['timestamp'].isoformat()
            if isinstance(r.get('sensitive_data'), str):
                try:
                    r['sensitive_data'] = json.loads(r['sensitive_data'])
                except:
                    pass
            findings.append(r)
        
        # Agregación
        all_patterns = {}
        for item in findings:
            patterns = item.get('sensitive_data', {})
            for key, values in patterns.items():
                if key not in all_patterns:
                    all_patterns[key] = []
                if isinstance(values, list):
                    all_patterns[key].extend(values)
        
        # Deduplicar
        for key in all_patterns:
            all_patterns[key] = list(set(all_patterns[key]))[:10]
        
        cur.close()
        conn.close()
        
        return jsonify({
            'findings': findings,
            'aggregated_patterns': all_patterns,
            'total_records': len(findings)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/modifications')
def api_modifications_log():
    """Log de modificaciones realizadas"""
    try:
        limit = min(int(request.args.get('limit', 100)), 500)
        conn = get_db()
        if not conn:
            return jsonify({'error': 'DB unavailable'}), 500
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT m.*, t.method, t.endpoint, t.timestamp as traffic_time
            FROM traffic_modifications m
            JOIN traffic_logs t ON m.traffic_id = t.id
            ORDER BY m.timestamp DESC
            LIMIT %s
        """, (limit,))
        
        mods = []
        for row in cur.fetchall():
            r = dict(row)
            if hasattr(r.get('timestamp'), 'isoformat'):
                r['timestamp'] = r['timestamp'].isoformat()
            if isinstance(r.get('original_value'), str):
                try:
                    r['original_value'] = json.loads(r['original_value'])
                except:
                    pass
            if isinstance(r.get('modified_value'), str):
                try:
                    r['modified_value'] = json.loads(r['modified_value'])
                except:
                    pass
            mods.append(r)
        
        cur.close()
        conn.close()
        
        return jsonify({
            'modifications': mods,
            'total': len(mods)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decryption-attempts')
def api_decryption_attempts():
    """Historial de intentos de desencriptación"""
    try:
        traffic_id = request.args.get('traffic_id')
        limit = min(int(request.args.get('limit', 100)), 500)
        
        conn = get_db()
        if not conn:
            return jsonify({'error': 'DB unavailable'}), 500
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        if traffic_id:
            cur.execute("""
                SELECT * FROM decryption_attempts
                WHERE traffic_id = %s
                ORDER BY depth ASC
                LIMIT %s
            """, (int(traffic_id), limit))
        else:
            cur.execute("""
                SELECT * FROM decryption_attempts
                ORDER BY timestamp DESC
                LIMIT %s
            """, (limit,))
        
        attempts = []
        for row in cur.fetchall():
            r = dict(row)
            if hasattr(r.get('timestamp'), 'isoformat'):
                r['timestamp'] = r['timestamp'].isoformat()
            attempts.append(r)
        
        cur.close()
        conn.close()
        
        return jsonify({
            'attempts': attempts,
            'total': len(attempts)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/mitm-stats')
def api_mitm_stats():
    """Estadísticas de MITM"""
    try:
        conn = get_db()
        if not conn:
            return jsonify({'error': 'DB unavailable'}), 500
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Total interceptado
        cur.execute("""
            SELECT
                COUNT(*) total,
                SUM(CASE WHEN mitm_intercepted THEN 1 ELSE 0 END) intercepted,
                SUM(CASE WHEN mitm_modified THEN 1 ELSE 0 END) modified,
                COUNT(DISTINCT endpoint) endpoints,
                COUNT(DISTINCT client_ip) clients
            FROM traffic_logs
        """)
        stats = dict(cur.fetchone())
        
        # Por tipo de encriptación
        cur.execute("""
            SELECT encryption_type, COUNT(*) cnt
            FROM traffic_logs
            GROUP BY encryption_type
            ORDER BY cnt DESC
        """)
        by_encryption = [dict(r) for r in cur.fetchall()]
        
        # Vulnerabilidades detectadas
        cur.execute("""
            SELECT vulnerabilities::text, COUNT(*) cnt
            FROM traffic_logs
            WHERE vulnerabilities::text != '[]'
            GROUP BY vulnerabilities::text
            LIMIT 10
        """)
        vulnerabilities_raw = cur.fetchall()
        
        # Datos sensibles encontrados
        cur.execute("""
            SELECT COUNT(DISTINCT traffic_id) traffic_count
            FROM decryption_attempts
        """)
        decryption_records = cur.fetchone()[0] if cur.fetchone() else 0
        
        cur.close()
        conn.close()
        
        return jsonify({
            'stats': stats,
            'by_encryption_type': by_encryption,
            'decryption_records': decryption_records,
            'total_modifications': stats.get('modified', 0)
        })
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

    # Start DB polling thread for SSE
    t = threading.Thread(target=_db_poll_thread, daemon=True, name="db-poll")
    t.start()
    logger.info("DB poll thread started - SSE live updates active")


startup()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False, threaded=True)
