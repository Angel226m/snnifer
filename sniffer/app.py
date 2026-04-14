#!/usr/bin/env python3
"""
Network Sniffer PRO - Monitor frontend-backend communication en tiempo real
Captura paquetes HTTP como Wireshark + Dashboard Web + Decoders Avanzados
Persiste todos los datos en PostgreSQL para auditoría y análisis histórico
Con análisis de seguridad + desciframiento automático de payloads
"""

from flask import Flask, render_template_string, request, jsonify
from datetime import datetime
import json
import os
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
import time
import base64
import hashlib
from urllib.parse import quote, unquote
import threading

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
DATABASE_URL = os.getenv('SNIFFER_DB_URL', 'postgresql://postgres:password@db:5432/learnwithgaray')

# Importar decoders avanzados
try:
    from decoders import AdvancedDecoder, PayloadDecryptor
    HAS_DECODERS = True
    logger.info("✅ Decoders Avanzados cargados")
except ImportError as e:
    HAS_DECODERS = False
    logger.warning(f"⚠️ Decoders no disponibles: {e}")

# Importar y iniciar packet sniffer
try:
    from packet_sniffer import start_packet_sniffer
    logger.info("🔍 Inicializando Packet Sniffer (captura de paquetes raw)...")
except ImportError as e:
    logger.warning(f"⚠️ Packet Sniffer no disponible: {e}")

# ==================== SECURITY ANALYSIS ====================

class SecurityAnalyzer:
    """Analiza vulnerabilidades de seguridad en payloads"""
    
    @staticmethod
    def analyze_payload(req_body, resp_body, headers):
        """Detecta vulnerabilidades"""
        vulnerabilities = []
        encryption_type = "UNKNOWN"
        
        # 1️⃣ DÉBIL: Base64 encoding (se ve en Authorization headers)
        if headers:
            auth = headers.get('Authorization', '')
            if auth.startswith('Bearer '):
                token = auth[7:]
                if SecurityAnalyzer.is_base64(token):
                    vulnerabilities.append({
                        'type': 'WEAK_ENCODING',
                        'severity': 'HIGH',
                        'name': '🔓 Base64 Token (NOT Encrypted)',
                        'description': 'Token en Base64 sin encriptación. Se decodifica en 1 segundo con: echo "TOKEN" | base64 -d',
                        'tool': 'CyberChef | base64 -d | Wireshark (filter: http.header.Authorization)'
                    })
                    encryption_type = "BASE64_ONLY"
        
        # 2️⃣ DÉBIL: Plain HTTP Passwords (si ves "password": "xxx")
        payload_str = json.dumps({**req_body, **resp_body}) if req_body or resp_body else ""
        if 'password' in payload_str.lower() and not any(c in payload_str for c in ['$2b', '$2a']):
            vulnerabilities.append({
                'type': 'PLAINTEXT_PASSWORD',
                'severity': 'CRITICAL',
                'name': '🚨 Plaintext Password (HTTP)',
                'description': 'CRÍTICO: Contraseña sin hashear en texto plano. Capturada en 1ms con: tcpdump -i any -A "tcp port 8000" | grep password',
                'tool': 'tcpdump | grep -i password | Wireshark | mitmproxy | sslstrip'
            })
            encryption_type = "PLAINTEXT"
        
        # 3️⃣ DÉBIL: URL Encoding en datos sensibles
        if 'email' in payload_str and '%' in payload_str:
            vulnerabilities.append({
                'type': 'URL_ENCODED_SENSITIVE',
                'severity': 'MEDIUM',
                'name': '⚠️ URL-Encoded Sensitive Data',
                'description': 'Datos en query strings: /login?email=user%40mail.com&pass=secret. Visible en logs, browser history y Wireshark.',
                'tool': 'URL Decode online | urldecoder.org | python -c "import urllib.parse; print(urllib.parse.unquote(...))"'
            })
            encryption_type = "URL_ENCODED"
        
        # 4️⃣ FUERTE: JWT con RS256 (RSA asimétrica)
        if auth and auth.startswith('Bearer ') and auth.count('.') == 2:
            try:
                parts = token.split('.')
                if len(parts) == 3:
                    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                    if header.get('alg') == 'RS256':
                        vulnerabilities.append({
                            'type': 'STRONG_JWT_RS256',
                            'severity': 'SECURE',
                            'name': '✅ JWT RS256 (RSA Asimétrica)',
                            'description': 'Firmado con Private Key del servidor. IMPOSIBLE falsificar sin la key privada. Verificable en jwt.io',
                            'tool': 'jwt.io (solo lectura) | OpenSSL RSA Key required para firmar'
                        })
                        encryption_type = "JWT_RS256"
            except:
                pass
        
        # 5️⃣ FUERTE: TLS 1.3 con AEAD ciphers
        if headers and headers.get('X-Encryption-Type') == 'TLS_1_3_AEAD':
            vulnerabilities.append({
                'type': 'STRONG_TLS13_AEAD',
                'severity': 'SECURE',
                'name': '🔒 TLS 1.3 with AEAD',
                'description': 'Máximo nivel de seguridad: TLS 1.3 + ChaCha20-Poly1305/AES-GCM. IMPOSIBLE desencriptar sin master key.',
                'tool': 'Wireshark + SSLKEYLOGFILE (si tienes server key) | Imposible por fuerza bruta'
            })
            encryption_type = "TLS_1_3_AEAD"
        
        return {
            'vulnerabilities': vulnerabilities,
            'encryption_type': encryption_type,
            'risk_level': 'CRITICAL' if vulnerabilities and vulnerabilities[0]['severity'] in ['CRITICAL', 'HIGH'] else 'MEDIUM' if vulnerabilities else 'LOW'
        }
    
    @staticmethod
    def is_base64(s):
        """Detecta si es Base64"""
        try:
            return isinstance(s, str) and base64.b64encode(base64.b64decode(s)).decode() == s
        except:
            return False

# ==================== DATABASE ====================

def get_db_connection():
    """Crear conexión a la base de datos"""
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception as e:
        logger.error(f"❌ Error de conexión DB: {e}")
        return None

def ensure_traffic_table():
    """Asegurar que la tabla traffic_logs existe"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                method VARCHAR(10),
                endpoint VARCHAR(255),
                status_code INTEGER,
                request_body JSONB,
                response_body JSONB,
                request_headers JSONB,
                response_headers JSONB,
                execution_time_ms FLOAT,
                is_encrypted BOOLEAN DEFAULT TRUE,
                encryption_type VARCHAR(50),
                vulnerabilities JSONB,
                user_agent VARCHAR(255),
                client_ip VARCHAR(45)
            );
            CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic_logs(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_traffic_ep ON traffic_logs(endpoint);
            CREATE INDEX IF NOT EXISTS idx_traffic_vuln ON traffic_logs USING GIN(vulnerabilities);
        """)
        conn.commit()
        cur.close()
        conn.close()
        logger.info("✅ Tabla traffic_logs lista con análisis de seguridad")
        return True
    except Exception as e:
        logger.error(f"❌ Error creando tabla: {e}")
        return False

# ==================== FLASK APP ====================

# HTML Dashboard Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔍 Network Sniffer - Comunicación Frontend↔Backend</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: #e0e0e0;
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1600px; margin: 0 auto; }
        h1 {
            text-align: center;
            margin-bottom: 20px;
            font-size: 2.2em;
            color: #00ff88;
            text-shadow: 0 0 10px rgba(0, 255, 136, 0.5);
        }
        .header-info {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr 1fr;
            gap: 15px;
            margin-bottom: 20px;
        }
        .info-box {
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid #00ff88;
            border-radius: 8px;
            padding: 15px;
            text-align: center;
        }
        .info-label { font-size: 12px; color: #888; text-transform: uppercase; }
        .info-value { font-size: 28px; font-weight: bold; color: #00ff88; margin-top: 5px; }
        .controls {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        button {
            padding: 10px 16px;
            background: #00ff88;
            color: #000;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
            font-family: monospace;
        }
        button:hover { background: #00dd77; transform: scale(1.05); }
        button.danger { background: #ff4444; color: white; }
        button.danger:hover { background: #cc3333; }
        .traffic-containers {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        .panel {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #00ff88;
            border-radius: 8px;
            padding: 20px;
            max-height: 700px;
            overflow-y: auto;
        }
        .panel h2 { color: #00ff88; margin-bottom: 15px; border-bottom: 1px solid #00ff88; padding-bottom: 10px; }
        .traffic-item {
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #00ff88;
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 12px;
            font-size: 12px;
            line-height: 1.6;
            transition: all 0.3s ease;
        }
        .traffic-item:hover {
            border-color: #00ffffff;
            box-shadow: 0 0 15px rgba(0, 255, 136, 0.3);
        }
        .traffic-item.response { border-color: #ffaa00; }
        .traffic-item.error { border-color: #ff4444; }
        .traffic-item.critical { border-color: #ff4444; background: rgba(255, 68, 68, 0.2); box-shadow: 0 0 10px rgba(255, 0, 0, 0.5); }
        .traffic-item.high { border-color: #ff9900; background: rgba(255, 153, 0, 0.2); box-shadow: 0 0 10px rgba(255, 153, 0, 0.3); }
        .traffic-item.medium { border-color: #ffd700; background: rgba(255, 215, 0, 0.2); box-shadow: 0 0 10px rgba(255, 215, 0, 0.3); }
        .timestamp { color: #888; font-size: 10px; font-family: monospace; }
        .method {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            font-weight: bold;
            margin-right: 8px;
            font-size: 11px;
            letter-spacing: 1px;
        }
        .method.post { background: #0066ff; color: white; }
        .method.get { background: #00aa00; color: white; }
        .method.put { background: #ff9900; color: black; }
        .method.delete { background: #ff3333; color: white; }
        .method.patch { background: #ff00ff; color: white; }
        .method.options { background: #666666; color: white; }
        .method.response { background: #bb86fc; color: white; }
        .endpoint { color: #00ff88; font-weight: bold; font-family: monospace; letter-spacing: 0.5px; }
        .status {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            font-weight: bold;
            margin: 0 8px;
            font-size: 11px;
        }
        .status.ok { background: #00aa00; color: white; }
        .status.created { background: #00ff88; color: black; }
        .status.redirect { background: #ffaa00; color: black; }
        .status.error { background: #ff3333; color: white; }
        .payload {
            background: rgba(0, 0, 0, 0.5);
            padding: 8px;
            margin-top: 8px;
            border-radius: 3px;
            border-left: 2px solid #00ff88;
            max-height: 200px;
            overflow: auto;
            font-size: 10px;
            color: #aaa;
        }
        .payload pre { margin: 0; white-space: pre-wrap; word-wrap: break-word; color: #0f0; font-family: monospace; }
        .payload strong { color: #00ff88; }
        .encryption-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            font-size: 11px;
            margin: 0 5px;
            font-weight: bold;
        }
        .encryption-badge.encrypted { background: rgba(0, 255, 136, 0.3); border: 1px solid #00ff88; color: #00ff88; }
        .encryption-badge.plaintext { background: rgba(255, 170, 0, 0.3); border: 1px solid #ffaa00; color: #ffaa00; }
        textarea { font-family: 'Courier New', monospace !important; letter-spacing: 1px; }
        button { transition: all 0.2s ease; }
        button:hover { transform: scale(1.05); opacity: 0.9; }
        button:active { transform: scale(0.95); }
        .packet-table {
            width: 100%;
            border-collapse: collapse;
            background: rgba(0,0,0,0.3);
            margin: 10px 0;
            border: 1px solid #00ff88;
            border-radius: 4px;
            overflow: hidden;
        }
        .packet-table th {
            background: rgba(0,255,136,0.2);
            color: #00ff88;
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #00ff88;
            font-weight: bold;
            font-size: 11px;
        }
        .packet-table td {
            padding: 6px 8px;
            border-bottom: 1px solid rgba(0,255,136,0.2);
            font-size: 10px;
            font-family: monospace;
        }
        .packet-table tr:hover {
            background: rgba(0,255,136,0.1);
        }
        .copy-btn {
            padding: 3px 6px;
            background: #00ff88;
            color: #000;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 9px;
            font-weight: bold;
            transition: all 0.2s;
        }
        .copy-btn:hover {
            background: #00dd77;
            transform: scale(1.1);
        }
        .copy-btn.copied {
            background: #00ff00;
        }
        .edit-btn {
            padding: 3px 6px;
            background: #00ccff;
            color: #000;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 9px;
            font-weight: bold;
        }
        .edit-btn:hover {
            background: #00aadd;
        }
        .inject-panel {
            background: rgba(50,50,100,0.3);
            border: 2px solid #00ccff;
            border-radius: 8px;
            padding: 15px;
            margin-top: 20px;
        }
        .inject-panel h3 {
            color: #00ccff;
            margin-top: 0;
        }
        .inject-panel textarea {
            width: 100%;
            height: 150px;
            background: #000;
            color: #0f0;
            border: 1px solid #00ccff;
            padding: 8px;
            border-radius: 4px;
            font-size: 11px;
        }
        .inject-panel button {
            margin-top: 10px;
            padding: 10px 16px;
            background: #00ccff;
            color: #000;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
        }
        .inject-panel button:hover {
            background: #00aadd;
        }
        @media (max-width: 1200px) {
            .traffic-containers { grid-template-columns: 1fr; }
            .header-info { grid-template-columns: 1fr 1fr; }
        }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: rgba(0, 0, 0, 0.3); }
        ::-webkit-scrollbar-thumb { background: #00ff88; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Network Sniffer - Frontend ↔️ Backend</h1>
        
        <div class="header-info">
            <div class="info-box">
                <div class="info-label">📦 Total</div>
                <div class="info-value" id="total">0</div>
            </div>
            <div class="info-box">
                <div class="info-label">🔒 Encriptado</div>
                <div class="info-value" id="encrypted" style="color: #00ff88;">0</div>
            </div>
            <div class="info-box">
                <div class="info-label">⚠️ Sin TLS</div>
                <div class="info-value" id="plaintext" style="color: #ffaa00;">0</div>
            </div>
            <div class="info-box">
                <div class="info-label">🕐 Última actualización</div>
                <div class="info-value" id="lastupdate" style="font-size: 14px; color: #666;">...</div>
            </div>
        </div>

        <div class="controls">
            <button onclick="location.reload()">🔄 Recargar</button>
            <button onclick="refreshNow()">⚡ Actualizar Ahora</button>
            <button class="danger" onclick="clearTraffic()">🗑️ Limpiar Historial</button>
        </div>

        <div class="traffic-containers">
            <div class="panel">
                <h2>📤 Solicitudes (Frontend → Backend)</h2>
                <div id="requests-panel">
                    <div class="traffic-item">📡 Esperando solicitudes...</div>
                </div>
            </div>
            <div class="panel">
                <h2>📥 Respuestas (Backend → Frontend)</h2>
                <div id="responses-panel">
                    <div class="traffic-item">📡 Esperando respuestas...</div>
                </div>
            </div>
        </div>

        <div class="panel" style="margin-top: 20px;">
            <h2>🚨 Vulnerabilidades Detectadas</h2>
            <div id="vulnerabilities-panel">
                <div class="traffic-item">✅ Sin vulnerabilidades detectadas</div>
            </div>
        </div>

        <div class="panel" style="margin-top: 20px;">
            <h2>💉 Inyectar/Modificar Paquetes (Teórico)</h2>
            <div class="inject-panel">
                <h3>🔧 Modificador de Paquetes en Curso</h3>
                <p style="color: #999; font-size: 11px;">
                    <strong>⚠️ NOTA:</strong> Esta herramienta es para <strong>testing/auditoría</strong>. 
                    Permite crear paquetes personalizados basados en los capturados.
                </p>
                
                <div style="margin-top: 15px;">
                    <label style="color: #00ccff; font-weight: bold;">Select Packet to Clone:</label>
                    <select id="packet-select" style="width: 100%; padding: 8px; background: #000; color: #0f0; border: 1px solid #00ccff; margin: 8px 0; border-radius: 4px;">
                        <option value="">-- Select a capturing packet --</option>
                    </select>
                </div>
                
                <div style="margin-top: 15px;">
                    <label style="color: #00ccff; font-weight: bold;">Modify Packet Payload:</label>
                    <textarea id="inject-payload" placeholder="Modify and inject custom payload..."></textarea>
                </div>
                
                <div style="margin-top: 10px;">
                    <label style="color: #00ccff; font-weight: bold;">Target Endpoint:</label>
                    <input type="text" id="inject-endpoint" style="width: 100%; padding: 8px; background: #000; color: #0f0; border: 1px solid #00ccff; margin: 8px 0; border-radius: 4px;" placeholder="/api/endpoint">
                </div>
                
                <div style="margin-top: 10px;">
                    <label style="color: #00ccff; font-weight: bold;">Method:</label>
                    <select id="inject-method" style="width: 100%; padding: 8px; background: #000; color: #0f0; border: 1px solid #00ccff; margin: 8px 0; border-radius: 4px;">
                        <option>GET</option>
                        <option>POST</option>
                        <option>PUT</option>
                        <option>DELETE</option>
                        <option>PATCH</option>
                    </select>
                </div>
                
                <button onclick="injectPacket()" style="width: 100%; padding: 12px; background: #00ccff; color: #000; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; font-size: 12px; margin-top: 15px;">
                    🚀 Inject Modified Packet
                </button>
                
                <div id="inject-result" style="margin-top: 15px; padding: 10px; background: rgba(0,200,255,0.1); border: 1px solid #00ccff; border-radius: 4px; color: #00ccff; font-size: 11px; display: none;">
                    Result will appear here...
                </div>
            </div>
        </div>
            
            <div style="background: rgba(255,68,68,0.15); border: 1px solid #ff4444; padding: 12px; margin-bottom: 15px; border-radius: 6px;">
                <strong style="color: #ff4444;">⚠️ 3 TIPOS DÉBILES (FÁCILES DE ROMPER):</strong>
                
                <div style="margin-top: 10px; padding-left: 10px; border-left: 2px solid #ff4444;">
                    <div style="margin-bottom: 12px;">
                        <strong>1️⃣ Base64 + Authorization Header</strong><br>
                        <span style="color: #aaa;">La contraseña/token solo está codificado en Base64, NO encriptado</span>
                        <div style="background: rgba(0,0,0,0.5); padding: 8px; margin-top: 6px; border-radius: 4px; font-family: monospace; font-size: 10px;">
                            <strong>Capturar con Wireshark:</strong> filter: <code style="color: #00ff88;">http.header.Authorization</code><br>
                            <strong>Decodificar con CyberChef:</strong> <a href="https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)" style="color: #00ff88;" target="_blank">gchq.github.io/CyberChef/#recipe=From_Base64</a><br>
                            <strong>O en terminal:</strong> <code style="color: #00ff88;">echo "base64_token" | base64 -d</code>
                        </div>
                    </div>
                    
                    <div style="margin-bottom: 12px;">
                        <strong>2️⃣ Plaintext Passwords (Flask, Django sin HTTPS)</strong><br>
                        <span style="color: #aaa;">Contraseña sin hashear viajando en texto plano HTTP</span>
                        <div style="background: rgba(0,0,0,0.5); padding: 8px; margin-top: 6px; border-radius: 4px; font-family: monospace; font-size: 10px;">
                            <strong>Capturar con tcpdump:</strong> <code style="color: #00ff88;">sudo tcpdump -i eth0 -A 'tcp port 8000 or 5000 or 3000' | grep -i password</code><br>
                            <strong>O con Wireshark:</strong> <code style="color: #00ff88;">Follow TCP Stream → Buscar 'password': 'xxx'</code><br>
                            <strong>Herramientas:</strong> Wireshark, tcpdump, mitmproxy, sslstrip
                        </div>
                    </div>
                    
                    <div style="margin-bottom: 12px;">
                        <strong>3️⃣ URL Encoding en Datos Sensibles</strong><br>
                        <span style="color: #aaa;">Email/datos en query strings: /login?email=user%40mail.com&pass=secret</span>
                        <div style="background: rgba(0,0,0,0.5); padding: 8px; margin-top: 6px; border-radius: 4px; font-family: monospace; font-size: 10px;">
                            <strong>Decodificar URL:</strong> <a href="https://www.urldecoder.org/" style="color: #00ff88;" target="_blank">urldecoder.org</a> o <code style="color: #00ff88;">python -c "import urllib.parse; print(urllib.parse.unquote('email%40mail.com'))"</code><br>
                            <strong>Problema:</strong> Visible en browser history, logs del servidor, Wireshark
                        </div>
                    </div>
                </div>
            </div>
            
            <div style="background: rgba(0,255,136,0.15); border: 1px solid #00ff88; padding: 12px; margin-bottom: 15px; border-radius: 6px;">
                <strong style="color: #00ff88;">🔒 2 TIPOS FUERTES (CASI IMPOSIBLES):</strong>
                
                <div style="margin-top: 10px; padding-left: 10px; border-left: 2px solid #00ff88;">
                    <div style="margin-bottom: 12px;">
                        <strong>4️⃣ JWT con RS256 (RSA Asimétrica)</strong><br>
                        <span style="color: #aaa;">Firmado con Private Key del servidor → No se puede falsificar sin la key privada</span>
                        <div style="background: rgba(0,0,0,0.5); padding: 8px; margin-top: 6px; border-radius: 4px; font-family: monospace; font-size: 10px;">
                            <strong>Estructura JWT:</strong> header.payload.signature (3 partes Base64)<br>
                            <strong>Verificar en:</strong> <a href="https://jwt.io/" style="color: #00ff88;" target="_blank">jwt.io</a><br>
                            <strong>Seguridad:</strong> Solo con Private Key se puede firmar → Imposible crear tokens falsos
                        </div>
                    </div>
                    
                    <div>
                        <strong>5️⃣ TLS 1.3 con AEAD (ChaCha20-Poly1305 o AES-GCM)</strong><br>
                        <span style="color: #aaa;">Encriptación moderna con Authenticated Encryption - Máxima seguridad</span>
                        <div style="background: rgba(0,0,0,0.5); padding: 8px; margin-top: 6px; border-radius: 4px; font-family: monospace; font-size: 10px;">
                            <strong>Verificar en Wireshark:</strong> TLS → Handshake → Cipher Suite (si dice 1.3 + AEAD → Seguro)<br>
                            <strong>Para descifrar:</strong> ❌ Imposible sin master key o vulnerabilidad 0-day<br>
                            <strong>Máximo nivel de protección:</strong> Forward Secrecy + AEAD + Perfect Forward Secrecy
                        </div>
                    </div>
                </div>
            </div>
            
            <div style="background: rgba(100,100,100,0.3); padding: 12px; border-radius: 6px; margin-top: 10px;">
                <strong>🛠️ Herramientas Recomendadas:</strong>
                <ul style="margin: 8px 0; padding-left: 20px;">
                    <li><code style="color: #ffaa00;">Wireshark</code> - Captura y análisis de paquetes (GUI)</li>
                    <li><code style="color: #ffaa00;">tcpdump</code> - Captura desde terminal</li>
                    <li><code style="color: #ffaa00;">mitmproxy</code> - Man-in-the-Middle proxy (HTTP/HTTPS)</li>
                    <li><code style="color: #ffaa00;">sslstrip</code> - Downgrade HTTPS → HTTP en WiFi</li>
                    <li><code style="color: #ffaa00;">aircrack-ng</code> - Crack WPA2 handshakes</li>
                    <li><code style="color: #ffaa00;">CyberChef</code> - Decodificar (Base64, URL, Hex, etc)</li>
                    <li><code style="color: #ffaa00;">hashcat</code> - GPU brute-force hashes</li>
                    <li><code style="color: #ffaa00;">hydra</code> - Distributed brute-force (SSH, FTP, HTTP)</li>
                </ul>
            </div>
        </div>
    </div>

    <script>
        function formatTime(ts) {
            if (!ts) return '--:--:--';
            const d = new Date(ts);
            return d.toLocaleTimeString('es-ES', { hour12: false });
        }

        function updateDisplay() {
            fetch('/api/traffic')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('total').textContent = data.total;
                    document.getElementById('encrypted').textContent = data.encrypted;
                    document.getElementById('plaintext').textContent = data.plaintext;
                    document.getElementById('lastupdate').textContent = new Date().toLocaleTimeString('es-ES').split(':').slice(0, 2).join(':');
                    
                    const traffic = data.traffic || [];
                    if (traffic.length === 0) {
                        document.getElementById('requests-panel').innerHTML = '<div class="traffic-item">📡 Esperando solicitudes...</div>';
                        document.getElementById('responses-panel').innerHTML = '<div class="traffic-item">📡 Esperando respuestas...</div>';
                        return;
                    }
                    
                    // Requests & Responses - Mejorado para mostrar todos los paquetes
                    const requests = traffic.filter(t => 
                        (t.method && t.method !== 'RESPONSE') || t.request_body
                    );
                    const responses = traffic.filter(t => 
                        t.method === 'RESPONSE' || (t.response_body && !t.request_body)
                    );
                    
                    document.getElementById('requests-panel').innerHTML = requests.length > 0 ?
                        requests.reverse().slice(0, 50).map(t => formatTrafficItem(t, 'request')).join('') :
                        '<div class="traffic-item">📡 Esperando paquetes...</div>';
                    
                    document.getElementById('responses-panel').innerHTML = responses.length > 0 ?
                        responses.reverse().slice(0, 50).map(t => formatTrafficItem(t, 'response')).join('') :
                        '<div class="traffic-item">📡 Esperando respuestas...</div>';
                    
                    // Vulnerabilities
                    const allVulns = traffic.flatMap(t => (t.vulnerabilities || []).map(v => ({...v, timestamp: t.timestamp})));
                    if (allVulns.length > 0) {
                        const vulnPanel = document.getElementById('vulnerabilities-panel');
                        vulnPanel.innerHTML = allVulns.slice(0, 10).map(v => `
                            <div class="traffic-item ${v.severity.toLowerCase()}">
                                <div class="timestamp">⏱️ ${formatTime(v.timestamp)}</div>
                                <div style="margin-top: 6px; margin-bottom: 8px;">
                                    <span style="color: #ff6b6b; font-weight: bold;">${v.type}</span>
                                    <span style="margin-left: 8px; padding: 2px 8px; border-radius: 3px; background: ${v.severity === 'CRITICAL' ? 'rgba(255,68,68,0.4)' : v.severity === 'HIGH' ? 'rgba(255,153,0,0.4)' : 'rgba(255,215,0,0.4)'}; color: ${v.severity === 'CRITICAL' ? '#ff4444' : v.severity === 'HIGH' ? '#ff9900' : '#ffd700'};">
                                        ${v.severity}
                                    </span>
                                </div>
                                <div style="margin-top: 8px; color: #aaa; font-size: 10px; line-height: 1.5;">
                                    <strong style="color: #00ff88;">${v.name}</strong><br>
                                    ${v.description}<br>
                                    <div style="margin-top: 6px; padding: 6px; background: rgba(0,0,0,0.5); border-left: 2px solid #00ff88; border-radius: 3px;">
                                        <em style="color: #ffaa00;">🔧 Herramienta: ${v.tool}</em>
                                    </div>
                                </div>
                            </div>
                        `).join('');
                    }
                })
                .catch(e => console.error('❌ Error:', e));
        }

        function formatTrafficItem(t, type) {
            const statusClass = t.status_code < 300 ? 'ok' : t.status_code < 400 ? 'redirect' : 'error';
            const hasVulns = t.vulnerabilities && t.vulnerabilities.length > 0;
            const vulnClass = hasVulns ? `${t.vulnerabilities[0].severity.toLowerCase()}` : '';
            
            // Crear ID único para expandir/colapsar
            const itemId = `packet-${t.id || Math.random()}`;
            
            return `
                <div class="traffic-item ${type} ${vulnClass}">
                    <div class="timestamp">⏱️ ${formatTime(t.timestamp)}</div>
                    <div style="margin-top: 8px; margin-bottom: 8px;">
                        <span class="method ${(t.method || 'UNKNOWN').toLowerCase()}">${t.method || 'UNKNOWN'}</span>
                        <span class="endpoint">${t.endpoint || '/'}</span>
                        ${t.status_code ? '<span class="status ' + statusClass + '">HTTP ' + t.status_code + '</span>' : ''}
                        <span class="encryption-badge ${t.is_encrypted ? 'encrypted' : 'plaintext'}">
                            ${t.is_encrypted ? '🔒 ' + (t.encryption_type || 'HTTPS') : '⚠️ HTTP'}
                        </span>
                    </div>
                    
                    <div style="font-size: 11px; color: #999; margin: 6px 0; padding: 6px; background: rgba(0,0,0,0.3); border-radius: 4px;">
                        <strong>📍 ${t.client_ip || 'unknown'}</strong> ${t.execution_time_ms ? '| ⚡ ' + t.execution_time_ms.toFixed(1) + 'ms' : ''}
                        ${t.user_agent ? '<br>🌐 ' + t.user_agent.substring(0, 60) + '...' : ''}
                    </div>
                    
                    ${hasVulns ? '<div style="color: #ff4444; font-size: 11px; font-weight: bold; margin: 4px 0; padding: 4px; background: rgba(255,68,68,0.2); border-radius: 3px;">🚨 ' + t.vulnerabilities[0].name + ' (' + t.vulnerabilities[0].severity + ')</div>' : ''}
                    
                    <div style="margin-top: 8px;">
                        <button onclick="togglePacketDetail('${itemId}')" style="width: 100%; padding: 8px; background: #00ff88; color: #000; border: none; cursor: pointer; font-weight: bold; border-radius: 4px; font-size: 11px;">
                            ▼ Ver Detalles Completos
                        </button>
                    </div>
                    
                    <div id="${itemId}" style="display: none; margin-top: 10px; padding: 10px; background: rgba(0,0,0,0.4); border-radius: 4px; border-left: 3px solid #00ff88;">
                        ${t.request_headers && Object.keys(t.request_headers).length > 0 ? `
                            <div style="margin-bottom: 10px;">
                                <strong style="color: #00ff88;">📤 REQUEST HEADERS:</strong>
                                <div style="font-size: 10px; color: #aaa; max-height: 150px; overflow-y: auto; background: rgba(0,0,0,0.5); padding: 6px; margin-top: 4px; border-radius: 3px; font-family: monospace;">
                                    ${Object.entries(t.request_headers).map(([k,v]) => `<div><strong>${k}:</strong> ${v}</div>`).join('')}
                                </div>
                            </div>
                        ` : ''}
                        
                        ${t.request_body ? `
                            <div style="margin-bottom: 10px;">
                                <strong style="color: #00ff88;">📤 REQUEST BODY:</strong>
                                <textarea readonly style="width: 100%; height: 120px; font-size: 10px; font-family: monospace; background: #000; color: #0f0; border: 1px solid #00ff88; padding: 6px; border-radius: 3px; resize: none;">${JSON.stringify(t.request_body, null, 2)}</textarea>
                                <div style="margin-top: 4px;">
                                    <button onclick="copyToClipboard(this)" style="padding: 4px 8px; font-size: 10px; background: #ffaa00; color: #000; border: none; cursor: pointer; border-radius: 3px;">📋 Copiar</button>
                                    <button onclick="decodeWithAdvancedTools('${btoa(JSON.stringify(t.request_body))}')" style="padding: 4px 8px; font-size: 10px; background: #00ccff; color: #000; border: none; cursor: pointer; border-radius: 3px; margin-left: 4px;">🔓 Herramientas Avanzadas</button>
                                </div>
                            </div>
                        ` : ''}
                        
                        ${t.response_headers && Object.keys(t.response_headers).length > 0 ? `
                            <div style="margin-bottom: 10px;">
                                <strong style="color: #ffaa00;">📥 RESPONSE HEADERS:</strong>
                                <div style="font-size: 10px; color: #aaa; max-height: 150px; overflow-y: auto; background: rgba(0,0,0,0.5); padding: 6px; margin-top: 4px; border-radius: 3px; font-family: monospace;">
                                    ${Object.entries(t.response_headers).map(([k,v]) => `<div><strong>${k}:</strong> ${v}</div>`).join('')}
                                </div>
                            </div>
                        ` : ''}
                        
                        ${t.response_body ? `
                            <div style="margin-bottom: 10px;">
                                <strong style="color: #ffaa00;">📥 RESPONSE BODY:</strong>
                                <textarea readonly style="width: 100%; height: 120px; font-size: 10px; font-family: monospace; background: #000; color: #0f0; border: 1px solid #ffaa00; padding: 6px; border-radius: 3px; resize: none;">${typeof t.response_body === 'string' ? t.response_body : JSON.stringify(t.response_body, null, 2)}</textarea>
                                <div style="margin-top: 4px;">
                                    <button onclick="copyToClipboard(this)" style="padding: 4px 8px; font-size: 10px; background: #ffaa00; color: #000; border: none; cursor: pointer; border-radius: 3px;">📋 Copiar</button>
                                    <button onclick="decodeWithAdvancedTools('${btoa(JSON.stringify(t.response_body))}')" style="padding: 4px 8px; font-size: 10px; background: #00ccff; color: #000; border: none; cursor: pointer; border-radius: 3px; margin-left: 4px;">🔓 Herramientas Avanzadas</button>
                                </div>
                            </div>
                        ` : ''}
                        
                        <div style="margin-top: 10px;">
                            <button onclick="analyzeBase64('${itemId}')" style="padding: 4px 8px; font-size: 10px; background: #ff9900; color: #000; border: none; cursor: pointer; border-radius: 3px; margin: 2px;">🔐 Base64 Decode</button>
                            <button onclick="analyzeURL('${itemId}')" style="padding: 4px 8px; font-size: 10px; background: #ff6600; color: #fff; border: none; cursor: pointer; border-radius: 3px; margin: 2px;">🔗 URL Decode</button>
                            <button onclick="analyzeHex('${itemId}')" style="padding: 4px 8px; font-size: 10px; background: #00ffff; color: #000; border: none; cursor: pointer; border-radius: 3px; margin: 2px;">⚙️ Hex View</button>
                            <button onclick="analyzeJSON('${itemId}')" style="padding: 4px 8px; font-size: 10px; background: #ff0099; color: #fff; border: none; cursor: pointer; border-radius: 3px; margin: 2px;">📊 Format JSON</button>
                        </div>
                    </div>
                </div>
            `;
        }

        function togglePacketDetail(itemId) {
            const elem = document.getElementById(itemId);
            if (elem.style.display === 'none') {
                elem.style.display = 'block';
                elem.parentElement.querySelector('button').textContent = '▲ Ocultar Detalles';
            } else {
                elem.style.display = 'none';
                elem.parentElement.querySelector('button').textContent = '▼ Ver Detalles Completos';
            }
        }

        function copyToClipboard(btn) {
            const textarea = btn.parentElement.previousElementSibling;
            if (!textarea) return;
            
            navigator.clipboard.writeText(textarea.value).then(() => {
                const originalText = btn.textContent;
                btn.textContent = '✅ Copiado!';
                btn.style.background = '#00ff00';
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.style.background = '';
                }, 2000);
            });
        }

        function analyzeBase64(itemId) {
            const elem = document.getElementById(itemId);
            const textareas = elem.querySelectorAll('textarea');
            let content = '';
            
            for (let ta of textareas) {
                if (ta.value) {
                    try {
                        const decoded = atob(ta.value);
                        content += decoded + '\n\n';
                    } catch {
                        const text = ta.value;
                        for (let i = 0; i < text.length; i++) {
                            if (/^[A-Za-z0-9+/=]+$/.test(text[i])) continue;
                        }
                        const b64Match = text.match(/[A-Za-z0-9+\/]{20,}={0,2}/g);
                        if (b64Match) {
                            b64Match.forEach(match => {
                                try {
                                    content += 'BASE64: ' + match + '\nDECODED: ' + atob(match) + '\n\n';
                                } catch {}
                            });
                        }
                    }
                }
            }
            
            if (content) {
                alert('BASE64 DECODIFICADO:\n\n' + content);
            } else {
                alert('No se encontró Base64 válido en este paquete');
            }
        }

        function analyzeURL(itemId) {
            const elem = document.getElementById(itemId);
            const endpoint = elem.closest('.traffic-item').querySelector('.endpoint').textContent;
            const decoded = decodeURIComponent(endpoint);
            alert('URL DECODIFICADA:\n\n' + decoded);
        }

        function analyzeHex(itemId) {
            const elem = document.getElementById(itemId);
            const textareas = elem.querySelectorAll('textarea');
            let hex = '';
            
            if (textareas.length > 0) {
                const text = textareas[0].value;
                for (let i = 0; i < text.length; i++) {
                    hex += text.charCodeAt(i).toString(16).padStart(2, '0') + ' ';
                }
            }
            
            alert('HEX VIEW:\n\n' + (hex || 'No hay contenido'));
        }

        function analyzeJSON(itemId) {
            const elem = document.getElementById(itemId);
            const textareas = elem.querySelectorAll('textarea');
            
            if (textareas.length > 0) {
                try {
                    const parsed = JSON.parse(textareas[0].value);
                    alert('JSON FORMATEADO:\n\n' + JSON.stringify(parsed, null, 2));
                } catch {
                    alert('Este contenido no es JSON válido');
                }
            }
        }

        function decodePayload(itemId, encoded) {
            try {
                const decoded = atob(encoded);
                alert('PAYLOAD DECODIFICADO:\n\n' + decoded);
            } catch {
                alert('Error al decodificar');
            }
        }

        function decodeWithAdvancedTools(payload) {
            if (!payload) {
                alert('❌ No hay payload para decodificar');
                return;
            }
            
            // Mostrar modal con opciones de decodificación
            const modal = document.createElement('div');
            modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); display: flex; align-items: center; justify-content: center; z-index: 9999;';
            
            modal.innerHTML = `
                <div style="background: #1a1a2e; border: 2px solid #00ff88; border-radius: 8px; padding: 20px; max-width: 600px; max-height: 80vh; overflow-y: auto; color: #e0e0e0;">
                    <div style="text-align: right; margin-bottom: 15px;">
                        <button onclick="this.closest('div').parentElement.remove()" style="background: #ff4444; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer;">✕ Cerrar</button>
                    </div>
                    
                    <h3 style="color: #00ff88; margin-top: 0;">🔓 Herramientas Avanzadas de Decodificación</h3>
                    <p style="color: #999; font-size: 12px;">Payload original: ${payload.substring(0, 50)}...</p>
                    
                    <hr style="border-color: #00ff88; margin: 15px 0;">
                    
                    <div style="margin-bottom: 15px;">
                        <button class="decode-btn" onclick="performDecoding('auto', '${payload}')" style="display:block; width: 100%; padding: 10px; margin: 5px 0; background: #00ff88; color: #000; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">
                            🔄 AUTO-DECODIFICAR (Detectar automáticamente)
                        </button>
                        
                        <button class="decode-btn" onclick="performDecoding('base64', '${payload}')" style="display:block; width: 100%; padding: 10px; margin: 5px 0; background: #0066ff; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">
                            📦 Base64 Decode
                        </button>
                        
                        <button class="decode-btn" onclick="performDecoding('url', '${payload}')" style="display:block; width: 100%; padding: 10px; margin: 5px 0; background: #ff9900; color: #000; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">
                            🔗 URL Decode
                        </button>
                        
                        <button class="decode-btn" onclick="performDecoding('hex', '${payload}')" style="display:block; width: 100%; padding: 10px; margin: 5px 0; background: #00ccff; color: #000; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">
                            ⚙️ Hex Decode
                        </button>
                        
                        <button class="decode-btn" onclick="performDecoding('analyze', '${payload}')" style="display:block; width: 100%; padding: 10px; margin: 5px 0; background: #ff6699; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">
                            🔍 Analizar Payload
                        </button>
                        
                        <button class="decode-btn" onclick="performDecoding('extract', '${payload}')" style="display:block; width: 100%; padding: 10px; margin: 5px 0; background: #ffaa00; color: #000; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">
                            📋 Extraer Datos Sensibles
                        </button>
                        
                        <button class="decode-btn" onclick="performDecoding('try-all', '${payload}')" style="display:block; width: 100%; padding: 10px; margin: 5px 0; background: #00ff00; color: #000; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">
                            🚀 Intentar Todas las Decodificaciones
                        </button>
                    </div>
                    
                    <div id="decode-results" style="margin-top: 15px; background: rgba(0,0,0,0.5); padding: 10px; border-radius: 4px; min-height: 50px; max-height: 300px; overflow-y: auto;">
                        <p style="color: #999;">Resultados aparecerán aquí...</p>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
        }

        function performDecoding(type, payload) {
            const resultsDiv = document.querySelector('#decode-results');
            resultsDiv.innerHTML = '<p style="color: #999;">⏳ Procesando...</p>';
            
            let endpoint = '';
            if (type === 'auto') endpoint = '/api/decode';
            else if (type === 'base64') endpoint = '/api/decode/base64';
            else if (type === 'url') endpoint = '/api/decode/url';
            else if (type === 'hex') endpoint = '/api/decode/hex';
            else if (type === 'analyze') endpoint = '/api/decode/analyze';
            else if (type === 'extract') endpoint = '/api/decode/extract-sensitive';
            else if (type === 'try-all') endpoint = '/api/decode/try-all';
            
            fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ payload: payload })
            })
            .then(r => r.json())
            .then(data => {
                let html = '';
                
                if (data.error) {
                    html = `<div style="color: #ff4444;"><strong>❌ Error:</strong> ${data.error}</div>`;
                } else if (type === 'auto') {
                    html = `
                        <div style="color: #00ff88;">
                            <strong>✅ Decodificaciones encontradas:</strong>
                            <div style="margin-top: 10px;">
                                ${Object.entries(data.decodings || {}).map(([k,v]) => 
                                    `<div style="background: rgba(0,255,136,0.1); padding: 8px; margin: 5px 0; border-radius: 3px;">
                                        <strong>${k}:</strong> ${(v || '').substring(0, 150)}...
                                    </div>`
                                ).join('')}
                            </div>
                            ${Object.keys(data.detections?.api_keys || {}).length > 0 ? 
                                `<div style="color: #ff4444; margin-top: 10px;"><strong>🚨 API Keys Detectadas:</strong> ${JSON.stringify(data.detections.api_keys)}</div>` : ''}
                        </div>
                    `;
                } else if (type === 'analyze') {
                    html = `
                        <div style="color: #ffaa00;">
                            <strong>📊 Análisis:</strong>
                            <div style="margin-top: 8px; font-size: 11px;">
                                <div>Tipo: <strong>${data.type}</strong></div>
                                <div>Tamaño: <strong>${data.size} bytes</strong></div>
                                ${data.sensitive_data.length > 0 ? `<div style="color: #ff4444;">🚨 Datos Sensibles: ${data.sensitive_data.join(', ')}</div>` : ''}
                                ${data.suspicious_patterns.length > 0 ? `<div style="color: #ff9900;">⚠️ Patrones Sospechosos: ${data.suspicious_patterns.join(', ')}</div>` : ''}
                            </div>
                        </div>
                    `;
                } else if (type === 'extract') {
                    html = `
                        <div style="color: #ffaa00;">
                            <strong>📋 Datos Extraídos:</strong>
                            ${data.emails?.length > 0 ? `<div style="margin-top: 8px;"><strong>📧 Emails:</strong> ${data.emails.join(', ')}</div>` : ''}
                            ${data.urls?.length > 0 ? `<div style="margin-top: 8px;"><strong>🔗 URLs:</strong> ${data.urls.slice(0, 3).join(', ')}</div>` : ''}
                            ${Object.keys(data.api_keys || {}).length > 0 ? 
                                `<div style="color: #ff4444; margin-top: 8px;"><strong>🚨 API Keys Detectadas:</strong><br>${Object.entries(data.api_keys).map(([k,v]) => `${k}: ${v[0]?.substring(0, 30)}...`).join('<br>')}</div>` : ''}
                        </div>
                    `;
                } else if (type === 'try-all') {
                    html = `
                        <div style="color: #00ff88;">
                            <strong>🚀 Decodificaciones Sucesivas (${data.total_layers} capas):</strong>
                            ${data.decodings.map((d, i) => 
                                `<div style="background: rgba(0,255,136,0.1); padding: 8px; margin: 5px 0; border-radius: 3px;">
                                    <strong>Capa ${d.depth} - ${d.method}:</strong> ${d.payload.substring(0, 100)}...
                                </div>`
                            ).join('')}
                        </div>
                    `;
                } else {
                    html = `
                        <div style="color: #00ff88;">
                            <strong>${data.success ? '✅ Decodificado:' : '❌ Fallo'}
                            <textarea readonly style="width: 100%; height: 200px; font-size: 10px; font-family: monospace; background: #000; color: #0f0; border: 1px solid #00ff88; padding: 6px; margin-top: 8px; border-radius: 3px; resize: none;">${data.result || data.error || 'Sin resultado'}</textarea>
                        </div>
                    `;
                }
                
                resultsDiv.innerHTML = html;
            })
            .catch(e => {
                resultsDiv.innerHTML = `<div style="color: #ff4444;"><strong>❌ Error:</strong> ${e.message}</div>`;
            });
        }

        function clearTraffic() {
            if (confirm('¿Borrar todo el historial de tráfico?')) {
                fetch('/api/traffic', { method: 'DELETE' })
                    .then(() => { setTimeout(updateDisplay, 300); });
            }
        }

        function refreshNow() {
            updateDisplay();
        }

        // ==================== COPY & INJECT FUNCTIONS ====================

        function copyToClipboardAdvanced(text, btn) {
            navigator.clipboard.writeText(text).then(() => {
                const originalText = btn.textContent;
                btn.textContent = '✅ Copiado!';
                btn.style.background = '#00ff00';
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.style.background = '';
                }, 2000);
            });
        }

        function populatePacketSelect() {
            fetch('/api/traffic?limit=50')
                .then(r => r.json())
                .then(data => {
                    const select = document.getElementById('packet-select');
                    if (!select) return;
                    
                    select.innerHTML = '<option value="">-- Select a captured packet --</option>';
                    
                    if (data.traffic && data.traffic.length > 0) {
                        data.traffic.forEach((t, i) => {
                            const label = `${t.timestamp} | ${t.method} ${t.endpoint} (${t.status_code})`;
                            const option = document.createElement('option');
                            option.value = JSON.stringify({
                                method: t.method,
                                endpoint: t.endpoint,
                                body: t.request_body || t.response_body || {},
                                headers: t.request_headers || {}
                            });
                            option.textContent = label;
                            select.appendChild(option);
                        });
                    }
                });
        }

        function onPacketSelected() {
            const select = document.getElementById('packet-select');
            const payload = document.getElementById('inject-payload');
            const endpoint = document.getElementById('inject-endpoint');
            const method = document.getElementById('inject-method');
            
            if (select.value) {
                const packet = JSON.parse(select.value);
                payload.value = JSON.stringify(packet.body, null, 2);
                endpoint.value = packet.endpoint;
                method.value = packet.method || 'POST';
            }
        }

        function injectPacket() {
            const payload = document.getElementById('inject-payload').value;
            const endpoint = document.getElementById('inject-endpoint').value;
            const method = document.getElementById('inject-method').value;
            const resultDiv = document.getElementById('inject-result');
            
            if (!payload || !endpoint) {
                resultDiv.style.display = 'block';
                resultDiv.textContent = '❌ Payload and endpoint required';
                resultDiv.style.color = '#ff4444';
                return;
            }
            
            resultDiv.style.display = 'block';
            resultDiv.textContent = '⏳ Sending packet...';
            resultDiv.style.color = '#ffaa00';
            
            let data = {};
            try {
                data = JSON.parse(payload);
            } catch {
                data = { raw: payload };
            }
            
            fetch(endpoint, {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                    'X-Injected-Packet': 'true'
                },
                body: JSON.stringify(data)
            })
            .then(r => {
                resultDiv.style.color = '#00ff88';
                resultDiv.textContent = `✅ Packet injected! Status: ${r.status} ${r.statusText}`;
                
                setTimeout(() => {
                    updateDisplay();
                    populatePacketSelect();
                }, 500);
            })
            .catch(e => {
                resultDiv.style.color = '#ff4444';
                resultDiv.textContent = `❌ Error: ${e.message}`;
            });
        }

        // ==================== VIEW AS TABLE ====================

        function viewPacketAsTable(itemId) {
            const item = document.getElementById(itemId);
            if (!item) return;
            
            const packet = {
                method: item.querySelector('.method')?.textContent || 'UNKNOWN',
                endpoint: item.querySelector('.endpoint')?.textContent || '/',
                status: item.querySelector('.status')?.textContent || 'N/A',
                timestamp: item.querySelector('.timestamp')?.textContent || 'N/A',
            };
            
            let html = `
                <table class="packet-table">
                    <thead>
                        <tr>
                            <th>Property</th>
                            <th>Value</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Method</td>
                            <td><strong>${packet.method}</strong></td>
                            <td><button class="copy-btn" onclick="copyToClipboardAdvanced('${packet.method}', this)">Copy</button></td>
                        </tr>
                        <tr>
                            <td>Endpoint</td>
                            <td><strong>${packet.endpoint}</strong></td>
                            <td><button class="copy-btn" onclick="copyToClipboardAdvanced('${packet.endpoint}', this)">Copy</button></td>
                        </tr>
                        <tr>
                            <td>Status</td>
                            <td><strong>${packet.status}</strong></td>
                            <td><button class="copy-btn" onclick="copyToClipboardAdvanced('${packet.status}', this)">Copy</button></td>
                        </tr>
                        <tr>
                            <td>Timestamp</td>
                            <td><strong>${packet.timestamp}</strong></td>
                            <td><button class="copy-btn" onclick="copyToClipboardAdvanced('${packet.timestamp}', this)">Copy</button></td>
                        </tr>
                    </tbody>
                </table>
            `;
            
            alert(html);
        }

        // ==================== AUTO-UPDATE ====================

        function refreshNow() {
            updateDisplay();
        }

        // Auto-update cada 1.5 segundos
        setInterval(() => {
            updateDisplay();
            populatePacketSelect();
        }, 1500);
        
        // Initial load
        updateDisplay();
        populatePacketSelect();
        
        // Add event listener to packet select
        const packetSelect = document.getElementById('packet-select');
        if (packetSelect) {
            packetSelect.addEventListener('change', onPacketSelected);
        }
    </script>
</body>
</html>
"""

@app.before_request
def capture_start():
    """Iniciar captura de tiempo"""
    request.start_time = time.time()

@app.after_request
def capture_end(response):
    """Guardar tráfico en BD con análisis de seguridad"""
    # Capturar TODOS los requests que NO sean del sniffer mismo
    if not request.path.startswith('/api/traffic') and not request.path.startswith('/health'):
        try:
            conn = get_db_connection()
            if not conn:
                return response
            
            # Parse bodies
            req_body = None
            if request.is_json and request.get_data(as_text=True):
                try:
                    req_body = request.get_json()
                except:
                    pass
            
            resp_body = None
            if response.is_json and response.get_data(as_text=True):
                try:
                    resp_body = response.get_json()
                except:
                    pass
            
            # Capturar headers
            req_headers = dict(request.headers)
            resp_headers = dict(response.headers)
            
            # Análisis de seguridad
            security_analysis = SecurityAnalyzer.analyze_payload(req_body, resp_body, req_headers)
            
            exec_time = (time.time() - getattr(request, 'start_time', time.time())) * 1000
            
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO traffic_logs 
                (method, endpoint, status_code, request_body, response_body, 
                 request_headers, response_headers, execution_time_ms, is_encrypted, 
                 encryption_type, vulnerabilities, user_agent, client_ip)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                request.method,
                request.path,
                response.status_code,
                json.dumps(req_body) if req_body else None,
                json.dumps(resp_body) if resp_body else None,
                json.dumps(req_headers),
                json.dumps(resp_headers),
                exec_time,
                response.status_code < 300,  # Asume que 2xx es exitoso
                security_analysis['encryption_type'],
                json.dumps(security_analysis['vulnerabilities']),
                request.headers.get('User-Agent', ''),
                request.remote_addr
            ))
            
            conn.commit()
            cur.close()
            conn.close()
            
            # Log
            if security_analysis['vulnerabilities']:
                logger.warning(f"🚨 VULNERABILITIES DETECTED: {security_analysis['encryption_type']}")
            
        except Exception as e:
            logger.error(f"❌ Error guardando tráfico: {e}")
    
    return response

@app.route('/')
def dashboard():
    """Dashboard principal"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/traffic', methods=['GET', 'DELETE'])
def traffic():
    """Get o DELETE traffic logs con análisis de seguridad"""
    if request.method == 'DELETE':
        try:
            conn = get_db_connection()
            if conn:
                cur = conn.cursor()
                cur.execute("TRUNCATE TABLE traffic_logs")
                conn.commit()
                cur.close()
                conn.close()
                logger.info("✅ Traffic logs borrados")
                return jsonify({'status': 'cleared'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database unavailable'}), 500
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT * FROM traffic_logs
            ORDER BY timestamp DESC
            LIMIT 100
        """)
        
        traffic_list = []
        for row in cur.fetchall():
            item = dict(row)
            # Parse JSON fields
            for field in ['request_body', 'response_body', 'request_headers', 'response_headers', 'vulnerabilities']:
                if field in item and isinstance(item[field], str):
                    try:
                        item[field] = json.loads(item[field])
                    except:
                        pass
            traffic_list.append(item)
        
        # Stats
        cur.execute("""
            SELECT 
                COUNT(*) total,
                SUM(CASE WHEN is_encrypted THEN 1 ELSE 0 END) encrypted,
                SUM(CASE WHEN NOT is_encrypted THEN 1 ELSE 0 END) plaintext,
                COUNT(DISTINCT encryption_type) encryption_types
            FROM traffic_logs
        """)
        stats = cur.fetchone()
        
        # Vulnerabilities summary
        cur.execute("""
            SELECT 
                encryption_type,
                COUNT(*) count,
                MAX((vulnerabilities->0->>'severity')::text) max_severity
            FROM traffic_logs
            WHERE vulnerabilities IS NOT NULL AND vulnerabilities::text != '[]'
            GROUP BY encryption_type
        """)
        vuln_summary = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return jsonify({
            'total': stats['total'] or 0,
            'encrypted': stats['encrypted'] or 0,
            'plaintext': stats['plaintext'] or 0,
            'encryption_types': stats['encryption_types'] or 0,
            'vulnerabilities_summary': [dict(v) for v in vuln_summary] if vuln_summary else [],
            'traffic': traffic_list
        })
        
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        return jsonify({'error': str(e)}), 500

# ==================== NEW: ADVANCED DECODER ENDPOINTS ====================

@app.route('/api/decode', methods=['POST'])
def api_decode():
    """Endpoint para decodificar payloads con todos los métodos disponibles"""
    if not HAS_DECODERS:
        return jsonify({'error': 'Decoders not available'}), 503
    
    try:
        data = request.get_json()
        payload = data.get('payload', '')
        
        if not payload:
            return jsonify({'error': 'No payload provided'}), 400
        
        # Ejecutar auto-decode
        result = AdvancedDecoder.auto_decode(payload)
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decode/base64', methods=['POST'])
def api_decode_base64():
    """Decodificar Base64"""
    if not HAS_DECODERS:
        return jsonify({'error': 'Decoders not available'}), 503
    
    try:
        data = request.get_json()
        payload = data.get('payload', '')
        
        success, result = AdvancedDecoder.decode_base64(payload)
        return jsonify({'success': success, 'result': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decode/url', methods=['POST'])
def api_decode_url():
    """Decodificar URL Encoding"""
    if not HAS_DECODERS:
        return jsonify({'error': 'Decoders not available'}), 503
    
    try:
        data = request.get_json()
        payload = data.get('payload', '')
        
        success, result = AdvancedDecoder.decode_url(payload)
        return jsonify({'success': success, 'result': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decode/hex', methods=['POST'])
def api_decode_hex():
    """Decodificar Hex"""
    if not HAS_DECODERS:
        return jsonify({'error': 'Decoders not available'}), 503
    
    try:
        data = request.get_json()
        payload = data.get('payload', '')
        
        success, result = AdvancedDecoder.decode_hex(payload)
        return jsonify({'success': success, 'result': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decode/analyze', methods=['POST'])
def api_decode_analyze():
    """Análisis completo de payload"""
    if not HAS_DECODERS:
        return jsonify({'error': 'Decoders not available'}), 503
    
    try:
        data = request.get_json()
        payload = data.get('payload', '')
        
        analysis = AdvancedDecoder.analyze_payload_advanced(payload)
        return jsonify(analysis), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decode/extract-tokens', methods=['POST'])
def api_extract_tokens():
    """Extraer tokens Base64 del payload"""
    if not HAS_DECODERS:
        return jsonify({'error': 'Decoders not available'}), 503
    
    try:
        data = request.get_json()
        payload = data.get('payload', '')
        
        tokens = AdvancedDecoder.extract_base64_tokens(payload)
        
        # Intentar decodificar cada uno
        decoded_tokens = {}
        for token in tokens[:10]:  # Primeros 10
            success, result = AdvancedDecoder.decode_base64(token)
            if success:
                decoded_tokens[token[:30] + '...'] = result[:100]
        
        return jsonify({
            'found_tokens': len(tokens),
            'tokens': tokens[:10],
            'decoded': decoded_tokens
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decode/extract-sensitive', methods=['POST'])
def api_extract_sensitive():
    """Extraer datos sensibles (emails, URLs, API keys)"""
    if not HAS_DECODERS:
        return jsonify({'error': 'Decoders not available'}), 503
    
    try:
        data = request.get_json()
        payload = data.get('payload', '')
        
        result = {
            'emails': AdvancedDecoder.extract_emails(payload),
            'urls': AdvancedDecoder.extract_urls(payload),
            'api_keys': AdvancedDecoder.extract_api_keys(payload),
        }
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decode/try-all', methods=['POST'])
def api_try_all_decodings():
    """Intentar todas las decodificaciones sucesivas"""
    if not HAS_DECODERS:
        return jsonify({'error': 'Decoders not available'}), 503
    
    try:
        data = request.get_json()
        payload = data.get('payload', '')
        
        results = PayloadDecryptor.try_all_decodings(payload)
        return jsonify({
            'original': payload[:200],
            'decodings': results,
            'total_layers': len(results)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/security-report', methods=['GET'])
def security_report():
    """Reporte de seguridad con vulnerabilidades detectadas"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database unavailable'}), 500
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Obtener todos los registros con vulnerabilidades
        cur.execute("""
            SELECT 
                timestamp,
                method,
                endpoint,
                encryption_type,
                vulnerabilities,
                status_code
            FROM traffic_logs
            WHERE vulnerabilities IS NOT NULL AND vulnerabilities::text != '[]'
            ORDER BY timestamp DESC
            LIMIT 50
        """)
        
        vulns = []
        for row in cur.fetchall():
            row = dict(row)
            if isinstance(row['vulnerabilities'], str):
                row['vulnerabilities'] = json.loads(row['vulnerabilities'])
            vulns.append(row)
        
        # Resumen
        cur.execute("""
            SELECT 
                encryption_type,
                COUNT(*) as count
            FROM traffic_logs
            GROUP BY encryption_type
            ORDER BY count DESC
        """)
        
        types = [dict(t) for t in cur.fetchall()]
        cur.close()
        conn.close()
        
        return jsonify({
            'encryption_types': types,
            'vulnerabilities': vulns,
            'recommendations': {
                'weak_encoding': 'Usa JWT con RS256 o TLS 1.3 AEAD',
                'plaintext_password': 'CRÍTICO: Implementa bcrypt + HTTPS + TLS 1.3',
                'url_encoded_sensitive': 'Nunca envíes datos sensibles en URL. Usa POST + TLS 1.3'
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    try:
        conn = get_db_connection()
        if conn:
            conn.close()
            return jsonify({'status': 'ok', 'db': 'connected'}), 200
    except:
        pa