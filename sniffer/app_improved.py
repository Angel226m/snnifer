#!/usr/bin/env python3
"""
Network Sniffer v3 - WIRESHARK REAL
Captura paquetes HTTP reales entre frontend y backend.
El backend envía cada request/response a /api/capture (no simulado).
"""

from flask import Flask, render_template, request, jsonify, Response
from flask_cors import CORS
from datetime import datetime
import json
import os
import logging
import time
import re
from threading import Lock
from collections import deque

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Enable CORS for frontend communication
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:3000", "http://localhost:5000"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

# ============================================================
# ANALIZADOR DE DATOS CAPTURADOS
# ============================================================
class DataAnalyzer:
    """Analiza y extrae datos de payloads JSON"""
    
    @staticmethod
    def is_json(text):
        """Verifica si el texto es JSON válido"""
        try:
            json.loads(text)
            return True
        except (json.JSONDecodeError, TypeError):
            return False
    
    @staticmethod
    def extract_sensitive_data(data):
        """Extrae datos sensibles del payload"""
        sensitive = {
            'passwords': [],
            'emails': [],
            'api_keys': [],
            'tokens': [],
            'phone_numbers': [],
            'credit_cards': []
        }
        
        data_str = json.dumps(data) if isinstance(data, dict) else str(data)
        
        # Detectar contraseñas
        password_patterns = [
            r'"password"\s*:\s*"([^"]+)"',
            r"'password'\s*:\s*'([^']+)'",
            r'"password"\s*:\s*([^,}]+)',
        ]
        for pattern in password_patterns:
            matches = re.findall(pattern, data_str, re.IGNORECASE)
            sensitive['passwords'].extend(matches)
        
        # Detectar emails
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        sensitive['emails'] = re.findall(email_pattern, data_str)
        
        # Detectar tokens
        token_pattern = r'(eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.)'
        sensitive['tokens'] = re.findall(token_pattern, data_str)
        
        # Detectar API keys
        api_patterns = [
            r'"api[_-]?key"\s*:\s*"([^"]+)"',
            r'"secret"\s*:\s*"([^"]+)"',
        ]
        for pattern in api_patterns:
            matches = re.findall(pattern, data_str, re.IGNORECASE)
            sensitive['api_keys'].extend(matches)
        
        # Detectar teléfonos (formato español 9 dígitos o US 10 dígitos)
        phone_patterns = [
            r'\b[6-9]\d{8}\b',                        # Móvil español: 6XX/7XX/8XX/9XX
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',       # US format: XXX-XXX-XXXX
        ]
        phones = []
        for pp in phone_patterns:
            phones.extend(re.findall(pp, data_str))
        sensitive['phone_numbers'] = list(set(phones))
        
        # Detectar tarjetas de crédito
        cc_pattern = r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
        sensitive['credit_cards'] = re.findall(cc_pattern, data_str)

        # Detectar DNI / documentos de identidad (7-10 dígitos)
        dni_pattern = r'"dni"\s*:\s*"?(\d{7,10})"?'
        sensitive['documents'] = re.findall(dni_pattern, data_str, re.IGNORECASE)

        # Datos personales en texto plano (name, address, etc.)
        personal_patterns = [
            r'"name"\s*:\s*"([^"]+)"',
            r'"surname"\s*:\s*"([^"]+)"',
            r'"address"\s*:\s*"([^"]+)"',
            r'"fullname"\s*:\s*"([^"]+)"',
        ]
        personal = []
        for pp in personal_patterns:
            personal.extend(re.findall(pp, data_str, re.IGNORECASE))
        sensitive['personal_data'] = list(set(personal))

        # Limpiar duplicados
        for key in sensitive:
            sensitive[key] = list(set(sensitive[key]))

        return sensitive
    
    @staticmethod
    def calculate_risk_level(data):
        """Calcula el nivel de riesgo de los datos"""
        risk_score = 0
        
        if isinstance(data, dict):
            data_str = json.dumps(data)
        else:
            data_str = str(data)
        
        # Scoring de riesgo
        if re.search(r'"password"\s*:', data_str, re.IGNORECASE):
            risk_score += 100
        if re.search(r'@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', data_str):
            risk_score += 30
        if re.search(r'(access_token|token_type|bearer)', data_str, re.IGNORECASE):
            risk_score += 60
        if re.search(r'(api[_-]?key|secret)', data_str, re.IGNORECASE):
            risk_score += 50
        # Teléfono español o US
        if re.search(r'\b[6-9]\d{8}\b|\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', data_str):
            risk_score += 40
        # Datos personales expuestos
        if re.search(r'"(name|surname|address|dni)"\s*:', data_str, re.IGNORECASE):
            risk_score += 25
        
        if risk_score >= 100:
            return 'CRÍTICO'
        elif risk_score >= 50:
            return 'ALTO'
        elif risk_score >= 20:
            return 'MEDIO'
        else:
            return 'BAJO'


# ============================================================
# GESTOR DE PAQUETES CAPTURADOS
# ============================================================
class PacketManager:
    """Gestiona el almacenamiento y recuperación de paquetes capturados"""
    
    def __init__(self, max_packets=500):
        self.packets = deque(maxlen=max_packets)
        self.lock = Lock()
        self.packet_id = 0
    
    def add_packet(self, method, endpoint, direction, data,
                   headers=None, status_code=None, source=None, destination=None):
        """Agrega un nuevo paquete capturado"""
        with self.lock:
            self.packet_id += 1

            # Parsear JSON si es posible
            payload = data
            is_json = False
            if isinstance(data, str) and data.strip():
                if DataAnalyzer.is_json(data):
                    try:
                        payload = json.loads(data)
                        is_json = True
                    except Exception:
                        payload = data
            elif isinstance(data, dict) and data:
                payload = data
                is_json = True

            # Extraer datos sensibles
            sensitive = DataAnalyzer.extract_sensitive_data(payload)

            packet = {
                'id': self.packet_id,
                'timestamp': datetime.now().isoformat(),
                'method': method,
                'endpoint': endpoint,
                'direction': direction,
                'source': source or ('Frontend' if direction == 'REQUEST → Backend' else 'Backend'),
                'destination': destination or ('Backend' if direction == 'REQUEST → Backend' else 'Frontend'),
                'payload': payload,
                'is_json': is_json,
                'sensitive_data': sensitive,
                'risk_level': DataAnalyzer.calculate_risk_level(payload),
                'headers': headers or {},
                'status_code': status_code,
                'size_bytes': len(str(data))
            }

            self.packets.append(packet)
            logger.info(f"[CAPTURA] {method} {endpoint} [{direction}] → {packet['risk_level']}")
            return packet
    
    def get_all(self):
        """Retorna todos los paquetes"""
        with self.lock:
            return list(self.packets)
    
    def get_by_id(self, packet_id):
        """Obtiene un paquete específico"""
        with self.lock:
            for pkt in self.packets:
                if pkt['id'] == packet_id:
                    return pkt
        return None
    
    def clear(self):
        """Limpia todos los paquetes"""
        with self.lock:
            self.packets.clear()
            logger.info("[LIMPIEZA] Se eliminaron todos los paquetes capturados")
    
    def get_stats(self):
        """Retorna estadísticas"""
        with self.lock:
            total = len(self.packets)
            critical = sum(1 for p in self.packets if p['risk_level'] == 'CRÍTICO')
            high = sum(1 for p in self.packets if p['risk_level'] == 'ALTO')
            requests = sum(1 for p in self.packets if 'REQUEST' in p.get('direction', ''))

            return {
                'total_packets': total,
                'critical': critical,
                'high': high,
                'total_requests': requests,
                'risk_summary': f"{critical} CRÍTICO, {high} ALTO"
            }


# Instancia global del gestor
packet_manager = PacketManager()

# ============================================================
# RUTAS API
# ============================================================

@app.route('/')
def index():
    """Página principal con el dashboard mejorado"""
    return render_template('dashboard_improved.html')


@app.route('/api/packets', methods=['GET'])
def get_packets():
    """Retorna todos los paquetes capturados como JSON"""
    packets = packet_manager.get_all()
    return jsonify({
        'success': True,
        'count': len(packets),
        'packets': packets
    })


@app.route('/api/packets/<int:packet_id>', methods=['GET'])
def get_packet_detail(packet_id):
    """Retorna los detalles de un paquete específico"""
    packet = packet_manager.get_by_id(packet_id)
    if not packet:
        return jsonify({'error': 'Paquete no encontrado'}), 404
    
    return jsonify({
        'success': True,
        'packet': packet
    })


@app.route('/health')
def health():
    """Health check para Docker"""
    return jsonify({'status': 'ok', 'packets': len(packet_manager.packets)})


@app.route('/api/capture', methods=['POST'])
def capture_from_backend():
    """Recibe paquetes capturados por el middleware del backend FastAPI.
    Este es el endpoint real – no hay simulación."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'No JSON data'}), 400

    method   = data.get('method', 'GET')
    endpoint = data.get('endpoint', '/')

    # ── REQUEST (cuerpo enviado por el frontend) ──────────────────────────
    req_body_raw = data.get('request_body', '')
    if req_body_raw and req_body_raw.strip() and method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        try:
            req_payload = json.loads(req_body_raw)
        except Exception:
            req_payload = req_body_raw

        if req_payload:  # solo registrar si hay algo
            packet_manager.add_packet(
                method=method,
                endpoint=endpoint,
                direction='REQUEST → Backend',
                data=req_payload,
                headers=data.get('request_headers', {}),
                status_code=None,
                source='Frontend',
                destination='Backend',
            )

    # ── RESPONSE (cuerpo que el backend devuelve al frontend) ─────────────
    resp_body_raw = data.get('response_body', '')
    if resp_body_raw and resp_body_raw.strip():
        try:
            resp_payload = json.loads(resp_body_raw)
        except Exception:
            resp_payload = resp_body_raw

        if resp_payload:
            packet_manager.add_packet(
                method=method,
                endpoint=endpoint,
                direction='Backend → Frontend',
                data=resp_payload,
                headers=data.get('response_headers', {}),
                status_code=data.get('status_code'),
                source='Backend',
                destination='Frontend',
            )

    return jsonify({'success': True})


@app.route('/api/packets/clear', methods=['POST'])
def clear_packets():
    """Limpia todos los paquetes capturados"""
    packet_manager.clear()
    return jsonify({
        'success': True,
        'message': 'Todos los paquetes han sido eliminados'
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Retorna estadísticas de los paquetes"""
    return jsonify(packet_manager.get_stats())


@app.route('/api/stream', methods=['GET'])
def stream_packets():
    """Server-Sent Events: Streaming de nuevos paquetes en tiempo real.
    Usa Last-Event-ID para reconexión sin reenviar paquetes ya vistos."""
    # Leer header ANTES del generador — el contexto de request se cierra al salir de la vista
    try:
        initial_last_id = int(request.headers.get('Last-Event-ID', 0))
    except (ValueError, TypeError):
        initial_last_id = 0

    def generate():
        last_id = initial_last_id
        while True:
            packets = packet_manager.get_all()
            for packet in packets:
                if packet['id'] > last_id:
                    yield f"id: {packet['id']}\ndata: {json.dumps(packet, ensure_ascii=False)}\n\n"
                    last_id = packet['id']
            time.sleep(0.5)

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )



# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(error):
    """Manejo de rutas no encontradas"""
    return jsonify({'error': 'No encontrado'}), 404


@app.errorhandler(500)
def server_error(error):
    """Manejo de errores del servidor"""
    logger.error(f"Error del servidor: {error}")
    return jsonify({'error': 'Error interno del servidor'}), 500


# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    logger.info("🚀 Sniffer v3 - Dashboard mejorado iniciando...")
    logger.info("📊 Dirección: http://localhost:5000")
    logger.info("📡 Stream SSE disponible en: http://localhost:5000/api/stream")
    logger.info("📝 Prueba en: http://localhost:5000/api/test-capture (POST)")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True,
        use_reloader=False
    )
