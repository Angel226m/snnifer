#!/usr/bin/env python3
"""
Network Capture Middleware
Intercepta y captura TODOS los paquetes entre frontend-backend
Como Wireshark integrado en la aplicación
"""

import psycopg2
import json
import logging
from datetime import datetime
from functools import wraps
from flask import request, g
import time
import base64

logger = logging.getLogger(__name__)

DATABASE_URL = 'postgresql://postgres:password@db:5432/learnwithgaray'

class PacketCaptureMiddleware:
    """Middleware para capturar paquetes automáticamente"""
    
    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Inicializar con Flask app"""
        app.before_request(self.capture_request)
        app.after_request(self.capture_response)
    
    @staticmethod
    def get_db_connection():
        try:
            return psycopg2.connect(DATABASE_URL, connect_timeout=5)
        except Exception as e:
            logger.error(f"DB connection error: {e}")
            return None
    
    def capture_request(self):
        """Capturar información del request"""
        g.packet_start_time = time.time()
        g.request_data = None
        
        # Capturar body
        if request.method in ['POST', 'PUT', 'PATCH']:
            try:
                if request.is_json:
                    g.request_data = request.get_json(silent=True)
                else:
                    g.request_data = request.get_data(as_text=True)
            except:
                pass
        
        # Guardar headers
        g.request_headers = dict(request.headers)
    
    def capture_response(self, response):
        """Capturar información de la respuesta"""
        try:
            elapsed = (time.time() - g.packet_start_time) * 1000
            
            # Determinar dirección
            user_agent = g.request_headers.get('User-Agent', '')
            if 'firefox' in user_agent.lower() or 'safari' in user_agent.lower() or 'chrome' in user_agent.lower():
                direction = 'frontend-backend'
            else:
                direction = 'backend-frontend'
            
            # Analizar respuesta
            response_data = None
            try:
                response_data = response.get_json(silent=True)
            except:
                response_data = response.get_data(as_text=True)
            
            # Preparar datos para logging
            packet_info = {
                'timestamp': datetime.now(),
                'method': request.method,
                'endpoint': request.path,
                'direction': direction,
                'status_code': response.status_code,
                'response_time_ms': elapsed,
                'client_ip': request.remote_addr,
                'user_agent': user_agent,
                'request_data': g.request_data,
                'response_data': response_data,
                'request_headers': g.request_headers,
                'response_headers': dict(response.headers),
                'is_encrypted': request.scheme == 'https'
            }
            
            # Log asíncrono a BD
            self._log_to_db_async(packet_info)
        
        except Exception as e:
            logger.error(f"Capture response error: {e}")
        
        return response
    
    @staticmethod
    def _log_to_db_async(packet_info):
        """Loguear a BD en un thread separado para no bloquear"""
        import threading
        
        def _log():
            try:
                conn = PacketCaptureMiddleware.get_db_connection()
                if not conn:
                    return
                
                cur = conn.cursor()
                
                # Análisis del payload
                from app_enhanced import RawPayloadAnalyzer
                req_analysis = RawPayloadAnalyzer.extract_all_data(packet_info['request_data'])
                resp_analysis = RawPayloadAnalyzer.extract_all_data(packet_info['response_data'])
                
                combined = {
                    'request': req_analysis,
                    'response': resp_analysis
                }
                
                risk = RawPayloadAnalyzer.get_risk_level({**req_analysis, **resp_analysis})
                
                # Vulnerabilidades
                vulns = []
                if req_analysis['passwords']:
                    vulns.append({
                        'type': 'PLAINTEXT_PASSWORD',
                        'severity': 'CRITICAL',
                        'description': 'Contraseña en TEXTO PLANO'
                    })
                
                cur.execute("""
                    INSERT INTO packet_capture
                    (timestamp, method, endpoint, status_code, direction,
                     request_data, response_data, request_headers, response_headers,
                     request_json, response_json,
                     payload_analysis, risk_level, vulnerabilities,
                     response_time_ms, client_ip, user_agent, is_encrypted)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    packet_info['timestamp'],
                    packet_info['method'],
                    packet_info['endpoint'],
                    packet_info['status_code'],
                    packet_info['direction'],
                    str(packet_info['request_data']).encode() if packet_info['request_data'] else None,
                    str(packet_info['response_data']).encode() if packet_info['response_data'] else None,
                    json.dumps(packet_info['request_headers']),
                    json.dumps(packet_info['response_headers']),
                    json.dumps(req_analysis.get('json_parsed')),
                    json.dumps(resp_analysis.get('json_parsed')),
                    json.dumps(combined),
                    risk,
                    json.dumps(vulns),
                    packet_info['response_time_ms'],
                    packet_info['client_ip'],
                    packet_info['user_agent'],
                    packet_info['is_encrypted']
                ))
                
                conn.commit()
                cur.close()
                conn.close()
            
            except Exception as e:
                logger.error(f"Async DB log error: {e}")
        
        thread = threading.Thread(target=_log, daemon=True)
        thread.start()
