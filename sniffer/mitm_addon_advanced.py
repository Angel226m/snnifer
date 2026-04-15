#!/usr/bin/env python3
"""
Advanced MITM Proxy Addon - Wireshark-like packet capture
Para usarse con mitmproxy: mitmproxy -s mitm_addon_advanced.py
Captura y analiza TODA la comunicación HTTP/HTTPS con detalles completos
"""

from mitmproxy import http, ctx, connection
from mitmproxy.tools.dump import DumpMaster
import logging
import json
import psycopg2
from datetime import datetime
import time
import re
import hashlib
from typing import Optional, Dict, Any
import gzip
import zlib

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DATABASE_URL = 'postgresql://postgres:password@db:5432/learnwithgaray'

# ============================================================
# DECOMPRESSOR - Decomprimir payloads
# ============================================================
class PayloadDecompressor:
    @staticmethod
    def decompress(data: bytes) -> tuple:
        """Intentar descomprimir en múltiples formatos"""
        if not data:
            return data, None
        
        # Gzip
        if data.startswith(b'\x1f\x8b'):
            try:
                return gzip.decompress(data), 'gzip'
            except:
                pass
        
        # Deflate
        if data.startswith(b'\x78'):
            try:
                return zlib.decompress(data), 'deflate'
            except:
                pass
        
        # Brotli
        try:
            import brotli
            return brotli.decompress(data), 'brotli'
        except:
            pass
        
        return data, None


# ============================================================
# ADVANCED MITM ADDON
# ============================================================
class AdvancedMitmAddon:
    """Addon avanzado para mitmproxy con análisis tipo Wireshark"""
    
    def __init__(self):
        self.flow_counter = 0
        self.db_connection = None
        self.stats = {
            'requests': 0,
            'responses': 0,
            'errors': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
        }
        self.connect_to_db()
    
    def connect_to_db(self):
        """Conectar a base de datos"""
        try:
            self.db_connection = psycopg2.connect(DATABASE_URL)
            logger.info("✅ Connected to PostgreSQL database")
        except Exception as e:
            logger.error(f"❌ DB Connection failed: {e}")
    
    def get_db_connection(self):
        """Obtener o reconectar a BD"""
        try:
            if self.db_connection is None:
                self.connect_to_db()
            # Test connection
            cur = self.db_connection.cursor()
            cur.execute("SELECT 1")
            cur.close()
            return self.db_connection
        except:
            self.connect_to_db()
            return self.db_connection
    
    def extract_body_data(self, flow: http.HTTPFlow) -> Dict[str, Any]:
        """Extraer información completa del body"""
        request_body = None
        response_body = None
        request_compression = None
        response_compression = None
        
        try:
            # Request body
            if flow.request.content:
                request_compression_header = flow.request.headers.get('content-encoding')
                request_body_data = flow.request.content
                
                if request_compression_header:
                    decompressed, compression_type = PayloadDecompressor.decompress(request_body_data)
                    if compression_type:
                        request_compression = compression_type
                        request_body_data = decompressed
                
                try:
                    request_body = json.loads(request_body_data.decode('utf-8'))
                except:
                    request_body = request_body_data.decode('utf-8', errors='ignore')[:1000]
        except Exception as e:
            logger.debug(f"Request body extraction error: {e}")
        
        try:
            # Response body
            if flow.response and flow.response.content:
                response_compression_header = flow.response.headers.get('content-encoding')
                response_body_data = flow.response.content
                
                if response_compression_header:
                    decompressed, compression_type = PayloadDecompressor.decompress(response_body_data)
                    if compression_type:
                        response_compression = compression_type
                        response_body_data = decompressed
                
                try:
                    response_body = json.loads(response_body_data.decode('utf-8'))
                except:
                    response_body = response_body_data.decode('utf-8', errors='ignore')[:1000]
        except Exception as e:
            logger.debug(f"Response body extraction error: {e}")
        
        return {
            'request_body': request_body,
            'response_body': response_body,
            'request_compression': request_compression,
            'response_compression': response_compression,
        }
    
    def extract_headers_info(self, flow: http.HTTPFlow) -> Dict[str, Any]:
        """Extraer información de headers importantes"""
        important_headers = [
            'Authorization', 'Content-Type', 'Content-Length', 'User-Agent',
            'Accept-Encoding', 'Content-Encoding', 'Cache-Control', 'ETag',
            'X-Forwarded-For', 'X-Real-IP', 'X-CSRF-Token', 'Cookie',
            'Set-Cookie', 'Referer', 'Origin', 'Access-Control-Allow-Origin',
            'Host', 'Connection', 'Keep-Alive', 'Transfer-Encoding'
        ]
        
        request_headers = {}
        response_headers = {}
        
        # Request headers
        for header in important_headers:
            value = flow.request.headers.get(header)
            if value:
                # Truncar si es muy largo (ej: Authorization)
                if len(value) > 100 and header in ['Authorization', 'Cookie']:
                    value = value[:100] + '...'
                request_headers[header] = value
        
        # Response headers
        if flow.response:
            for header in important_headers:
                value = flow.response.headers.get(header)
                if value:
                    if len(value) > 100:
                        value = value[:100] + '...'
                    response_headers[header] = value
        
        return {
            'request_headers': request_headers,
            'response_headers': response_headers,
        }
    
    def save_to_database(self, flow: http.HTTPFlow):
        """Guardar captura completa a base de datos"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return
            
            cur = conn.cursor()
            
            # Extraer datos
            body_data = self.extract_body_data(flow)
            headers_data = self.extract_headers_info(flow)
            
            # Información básica
            timestamp = datetime.now()
            method = flow.request.method
            url = flow.request.pretty_url
            path = flow.request.path
            host = flow.request.host
            port = flow.request.port
            
            status_code = flow.response.status_code if flow.response else 0
            reason = flow.response.reason if flow.response else 'No Response'
            
            # Tamaños
            request_size = len(flow.request.content) if flow.request.content else 0
            response_size = len(flow.response.content) if flow.response and flow.response.content else 0
            
            # Timing
            execution_time = 0
            if flow.timeline.first_request_byte and flow.timeline.first_response_byte:
                execution_time = (flow.timeline.first_response_byte - flow.timeline.first_request_byte) * 1000
            
            # TLS info
            is_encrypted = flow.request.scheme == 'https'
            tls_version = 'N/A'
            cipher_suite = 'N/A'
            if flow.server_conn and flow.server_conn.tls_established:
                tls_version = getattr(flow.server_conn, 'tls_version', 'UNKNOWN')
                cipher_suite = getattr(flow.server_conn, 'cipher_name', 'UNKNOWN')
            
            # Client IP
            client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else 'UNKNOWN'
            
            # Guardar en tabla de traffic_logs (compatible con app.py)
            cur.execute("""
                INSERT INTO traffic_logs 
                (timestamp, method, endpoint, status_code, request_body, response_body,
                 request_headers, response_headers, execution_time_ms, is_encrypted,
                 encryption_type, client_ip, user_agent, vulnerabilities)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                timestamp,
                method,
                path,
                status_code,
                json.dumps(body_data['request_body']),
                json.dumps(body_data['response_body']),
                json.dumps(headers_data['request_headers']),
                json.dumps(headers_data['response_headers']),
                execution_time,
                is_encrypted,
                f"TLS_{tls_version}_{cipher_suite}" if is_encrypted else "HTTP",
                client_ip,
                headers_data['request_headers'].get('User-Agent', 'Unknown'),
                json.dumps([])  # vulnerabilities
            ))
            
            # Insertar en tabla http_captures si existe
            try:
                cur.execute("""
                    INSERT INTO http_captures
                    (timestamp, method, path, status_code, src_ip, dst_ip, headers, body_preview, 
                     body_size, compression, is_encrypted, http_info)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    timestamp,
                    method,
                    path,
                    status_code,
                    client_ip,
                    host,
                    json.dumps({**headers_data['request_headers'], **headers_data['response_headers']}),
                    str(body_data['response_body'])[:500] if body_data['response_body'] else None,
                    response_size,
                    body_data['response_compression'],
                    is_encrypted,
                    json.dumps({
                        'url': url,
                        'tls_version': tls_version,
                        'cipher': cipher_suite,
                        'request_size': request_size,
                        'response_size': response_size,
                        'timing_ms': execution_time,
                    })
                ))
            except:
                pass  # Tabla opcional
            
            conn.commit()
            cur.close()
            
        except Exception as e:
            logger.error(f"❌ Database save error: {e}")
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Capturar request"""
        self.flow_counter += 1
        
        method = flow.request.method
        path = flow.request.path
        host = flow.request.host
        port = flow.request.port
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else 'UNKNOWN'
        
        is_https = flow.request.scheme == 'https'
        protocol_icon = "🔒" if is_https else "🌐"
        
        logger.info(f"{protocol_icon} REQUEST #{self.flow_counter}: {method} {path} from {client_ip}")
        logger.debug(f"   Host: {host}:{port} | User-Agent: {flow.request.headers.get('User-Agent', 'N/A')[:50]}")
        
        self.stats['requests'] += 1
        if flow.request.content:
            self.stats['bytes_sent'] += len(flow.request.content)
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Capturar response"""
        method = flow.request.method
        path = flow.request.path
        status = flow.response.status_code
        reason = flow.response.reason
        response_size = len(flow.response.content) if flow.response.content else 0
        
        # Color por status code
        if 200 <= status < 300:
            icon = "✅"
        elif 300 <= status < 400:
            icon = "📍"
        elif 400 <= status < 500:
            icon = "⚠️"
        else:
            icon = "❌"
        
        logger.info(f"{icon} RESPONSE: {method} {path} → {status} {reason} ({response_size} bytes)")
        
        self.stats['responses'] += 1
        self.stats['bytes_received'] += response_size
        
        # Guardar en base de datos
        self.save_to_database(flow)
    
    def error(self, flow: http.HTTPFlow) -> None:
        """Capturar errores"""
        logger.error(f"❌ ERROR: {flow.request.method} {flow.request.path}")
        self.stats['errors'] += 1
    
    def done(self):
        """Llamado cuando termina mitmproxy"""
        logger.info("\n" + "="*80)
        logger.info("MITM CAPTURE STATISTICS".center(80))
        logger.info("="*80)
        logger.info(f"Total Requests:  {self.stats['requests']}")
        logger.info(f"Total Responses: {self.stats['responses']}")
        logger.info(f"Errors:          {self.stats['errors']}")
        logger.info(f"Bytes Sent:      {self.stats['bytes_sent']:,}")
        logger.info(f"Bytes Received:  {self.stats['bytes_received']:,}")
        logger.info("="*80)


# Crear instancia del addon
addons = [AdvancedMitmAddon()]
