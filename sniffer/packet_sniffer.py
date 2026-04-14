#!/usr/bin/env python3
"""
Raw Packet Sniffer MEJORADO - Captura paquetes HTTP/HTTPS en tiempo real
Guarda en PostgreSQL para visualización en dashboard
Con análisis avanzado de payloads y detección de compresión
"""

import threading
import json
import logging
import psycopg2
from scapy.all import sniff, IP, TCP, Raw
import re
from datetime import datetime
import os
import time
import gzip
import zlib

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv('SNIFFER_DB_URL', 'postgresql://postgres:password@db:5432/learnwithgaray')

# Importar decoders avanzados
try:
    from decoders import AdvancedDecoder, PayloadDecryptor
    HAS_DECODERS = True
except ImportError:
    HAS_DECODERS = False
    logger.warning("⚠️ Decoders module not found - usando métodos básicos")

class PacketSniffer:
    """Captura paquetes HTTP/HTTPS del tráfico de red con análisis avanzado"""
    
    def __init__(self):
        self.running = False
        self.seen_packets = {}  # Para evitar duplicados
        self.packet_count = 0
        self.decompressed_count = 0
    
    def get_db_connection(self):
        """Obtener conexión a BD"""
        try:
            conn = psycopg2.connect(DATABASE_URL)
            return conn
        except Exception as e:
            logger.error(f"❌ DB Error: {e}")
            return None
    
    def try_decompress(self, payload: bytes) -> tuple:
        """Intentar descomprimir payload (Gzip, Deflate, Brotli)"""
        compressions_tried = []
        
        # Detectar Gzip
        if payload.startswith(b'\x1f\x8b'):
            try:
                decompressed = gzip.decompress(payload)
                compressions_tried.append('GZIP')
                return decompressed, 'GZIP'
            except Exception as e:
                logger.debug(f"Gzip decompression failed: {e}")
        
        # Detectar Deflate (ZLib)
        if payload.startswith(b'\x78'):
            try:
                decompressed = zlib.decompress(payload, -zlib.MAX_WBITS)
                compressions_tried.append('DEFLATE')
                return decompressed, 'DEFLATE'
            except Exception:
                try:
                    decompressed = zlib.decompress(payload)
                    compressions_tried.append('DEFLATE')
                    return decompressed, 'DEFLATE'
                except Exception as e:
                    logger.debug(f"Deflate decompression failed: {e}")
        
        # Intentar Brotli si está disponible
        try:
            import brotli
            if payload.startswith(b'\xce\xb2\xcf\x81'):
                try:
                    decompressed = brotli.decompress(payload)
                    compressions_tried.append('BROTLI')
                    return decompressed, 'BROTLI'
                except Exception as e:
                    logger.debug(f"Brotli decompression failed: {e}")
        except ImportError:
            pass
        
        return payload, None
    
    def parse_http(self, payload):
        """Parse HTTP request/response - Mejorado con análisis de compresión"""
        try:
            # Intentar descomprimir primero
            decompressed_payload, compression_type = self.try_decompress(payload)
            
            # Decodificar a string
            data = decompressed_payload.decode('utf-8', errors='ignore')
            lines = data.split('\r\n')
            
            if not lines:
                return None
            
            first_line = lines[0]
            
            # Detectar si es request o response
            is_response = first_line.startswith('HTTP/')
            is_request = not is_response and any(first_line.startswith(m) for m in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
            
            if not (is_request or is_response):
                return None
            
            result = {
                'is_response': is_response,
                'is_request': is_request,
                'raw_line': first_line,
                'compression': compression_type,
                'headers': {},
                'headers_display': {},
                'size_original': len(payload),
                'size_decompressed': len(decompressed_payload) if compression_type else None,
            }
            
            # Parse first line
            if is_request:
                parts = first_line.split(' ')
                if len(parts) >= 3:
                    result['method'] = parts[0]
                    result['path'] = parts[1]
                    result['version'] = parts[2]
            elif is_response:
                parts = first_line.split(' ')
                if len(parts) >= 3:
                    result['version'] = parts[0]
                    result['status'] = int(parts[1])
                    result['reason'] = ' '.join(parts[2:])
            
            # Parse headers - Capturar TODOS los headers
            body_start = None
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, val = line.split(':', 1)
                    key_clean = key.strip()
                    val_clean = val.strip()
                    result['headers'][key_clean] = val_clean
                    # Mostrar headers importantes
                    if key_clean.lower() in ['user-agent', 'authorization', 'content-type', 'content-encoding', 'referer', 'cookie', 'accept-encoding', 'transfer-encoding', 'x-forwarded-for']:
                        result['headers_display'][key_clean] = val_clean[:100]
            
            # Parse body (JSON si es posible)
            if body_start and body_start < len(lines):
                body_text = '\r\n'.join(lines[body_start:])
                if body_text.strip():
                    # Intentar parsear como JSON
                    try:
                        result['body'] = json.loads(body_text)
                        result['body_type'] = 'JSON'
                    except:
                        # Intentar decodificar si está en Base64 o URL encoding
                        if HAS_DECODERS:
                            try:
                                # Extraer tokens Base64
                                b64_tokens = AdvancedDecoder.extract_base64_tokens(body_text)
                                if b64_tokens:
                                    decoded_tokens = {}
                                    for token in b64_tokens[:3]:  # Primeros 3 tokens
                                        success, decoded = AdvancedDecoder.decode_base64(token)
                                        if success:
                                            decoded_tokens[token[:20] + '...'] = decoded[:100]
                                    if decoded_tokens:
                                        result['decoded_tokens'] = decoded_tokens
                            except:
                                pass
                        
                        # Guardar primeros 500 caracteres
                        result['body'] = body_text[:500]
                        result['body_type'] = 'TEXT'
                        if len(body_text) > 500:
                            result['body_truncated'] = True
            
            # Análisis de seguridad rápido
            if HAS_DECODERS:
                try:
                    analysis = AdvancedDecoder.analyze_payload_advanced(data[:1000])
                    result['payload_analysis'] = analysis
                except:
                    pass
            
            return result
        except Exception as e:
            logger.debug(f"Parse error: {e}")
            return None
    
    def save_to_db(self, method, endpoint, status_code, req_body, resp_body, 
                   req_headers, resp_headers, is_encrypted, client_ip, user_agent=None, 
                   compression=None, payload_analysis=None):
        """Guardar tráfico en BD - Ahora con análisis avanzado"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return False
            
            cur = conn.cursor()
            
            # Extraer user_agent si no se pasa explícitamente
            if not user_agent and req_headers:
                user_agent = req_headers.get('User-Agent', 'Unknown')
            
            # Preparar campo de análisis
            analysis_json = json.dumps(payload_analysis) if payload_analysis else '{}'
            
            cur.execute("""
                INSERT INTO traffic_logs 
                (method, endpoint, status_code, request_body, response_body, 
                 request_headers, response_headers, execution_time_ms, 
                 is_encrypted, encryption_type, vulnerabilities, client_ip, user_agent)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                method or 'UNKNOWN',
                endpoint or '/',
                status_code or 200,
                json.dumps(req_body) if req_body else None,
                json.dumps(resp_body) if resp_body else None,
                json.dumps(req_headers) if req_headers else '{}',
                json.dumps(resp_headers) if resp_headers else '{}',
                1.0,  # execution_time_ms
                is_encrypted,
                f'HTTPS_{compression}' if compression else ('HTTPS' if is_encrypted else 'HTTP'),
                '[]',  # vulnerabilities
                client_ip,
                user_agent
            ))
            
            conn.commit()
            cur.close()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"❌ Save error: {e}")
            return False
    
    def packet_callback(self, packet):
        """Procesar cada paquete capturado"""
        try:
            # Verificar que sea TCP con payload
            if not (IP in packet and TCP in packet and Raw in packet):
                return
            
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            # Filtrar por puertos de aplicación
            app_ports = {3000, 8000, 5000, 80, 443}
            if dport not in app_ports and sport not in app_ports:
                return
            
            payload = bytes(packet[Raw].load)
            
            # Solo procesar si contiene HTTP
            if b'HTTP' not in payload:
                return
            
            # Evitar procesar el mismo paquete dos veces
            packet_key = f"{ip_src}:{sport}-{ip_dst}:{dport}:{hash(payload)}"
            if packet_key in self.seen_packets:
                if time.time() - self.seen_packets[packet_key] < 1:
                    return
            
            self.seen_packets[packet_key] = time.time()
            self.packet_count += 1
            
            # Limpiar cache antiguo
            if len(self.seen_packets) > 1000:
                cutoff = time.time() - 60
                self.seen_packets = {k: v for k, v in self.seen_packets.items() if v > cutoff}
            
            # Parsear HTTP
            http_info = self.parse_http(payload)
            if not http_info:
                return
            
            # Registrar descompresiones
            if http_info.get('compression'):
                self.decompressed_count += 1
                logger.info(f"📦 {http_info['compression']} decompressed: {http_info['size_original']} -> {http_info['size_decompressed']} bytes")
            
            # Determinar si es request o response
            is_request = http_info.get('is_request', False)
            is_response = http_info.get('is_response', False)
            is_encrypted = dport == 443 or sport == 443
            
            # Extraer datos
            method = http_info.get('method', 'UNKNOWN')
            endpoint = http_info.get('path', '/')
            status = http_info.get('status', 200)
            headers = http_info.get('headers', {})
            body = http_info.get('body')
            compression = http_info.get('compression')
            analysis = http_info.get('payload_analysis')
            
            # Guardar en BD
            if is_request:
                self.save_to_db(
                    method=method,
                    endpoint=endpoint,
                    status_code=status,
                    req_body=body,
                    resp_body=None,
                    req_headers=headers,
                    resp_headers=None,
                    is_encrypted=is_encrypted,
                    client_ip=ip_src,
                    compression=compression,
                    payload_analysis=analysis
                )
                logger.info(f"📤 {method} {endpoint} ← {ip_src}:{sport} {f'({compression})' if compression else ''}")
            
            elif is_response:
                self.save_to_db(
                    method='RESPONSE',
                    endpoint=endpoint,
                    status_code=status,
                    req_body=None,
                    resp_body=body,
                    req_headers=None,
                    resp_headers=headers,
                    is_encrypted=is_encrypted,
                    client_ip=ip_src,
                    compression=compression,
                    payload_analysis=analysis
                )
                logger.info(f"📥 HTTP {status} → {ip_dst}:{dport} {f'({compression})' if compression else ''}")
        
        except Exception as e:
            logger.debug(f"Packet error: {e}")
    
    def start_sniffing(self):
        """Iniciar captura de paquetes"""
        self.running = True
        logger.info("🔍 Sniffer MEJORADO iniciado: escuchando en eth0...")
        logger.info(f"📡 Portos monitoreados: 3000, 8000, 5000, 80, 443")
        logger.info(f"🔧 Decoders disponibles: {'SÍ' if HAS_DECODERS else 'NO'}")
        try:
            sniff(
                iface='eth0',
                prn=self.packet_callback,
                store=False,
                filter='tcp port 3000 or tcp port 8000 or tcp port 5000 or tcp port 80 or tcp port 443',
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            logger.error("❌ Necesita NET_ADMIN capability (ejecutar con sudo)")
        except Exception as e:
            logger.error(f"❌ Sniff error: {e}")
    
    def start(self):
        """Iniciar sniffer en thread background"""
        thread = threading.Thread(target=self.start_sniffing, daemon=True)
        thread.start()
        logger.info("✅ Packet Sniffer MEJORADO en background")


# Instancia global
sniffer = PacketSniffer()

def start_packet_sniffer():
    """Función para iniciar desde app.py"""
    sniffer.start()


if __name__ == '__main__':
    start_packet_sniffer()
    try:
        while True:
            time.sleep(1)
            if sniffer.packet_count % 100 == 0 and sniffer.packet_count > 0:
                logger.info(f"📊 Paquetes procesados: {sniffer.packet_count} | Descomprimidos: {sniffer.decompressed_count}")
    except KeyboardInterrupt:
        logger.info("Sniffer detenido")
        sniffer.running = False

    
    def save_to_db(self, method, endpoint, status_code, req_body, resp_body, 
                   req_headers, resp_headers, is_encrypted, client_ip, user_agent=None):
        """Guardar tráfico en BD - Ahora con User-Agent y más detalles"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return False
            
            cur = conn.cursor()
            
            # Extraer user_agent si no se pasa explícitamente
            if not user_agent and req_headers:
                user_agent = req_headers.get('User-Agent', 'Unknown')
            
            cur.execute("""
                INSERT INTO traffic_logs 
                (method, endpoint, status_code, request_body, response_body, 
                 request_headers, response_headers, execution_time_ms, 
                 is_encrypted, encryption_type, vulnerabilities, client_ip, user_agent)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                method or 'UNKNOWN',
                endpoint or '/',
                status_code or 200,
                json.dumps(req_body) if req_body else None,
                json.dumps(resp_body) if resp_body else None,
                json.dumps(req_headers) if req_headers else '{}',
                json.dumps(resp_headers) if resp_headers else '{}',
                1.0,  # execution_time_ms
                is_encrypted,
                'HTTPS' if is_encrypted else 'HTTP',
                '[]',  # vulnerabilities (JSON array)
                client_ip,
                user_agent
            ))
            
            conn.commit()
            cur.close()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"❌ Save error: {e}")
            return False
    
    def packet_callback(self, packet):
        """Procesar cada paquete capturado"""
        try:
            # Verificar que sea TCP con payload
            if not (IP in packet and TCP in packet and Raw in packet):
                return
            
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            # Filtrar por puertos de aplicación
            app_ports = {3000, 8000, 5000, 80, 443}
            if dport not in app_ports and sport not in app_ports:
                return
            
            payload = bytes(packet[Raw].load)
            
            # Solo procesar si contiene HTTP
            if b'HTTP' not in payload:
                return
            
            # Evitar procesar el mismo paquete dos veces
            packet_key = f"{ip_src}:{sport}-{ip_dst}:{dport}:{hash(payload)}"
            if packet_key in self.seen_packets:
                if time.time() - self.seen_packets[packet_key] < 1:  # Evitar duplicados en 1s
                    return
            
            self.seen_packets[packet_key] = time.time()
            
            # Limpiar cache antiguo
            if len(self.seen_packets) > 1000:
                cutoff = time.time() - 60
                self.seen_packets = {k: v for k, v in self.seen_packets.items() if v > cutoff}
            
            # Parsear HTTP
            http_info = self.parse_http(payload)
            if not http_info:
                return
            
            # Determinar si es request o response
            is_request = http_info.get('is_request', False)
            is_response = http_info.get('is_response', False)
            is_encrypted = dport == 443 or sport == 443
            
            # Extraer datos
            method = http_info.get('method', 'UNKNOWN')
            endpoint = http_info.get('path', '/')
            status = http_info.get('status', 200)
            headers = http_info.get('headers', {})
            body = http_info.get('body')
            
            # Guardar en BD
            if is_request:
                self.save_to_db(
                    method=method,
                    endpoint=endpoint,
                    status_code=status,
                    req_body=body,
                    resp_body=None,
                    req_headers=headers,
                    resp_headers=None,
                    is_encrypted=is_encrypted,
                    client_ip=ip_src
                )
                logger.info(f"📤 {method} {endpoint} ← {ip_src}:{sport}")
            
            elif is_response:
                self.save_to_db(
                    method='RESPONSE',
                    endpoint=endpoint,
                    status_code=status,
                    req_body=None,
                    resp_body=body,
                    req_headers=None,
                    resp_headers=headers,
                    is_encrypted=is_encrypted,
                    client_ip=ip_src
                )
                logger.info(f"📥 HTTP {status} → {ip_dst}:{dport}")
        
        except Exception as e:
            logger.debug(f"Packet error: {e}")
    
    def start_sniffing(self):
        """Iniciar captura de paquetes"""
        self.running = True
        logger.info("🔍 Sniffer iniciado: escuchando en eth0...")
        try:
            sniff(
                iface='eth0',
                prn=self.packet_callback,
                store=False,
                filter='tcp port 3000 or tcp port 8000 or tcp port 5000 or tcp port 80 or tcp port 443',
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            logger.error("❌ Necesita NET_ADMIN capability")
        except Exception as e:
            logger.error(f"❌ Sniff error: {e}")
    
    def start(self):
        """Iniciar sniffer en thread background"""
        thread = threading.Thread(target=self.start_sniffing, daemon=True)
        thread.start()
        logger.info("✅ Packet Sniffer en background")


# Instancia global
sniffer = PacketSniffer()

def start_packet_sniffer():
    """Función para iniciar desde app.py"""
    sniffer.start()


if __name__ == '__main__':
    start_packet_sniffer()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Sniffer detenido")
        sniffer.running = False
