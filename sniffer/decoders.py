#!/usr/bin/env python3
"""
Advanced Decoders & Analyzers - Máximo nivel de desciframiento
Soporta: Gzip, Brotli, Deflate, Base64, URL, Hex, JSON, Protobuf patterns, etc.
"""

import gzip
import zlib
import base64
import json
import logging
import re
from urllib.parse import unquote, quote
from typing import Dict, Any, Tuple, List

try:
    import brotli
    HAS_BROTLI = True
except ImportError:
    HAS_BROTLI = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdvancedDecoder:
    """Suite completa de decodificadores"""
    
    # ==================== COMPRESSION DECODERS ====================
    
    @staticmethod
    def decode_gzip(data: bytes) -> Tuple[bool, str]:
        """Descomprimir Gzip"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8', errors='ignore')
            decompressed = gzip.decompress(data)
            return True, decompressed.decode('utf-8', errors='ignore')
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def decode_brotli(data: bytes) -> Tuple[bool, str]:
        """Descomprimir Brotli"""
        if not HAS_BROTLI:
            return False, "Brotli not installed (pip install brotli)"
        
        try:
            if isinstance(data, str):
                data = data.encode('utf-8', errors='ignore')
            decompressed = brotli.decompress(data)
            return True, decompressed.decode('utf-8', errors='ignore')
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def decode_deflate(data: bytes) -> Tuple[bool, str]:
        """Descomprimir Deflate (ZLib)"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8', errors='ignore')
            decompressed = zlib.decompress(data, -zlib.MAX_WBITS)
            return True, decompressed.decode('utf-8', errors='ignore')
        except Exception:
            try:
                decompressed = zlib.decompress(data)
                return True, decompressed.decode('utf-8', errors='ignore')
            except Exception as e:
                return False, str(e)
    
    # ==================== ENCODING DECODERS ====================
    
    @staticmethod
    def decode_base64(data: str, validate: bool = False) -> Tuple[bool, str]:
        """Decodificar Base64"""
        try:
            # Agregar padding si es necesario
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            
            decoded = base64.b64decode(data, validate=validate)
            result = decoded.decode('utf-8', errors='ignore')
            return True, result
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def decode_base64_urlsafe(data: str) -> Tuple[bool, str]:
        """Decodificar Base64 URL Safe (JWT)"""
        try:
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            
            decoded = base64.urlsafe_b64decode(data)
            result = decoded.decode('utf-8', errors='ignore')
            return True, result
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def decode_url(data: str) -> Tuple[bool, str]:
        """Decodificar URL Encoding (%20 = espacio)"""
        try:
            decoded = unquote(data)
            return True, decoded
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def decode_hex(data: str) -> Tuple[bool, str]:
        """Decodificar Hex"""
        try:
            decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
            return True, decoded
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def decode_ascii_hex(data: str) -> Tuple[bool, str]:
        """Decodificar ASCII con formato hex (ej: 48 65 6c 6c 6f)"""
        try:
            hex_bytes = data.split()
            decoded = bytes([int(h, 16) for h in hex_bytes]).decode('utf-8', errors='ignore')
            return True, decoded
        except Exception as e:
            return False, str(e)
    
    # ==================== DETECTION & ANALYSIS ====================
    
    @staticmethod
    def detect_compression_type(data: bytes) -> List[str]:
        """Detectar tipo de compresión basado en magic bytes"""
        detected = []
        
        if isinstance(data, str):
            data = data.encode('utf-8', errors='ignore')
        
        if data.startswith(b'\x1f\x8b'):
            detected.append('GZIP')
        if data.startswith(b'\xce\xb2\xcf\x81'):
            detected.append('BROTLI')
        if data.startswith(b'\x78\x9c') or data.startswith(b'\x78\x01'):
            detected.append('DEFLATE')
        if data.startswith(b'\x78\xda'):
            detected.append('DEFLATE_MAX')
        if data.startswith(b'\x50\x4b'):
            detected.append('ZIP')
        
        return detected
    
    @staticmethod
    def extract_base64_tokens(text: str) -> List[str]:
        """Extraer todos los tokens Base64 del texto"""
        pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(pattern, text)
        return list(set(matches))
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extraer todos los URLs del texto"""
        url_pattern = r'https?://[^\s"]+'
        urls = re.findall(url_pattern, text)
        return list(set(urls))
    
    @staticmethod
    def extract_emails(text: str) -> List[str]:
        """Extraer emails"""
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, text)
        return list(set(emails))
    
    @staticmethod
    def extract_api_keys(text: str) -> Dict[str, List[str]]:
        """Detectar patrones de API keys y tokens"""
        patterns = {
            'AWS_KEY': r'AKIA[0-9A-Z]{16}',
            'GITHUB_TOKEN': r'ghp_[A-Za-z0-9_]{36,255}',
            'JWT': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
            'PRIVATE_KEY': r'-----BEGIN.*?PRIVATE KEY-----',
            'STRIPE_KEY': r'sk_live_[0-9a-zA-Z]{24,}',
            'SLACK_TOKEN': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'GOOGLE_API': r'AIza[0-9A-Za-z\-_]{35}',
        }
        
        found = {}
        for key_type, pattern in patterns.items():
            matches = re.findall(pattern, text, re.DOTALL)
            if matches:
                found[key_type] = list(set(matches))
        
        return found
    
    # ==================== AUTO-DECODE ====================
    
    @staticmethod
    def auto_decode(data) -> Dict[str, Any]:
        """Intentar decodificar automáticamente con todos los métodos"""
        if isinstance(data, dict):
            data_str = json.dumps(data)
            data_bytes = data_str.encode('utf-8')
        elif isinstance(data, str):
            data_str = data
            data_bytes = data.encode('utf-8')
        else:
            data_str = str(data)
            data_bytes = data_bytes if isinstance(data, bytes) else data_str.encode('utf-8')
        
        results = {
            'original': data_str[:200] if len(data_str) > 200 else data_str,
            'decodings': {},
            'detections': {},
            'extractions': {}
        }
        
        # Intentar descompresiones
        decompression_methods = [
            ('GZIP', AdvancedDecoder.decode_gzip),
            ('BROTLI', AdvancedDecoder.decode_brotli),
            ('DEFLATE', AdvancedDecoder.decode_deflate),
        ]
        
        for name, method in decompression_methods:
            success, result = method(data_bytes)
            if success and result != data_str:
                results['decodings'][name] = result[:500]
        
        # Intentar decodificaciones de encoding
        encoding_methods = [
            ('BASE64', AdvancedDecoder.decode_base64),
            ('BASE64_URLSAFE', AdvancedDecoder.decode_base64_urlsafe),
            ('URL', AdvancedDecoder.decode_url),
            ('HEX', AdvancedDecoder.decode_hex),
        ]
        
        for name, method in encoding_methods:
            success, result = method(data_str)
            if success and result != data_str and len(result) > 5:
                results['decodings'][name] = result[:500]
        
        # Detecciones
        results['detections']['compression'] = AdvancedDecoder.detect_compression_type(data_bytes)
        results['detections']['api_keys'] = AdvancedDecoder.extract_api_keys(data_str)
        results['detections']['urls'] = AdvancedDecoder.extract_urls(data_str)[:5]
        results['detections']['emails'] = AdvancedDecoder.extract_emails(data_str)[:5]
        
        return results
    
    # ==================== PAYLOAD ANALYSIS ====================
    
    @staticmethod
    def analyze_payload_advanced(payload: str) -> Dict[str, Any]:
        """Análisis completo de payload"""
        analysis = {
            'size': len(payload),
            'type': 'UNKNOWN',
            'encoding': [],
            'compression': [],
            'sensitive_data': [],
            'suspicious_patterns': [],
        }
        
        # Detectar tipo de contenido
        try:
            json.loads(payload)
            analysis['type'] = 'JSON'
        except:
            if payload.startswith('<'):
                analysis['type'] = 'HTML/XML'
            elif all(c in '0123456789abcdefABCDEF \n\r\t' for c in payload[:100]):
                analysis['type'] = 'HEX'
            elif all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n' for c in payload[:100]):
                analysis['type'] = 'BASE64'
            else:
                analysis['type'] = 'TEXT'
        
        # Detectar passwords
        if re.search(r'"password"\s*:\s*"[^"]{1,100}"', payload, re.IGNORECASE):
            analysis['sensitive_data'].append('PLAINTEXT_PASSWORD')
        
        # Detectar tokens
        if re.search(r'"token"\s*:\s*"[a-z0-9]{20,}"', payload, re.IGNORECASE):
            analysis['sensitive_data'].append('TOKEN')
        
        # Detectar credit cards
        if re.search(r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}', payload):
            analysis['sensitive_data'].append('CREDIT_CARD')
        
        # Detectar SSN/DNI
        if re.search(r'\d{3}-\d{2}-\d{4}', payload):
            analysis['sensitive_data'].append('SSN')
        
        # Patrones sospechosos
        if 'eval(' in payload or 'exec(' in payload:
            analysis['suspicious_patterns'].append('CODE_EXECUTION')
        
        if '<script' in payload.lower():
            analysis['suspicious_patterns'].append('XSS_PAYLOAD')
        
        if 'union select' in payload.lower():
            analysis['suspicious_patterns'].append('SQL_INJECTION')
        
        return analysis


class PayloadDecryptor:
    """Utilidades para intentar desencriptación de payloads"""
    
    @staticmethod
    def try_all_decodings(payload: str) -> List[Dict[str, Any]]:
        """Intentar todas las decodificaciones sucesivas"""
        results = []
        current = payload
        depth = 0
        max_depth = 5
        
        while depth < max_depth:
            depth += 1
            decoded_any = False
            
            # Intentar Base64
            success, decoded = AdvancedDecoder.decode_base64(current)
            if success and decoded != current and len(decoded) > 3:
                results.append({
                    'depth': depth,
                    'method': 'BASE64',
                    'payload': decoded[:500],
                    'full_length': len(decoded),
                })
                current = decoded
                decoded_any = True
                continue
            
            # Intentar URL
            success, decoded = AdvancedDecoder.decode_url(current)
            if success and decoded != current and '%' in current:
                results.append({
                    'depth': depth,
                    'method': 'URL',
                    'payload': decoded[:500],
                    'full_length': len(decoded),
                })
                current = decoded
                decoded_any = True
                continue
            
            # Intentar Gzip
            try:
                success, decoded = AdvancedDecoder.decode_gzip(current.encode())
                if success and decoded != current:
                    results.append({
                        'depth': depth,
                        'method': 'GZIP',
                        'payload': decoded[:500],
                        'full_length': len(decoded),
                    })
                    current = decoded
                    decoded_any = True
                    continue
            except:
                pass
            
            if not decoded_any:
                break
        
        return results


if __name__ == '__main__':
    # Test
    test_payload = base64.b64encode(b'Hello World').decode()
    print("Test payload:", test_payload)
    print("Auto decode:", AdvancedDecoder.auto_decode(test_payload))
