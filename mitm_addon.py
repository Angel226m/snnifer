#!/usr/bin/env python3
"""
mitmproxy Addon - Network Sniffer Pro
Captura, desencripta y modifica tráfico en tiempo real
"""

from mitmproxy import http, ctx
import requests
import json
import re
import base64
import urllib.parse
from datetime import datetime

SNIFFER_URL = "http://localhost:5000"
DEBUG = True

class LiveSnifferAddon:
    """Addon para mitmproxy que captura y modifica tráfico en tránsito"""
    
    def __init__(self):
        self.request_counter = 0
        self.modified_counter = 0
        self.decryption_cache = {}
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Intercepta request antes de ser enviado"""
        self.request_counter += 1
        
        try:
            # Extraer información
            method = flow.request.method
            path = flow.request.path
            headers = dict(flow.request.headers)
            
            # Parse body
            req_body = None
            try:
                if flow.request.content:
                    req_body = json.loads(flow.request.text)
            except:
                req_body = flow.request.text[:2000] if flow.request.text else None
            
            # Patrón: Si contiene "/login" y hay "password", marcar para análisis
            if "/login" in path and req_body and isinstance(req_body, dict):
                if "password" in req_body:
                    # Aquí puedes interceptar y modificar
                    # Por ejemplo, cambiar password para testing:
                    # req_body["password"] = "INTERCEPTED_" + req_body["password"]
                    # flow.request.text = json.dumps(req_body)
                    pass
            
            # Enviar a dashboard para logging
            self._send_to_dashboard({
                "direction": "request",
                "method": method,
                "path": path,
                "headers": headers,
                "body": req_body,
                "timestamp": datetime.utcnow().isoformat(),
                "client_ip": flow.client_conn.peername[0] if flow.client_conn else "unknown",
                "scheme": flow.request.scheme
            })
            
        except Exception as e:
            if DEBUG:
                ctx.log.error(f"Request hook error: {e}")
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Intercepta response del backend"""
        try:
            method = flow.request.method
            path = flow.request.path
            status_code = flow.response.status_code
            
            req_headers = dict(flow.request.headers)
            resp_headers = dict(flow.response.headers)
            
            # Parse request body
            req_body = None
            try:
                if flow.request.content:
                    req_body = json.loads(flow.request.text)
            except:
                req_body = flow.request.text[:2000] if flow.request.text else None
            
            # Parse response body
            resp_body = None
            try:
                if flow.response.content:
                    resp_body = json.loads(flow.response.text)
            except:
                resp_body = flow.response.text[:5000] if flow.response.text else None
            
            # Análisis de seguridad
            vulns = self._analyze_security(req_body, resp_body, req_headers)
            sensitive = self._extract_sensitive(str(req_body) + str(resp_body))
            
            # Desencriptación intenta
            decodings = self._try_decodings(str(req_body)[:1000])
            
            # Enviar a dashboard
            self._send_to_dashboard({
                "direction": "response",
                "method": method,
                "path": path,
                "status_code": status_code,
                "request_body": req_body,
                "response_body": resp_body,
                "request_headers": req_headers,
                "response_headers": resp_headers,
                "vulnerabilities": vulns,
                "sensitive_data": sensitive,
                "decodings": decodings,
                "timestamp": datetime.utcnow().isoformat(),
                "client_ip": flow.client_conn.peername[0] if flow.client_conn else "unknown",
                "scheme": flow.request.scheme,
                "is_https": flow.request.scheme == "https"
            })
            
        except Exception as e:
            if DEBUG:
                ctx.log.error(f"Response hook error: {e}")
    
    def _send_to_dashboard(self, data: dict) -> None:
        """Envía datos capturados al dashboard"""
        try:
            requests.post(
                f"{SNIFFER_URL}/api/stream-injection",
                json=data,
                timeout=2
            )
        except:
            pass  # Silent fail
    
    def _analyze_security(self, req_body, resp_body, headers) -> list:
        """Análisis de vulnerabilidades de seguridad"""
        vulns = []
        payload_str = str(req_body) + str(resp_body)
        
        # Bearer token
        auth = headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            token = auth[7:]
            if token.count('.') == 2:
                try:
                    vulns.append({
                        'type': 'JWT_DETECTED',
                        'severity': 'INFO',
                        'name': 'JWT Token encontrado'
                    })
                except:
                    pass
        
        # Plaintext password
        if 'password' in payload_str.lower():
            if not any(c in payload_str for c in ['$2b', '$2a', '$argon']):
                vulns.append({
                    'type': 'PLAINTEXT_PASSWORD',
                    'severity': 'CRITICAL',
                    'name': 'Contraseña en plaintext'
                })
        
        return vulns
    
    def _extract_sensitive(self, data: str) -> dict:
        """Extrae patrones sensibles"""
        sensitive = {}
        
        # Emails
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', data)
        if emails:
            sensitive['emails'] = list(set(emails))[:5]
        
        # JWT
        jwts = re.findall(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', data)
        if jwts:
            sensitive['jwt_tokens'] = list(set(jwts))[:3]
        
        # API Keys pattern
        api_keys = re.findall(r'["\']?(?:api_key|apikey|secret|token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', data, re.IGNORECASE)
        if api_keys:
            sensitive['api_keys'] = list(set(api_keys))[:5]
        
        # URLs
        urls = re.findall(r'https?://[^\s"\'<>]+', data)
        if urls:
            sensitive['urls'] = list(set(urls))[:5]
        
        return sensitive
    
    def _try_decodings(self, data: str, max_depth: int = 3) -> list:
        """Intenta descodificar datos"""
        results = []
        
        if not data or len(data) == 0:
            return results
        
        # Base64
        try:
            decoded = base64.b64decode(data, validate=True).decode('utf-8', errors='ignore')
            if decoded and decoded != data and len(decoded) > 5:
                results.append({
                    'type': 'base64',
                    'result': decoded[:500]
                })
        except:
            pass
        
        # URL encoding
        try:
            decoded = urllib.parse.unquote(data)
            if decoded != data and decoded.strip():
                results.append({
                    'type': 'url_encoded',
                    'result': decoded[:500]
                })
        except:
            pass
        
        # Hex
        try:
            if all(c in '0123456789abcdefABCDEF' for c in data):
                decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
                if decoded and decoded != data:
                    results.append({
                        'type': 'hex',
                        'result': decoded[:500]
                    })
        except:
            pass
        
        return results


addons = [LiveSnifferAddon()]
