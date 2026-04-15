#!/usr/bin/env python3
"""
Ejemplos prácticos de uso del Network Sniffer Pro v2
"""

import requests
import json
import base64
import urllib.parse

SNIFFER_URL = "http://localhost:5000"

# ============================================================
# 1. DECODIFICAR UN PAYLOAD
# ============================================================
def example_decode_base64():
    """Decodificar un payload Base64 capturado"""
    print("\n📦 EJEMPLO 1: Decodificar Base64")
    print("=" * 60)
    
    # Payload Base64 (ejemplo: "hello world")
    payload = "aGVsbG8gd29ybGQ="
    
    response = requests.post(
        f"{SNIFFER_URL}/api/decode/auto",
        json={"payload": payload}
    )
    
    result = response.json()
    print(f"Original: {payload}")
    print(f"Decodificado: {result['decodings'][0]['result'] if result['decodings'] else 'N/A'}")
    print(f"Capas: {result['layers']}")

# ============================================================
# 2. DECODIFICAR MÚLTIPLES CAPAS
# ============================================================
def example_decode_layers():
    """Decodificar un payload con múltiples capas de encoding"""
    print("\n🔥 EJEMPLO 2: Decodificación Recursiva (5 capas)")
    print("=" * 60)
    
    # Base64(URL(Base64(JSON)))
    json_str = '{"password":"super_secret"}'
    b64_1 = base64.b64encode(json_str.encode()).decode()
    url_enc = urllib.parse.quote(b64_1)
    b64_2 = base64.b64encode(url_enc.encode()).decode()
    
    print(f"Original: {json_str}")
    print(f"Capa 1 (Base64): {b64_1}")
    print(f"Capa 2 (URL): {url_enc}")
    print(f"Capa 3 (Base64): {b64_2}")
    
    response = requests.post(
        f"{SNIFFER_URL}/api/decode/auto",
        json={"payload": b64_2}
    )
    
    result = response.json()
    print(f"\n✓ Decodificaciones encontradas: {result['layers']}")
    for dec in result['decodings']:
        print(f"  - {dec['type']} (depth {dec['depth']}): {dec['result'][:50]}...")

# ============================================================
# 3. VER DATOS SENSIBLES CAPTURADOS
# ============================================================
def example_view_sensitive_data():
    """Ver todos los datos sensibles capturados"""
    print("\n🔓 EJEMPLO 3: Datos Sensibles Encontrados")
    print("=" * 60)
    
    response = requests.get(
        f"{SNIFFER_URL}/api/sensitive-data?limit=10"
    )
    
    result = response.json()
    print(f"Total de requests con datos sensibles: {result['total']}")
    
    if result['findings']:
        for finding in result['findings'][:3]:
            print(f"\n  Endpoint: {finding['endpoint']}")
            print(f"  Método: {finding['method']}")
            print(f"  Datos sensibles: {list(finding['sensitive_data'].keys())}")

# ============================================================
# 4. VER TODO LO CAPTURADO
# ============================================================
def example_view_all_traffic():
    """Ver todo el tráfico capturado"""
    print("\n📊 EJEMPLO 4: Tráfico Capturado")
    print("=" * 60)
    
    response = requests.get(
        f"{SNIFFER_URL}/api/traffic?limit=5"
    )
    
    result = response.json()
    print(f"Total capturado: {result['stats']['total']} requests")
    print(f"Endpoints únicos: {result['stats']['endpoints']}")
    print(f"Promedio respuesta: {result['stats'].get('avg_ms', 0):.1f}ms")
    
    print("\n📝 Últimas capturas:")
    for packet in result['traffic'][:3]:
        print(f"\n  {packet['method']} {packet['endpoint']}")
        print(f"  Status: {packet['status_code']}")
        print(f"  Encryption: {packet['encryption_type']}")
        if packet.get('vulnerabilities'):
            print(f"  ⚠️ Vulnerabilidades: {[v['name'] for v in packet['vulnerabilities']]}")

# ============================================================
# 5. VER ESTADÍSTICAS MITM
# ============================================================
def example_mitm_stats():
    """Ver estadísticas del MITM"""
    print("\n📈 EJEMPLO 5: Estadísticas MITM")
    print("=" * 60)
    
    response = requests.get(f"{SNIFFER_URL}/api/mitm-stats")
    result = response.json()
    
    stats = result['stats']
    print(f"Total capturado: {stats.get('total', 0)}")
    print(f"Endpoints diferentes: {stats.get('endpoints', 0)}")
    print(f"IPs clientes: {stats.get('clients', 0)}")
    print(f"Requests exitosos (200-299): {stats.get('success', 0)}")
    print(f"Errores (400+): {stats.get('errors', 0)}")
    
    print("\nPor tipo de encriptación:")
    for enc in result['by_encryption']:
        print(f"  {enc['encryption_type']}: {enc['cnt']}")

# ============================================================
# 6. ANALIZAR UN JWT CAPTURADO
# ============================================================
def example_analyze_jwt():
    """Analizar un JWT token capturado"""
    print("\n🔐 EJEMPLO 6: Analizar JWT")
    print("=" * 60)
    
    # JWT ejemplo (payload falso)
    jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    response = requests.post(
        f"{SNIFFER_URL}/api/decode/auto",
        json={"payload": jwt_token}
    )
    
    result = response.json()
    print(f"JWT Token: {jwt_token[:50]}...")
    print(f"\nDecodificaciones encontradas:")
    
    for dec in result['decodings']:
        print(f"\n  Tipo: {dec['type']}")
        print(f"  Contenido: {dec['result'][:100]}...")

# ============================================================
# 7. USAR EL PROXY REVERSO
# ============================================================
def example_use_proxy():
    """Usar el proxy reverso del Sniffer"""
    print("\n🔄 EJEMPLO 7: Proxy Reverso")
    print("=" * 60)
    
    print("""
    Para usar el proxy reverso, configura tu app con:
    
    VITE_API_URL=http://localhost:5000/proxy
    
    Ejemplo:
    - Tu backend en: http://backend:8000/api/users
    - Petición a: http://localhost:5000/proxy/api/users
    - Se captura automáticamente
    
    Curl:
    curl http://localhost:5000/proxy/api/login \\
      -X POST \\
      -H "Content-Type: application/json" \\
      -d '{"email":"test@example.com","password":"123456"}'
    """)

# ============================================================
# 8. JAVASCRIPT/Frontend
# ============================================================
def example_javascript_integration():
    print("\n🌐 EJEMPLO 8: JavaScript Integration")
    print("=" * 60)
    
    code = """
    // En tu frontend Svelte/Vue/React:
    
    const API_URL = "http://localhost:5000/proxy";  // Proxy del Sniffer
    
    // La petición será capturada automáticamente
    const response = await fetch(`${API_URL}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "user@example.com",
        password: "123456"
      })
    });
    
    // Ver en dashboard: http://localhost:5000
    """
    
    print(code)

# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    print("""
    ╔═════════════════════════════════════════╗
    ║  Network Sniffer Pro v2                 ║
    ║  Ejemplos de Uso                        ║
    ╚═════════════════════════════════════════╝
    
    REQUISITOS:
    1. Sniffer corriendo: python sniffer/app.py
    2. PostgreSQL conectado
    3. mitmproxy (opcional pero recomendado)
    """)
    
    # Verificar conexión
    try:
        response = requests.get(f"{SNIFFER_URL}/health", timeout=2)
        if response.status_code == 200:
            print("✓ Sniffer está corriendo\n")
        else:
            print("✗ Sniffer no responde correctamente\n")
    except:
        print("✗ Sniffer no está corriendo\n")
        print("Inicia con: cd sniffer && python app.py\n")
        exit(1)
    
    # Ejecutar ejemplos
    try:
        example_decode_base64()
        example_decode_layers()
        example_view_all_traffic()
        example_view_sensitive_data()
        example_mitm_stats()
        example_analyze_jwt()
        example_use_proxy()
        example_javascript_integration()
        
        print("\n" + "="*60)
        print("✓ Todos los ejemplos completados")
        print("="*60)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nAsegúrate de que:")
        print("1. El Sniffer esté corriendo")
        print("2. PostgreSQL esté disponible")
        print("3. Haya capturado algunos datos (navega tu app primero)")
