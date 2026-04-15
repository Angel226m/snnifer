#!/usr/bin/env python3
"""
Network Sniffer Pro v2 - MITM Complete Setup & Usage Guide
"""

import subprocess
import sys
import os
from pathlib import Path

def print_header(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}\n")

def check_python():
    """Verifica que Python 3.8+ esté disponible"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ requerido")
        sys.exit(1)
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor}")

def install_sniffer_deps():
    """Instala dependencias del sniffer"""
    print_header("Instalando dependencias del Sniffer")
    
    sniffer_dir = Path(__file__).parent / "sniffer"
    req_file = sniffer_dir / "requirements.txt"
    
    if req_file.exists():
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", str(req_file)],
                      check=True)
        print("✓ Dependencias del Sniffer instaladas")
    else:
        print("❌ requirements.txt no encontrado")

def install_mitmproxy():
    """Instala mitmproxy para MITM real"""
    print_header("Instalando mitmproxy para MITM Real")
    
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "mitmproxy>=9.0.0"],
                      check=True)
        print("✓ mitmproxy instalado")
    except:
        print("❌ Error instalando mitmproxy")
        print("Instálalo manualmente: pip install mitmproxy")

def start_sniffer():
    """Inicia el servidor del sniffer"""
    print_header("Iniciando Sniffer Dashboard")
    
    sniffer_dir = Path(__file__).parent / "sniffer"
    os.chdir(sniffer_dir)
    
    try:
        subprocess.run([sys.executable, "app.py"])
    except KeyboardInterrupt:
        print("\n✓ Sniffer detenido")

def start_mitmproxy():
    """Inicia mitmproxy con el addon"""
    print_header("Iniciando mitmproxy MITM")
    
    addon_path = Path(__file__).parent / "mitm_addon.py"
    
    print(f"\nUsando addon: {addon_path}")
    print("\nComandos disponibles:")
    print("  1. mitmproxy (interfaz web en http://localhost:8081)")
    print("  2. mitmweb (web en http://localhost:8081)")
    print("  3. mitmdump (solo línea de comandos)")
    
    try:
        # Puedes cambiar el comando aquí
        subprocess.run([
            "mitmproxy",
            "-s", str(addon_path),
            "--listen-port", "8080",
            "-k"  # Permitir HTTPS sin certificado válido
        ])
    except KeyboardInterrupt:
        print("\n✓ mitmproxy detenido")
    except FileNotFoundError:
        print("❌ mitmproxy no encontrado. Instálalo: pip install mitmproxy")

def show_usage():
    print_header("NETWORK SNIFFER PRO v2 - GUÍA DE USO")
    
    print("""
ARQUITECTURA:
─────────────────────────────────────────────────────────────
  Frontend → mitmproxy:8080 (MITM) → Backend:8000
            └─→ Sniffer:5000 (Dashboard & Storage)

CAPACIDADES:
─────────────────────────────────────────────────────────────
1. CAPTURA TOTAL:
   - Intercepta TODOS los requests/responses
   - Desencripta HTTPS automáticamente
   - Decodifica Base64, URL encoding, Hex

2. ANÁLISIS AVANZADO:
   - Detecta datos sensibles (emails, tokens, API keys)
   - Análisis de vulnerabilidades de seguridad
   - Clasificación de tipos de encriptación

3. MODIFICACIÓN EN TRÁNSITO (MITM REAL):
   - Cambiar valores en requests/responses
   - Inyectar datos maliciosos
   - Remover headers/campos

4. DESENCRIPTACIÓN PROFUNDA:
   - Base64 → Hex → URL encoding (múltiples capas)
   - Decodificación recursiva automática
   - Cache de patrones desencriptados

INSTALACIÓN RÁPIDA:
─────────────────────────────────────────────────────────────
1. pip install mitmproxy (si no está instalado)
2. python setup_sniffer.py

O MANUALMENTE:
─────────────────────────────────────────────────────────────
Terminal 1:
  $ python sniffer/app.py
  → Dashboard en http://localhost:5000

Terminal 2:
  $ mitmproxy -s mitm_addon.py --listen-port 8080 -k
  → MITM en localhost:8080
  → Web UI en http://localhost:8081

Terminal 3 (tu app):
  $ export http_proxy=http://localhost:8080
  $ export https_proxy=http://localhost:8080
  $ curl http://backend:8000/api/...

URLs DEL DASHBOARD:
─────────────────────────────────────────────────────────────
  /              → Dashboard principal
  /api/traffic           → Log de tráfico capturado
  /api/sensitive-data    → Datos sensibles encontrados
  /api/modifications     → Modificaciones realizadas
  /api/decryption-attempts → Intentos de desencriptación
  /api/mitm-stats        → Estadísticas de MITM

API ENDPOINTS:
─────────────────────────────────────────────────────────────
  POST /api/decode/auto              → Decodificar payload automáticamente
  POST /api/analyze/payload          → Análisis completo de payload
  GET  /api/sensitive-data           → Datos sensibles capturados
  GET  /api/modifications            → Log de modificaciones
  GET  /api/decryption-attempts      → Historia de desencriptación
  GET  /api/mitm-stats               → Estadísticas MITM

EJEMPLO PRÁCTICO:
─────────────────────────────────────────────────────────────
1. Inicia todo según instrucciones anteriores
2. Configura tu navegador proxy: http://localhost:8080
3. Navega por tu app web
4. Ve a http://localhost:5000 para ver todo capturado
5. Haz click en cualquier request para ver detalles
6. O usa: curl POST http://localhost:5000/api/decode/auto
   con payload: {"payload": "base64_string"}

MODIFICACIÓN EN TRÁNSITO:
─────────────────────────────────────────────────────────────
En mitm_addon.py, modifica la sección del request() hook:

  if "/login" in path and req_body:
      req_body["password"] = "INTERCEPTED"
      flow.request.text = json.dumps(req_body)

O usa headers HTTP:
  X-Sniff-Modify: {"password": "hacked"}

VISTA DE TRÁFICO:
─────────────────────────────────────────────────────────────
Cada línea tiene:
  - Method (GET/POST/PUT/DELETE)
  - Endpoint (/api/...)
  - Status Code (200/401/500...)
  - Encryption Type (PLAINTEXT/JWT_RS256/HTTPS...)
  - Vulnerabilities (detectadas automáticamente)
  - Sensitive Data (emails, tokens, etc.)
  - Modifications (si fue modificado en tránsito)

NOTA: Este sniffer es EDUCATIVO. No uses para actividades ilegales.
    """)

if __name__ == "__main__":
    check_python()
    
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        
        if cmd == "install":
            install_sniffer_deps()
            install_mitmproxy()
        elif cmd == "sniffer":
            start_sniffer()
        elif cmd == "mitm":
            start_mitmproxy()
        elif cmd == "help":
            show_usage()
        else:
            print(f"Comando desconocido: {cmd}")
            print("\nUsos:")
            print("  python setup_sniffer.py install  → Instalar dependencias")
            print("  python setup_sniffer.py sniffer  → Iniciar dashboard")
            print("  python setup_sniffer.py mitm     → Iniciar mitmproxy")
            print("  python setup_sniffer.py help     → Ver guía completa")
    else:
        show_usage()
