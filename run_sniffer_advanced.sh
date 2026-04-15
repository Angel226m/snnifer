#!/bin/bash
# Script para ejecutar el Sniffer Avanzado
# Uso: ./run_sniffer_advanced.sh [opción] [argumentos]

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║           Advanced Packet Sniffer (Wireshark-like)            ║"
echo "║                   v2.0 - Enhanced Package                     ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar si estamos en Docker o en local
if [ -f /.dockerenv ]; then
    CONTAINER_ENV=true
    echo -e "${GREEN}✅ Running inside Docker container${NC}"
else
    CONTAINER_ENV=false
    echo -e "${YELLOW}⚠️  Running on local system${NC}"
fi

# Función para mostrar ayuda
show_help() {
    cat << EOF
${BLUE}OPCIONES:${NC}

  1) raw-sniffer      - Capturar paquetes RAW (todas las capas OSI)
  2) raw-stats        - Iniciar captura RAW y mostrar estadísticas
  3) mitm-http        - MITM Proxy para HTTP (puerto 8080)
  4) mitm-https       - MITM Proxy para HTTP + HTTPS (puerto 8080)
  5) migrate-db       - Aplicar migraciones a base de datos
  6) help             - Mostrar esta ayuda

${BLUE}EJEMPLOS:${NC}

  Capturar paquetes RAW:
    ./run_sniffer_advanced.sh raw-sniffer

  MITM Proxy en puerto 8080:
    ./run_sniffer_advanced.sh mitm-http

  Migrar base de datos:
    ./run_sniffer_advanced.sh migrate-db

EOF
}

# Función para capturar paquetes RAW
run_raw_sniffer() {
    echo -e "${YELLOW}🎯 Iniciando captura de paquetes RAW...${NC}"
    echo -e "${YELLOW}   Presiona Ctrl+C para detener y ver estadísticas${NC}\n"
    
    if [ "$CONTAINER_ENV" = true ]; then
        python /app/packet_sniffer_enhanced.py
    else
        python sniffer/packet_sniffer_enhanced.py
    fi
}

# Función para MITM Proxy HTTP
run_mitm_http() {
    echo -e "${YELLOW}🌐 Iniciando MITM Proxy para HTTP (puerto 8080)...${NC}"
    echo -e "${YELLOW}   Configura tu navegador con proxy: localhost:8080${NC}\n"
    
    if [ "$CONTAINER_ENV" = true ]; then
        mitmdump -s /app/mitm_addon_advanced.py --mode regular --listen-port 8080 -v
    else
        mitmdump -s sniffer/mitm_addon_advanced.py --mode regular --listen-port 8080 -v
    fi
}

# Función para MITM Proxy HTTP + HTTPS
run_mitm_https() {
    echo -e "${YELLOW}🔒 Iniciando MITM Proxy para HTTP + HTTPS (puerto 8080)...${NC}"
    echo -e "${YELLOW}   Nota: Necesitarás instalar el certificado de mitmproxy${NC}"
    echo -e "${YELLOW}   Ubicación: ~/.mitmproxy/mitmproxy-ca-cert.pem${NC}\n"
    
    if [ "$CONTAINER_ENV" = true ]; then
        mitmdump -s /app/mitm_addon_advanced.py --mode regular --listen-port 8080 -v
    else
        mitmdump -s sniffer/mitm_addon_advanced.py --mode regular --listen-port 8080 -v
    fi
}

# Función para migración de BD
run_migrate_db() {
    echo -e "${YELLOW}🔧 Applying database migrations...${NC}\n"
    
    if [ "$CONTAINER_ENV" = true ]; then
        python /app/migrate_sniffer_db.py
    else
        python migrate_sniffer_db.py
    fi
}

# Procesar argumentos
case "${1:-help}" in
    1|raw-sniffer)
        run_raw_sniffer
        ;;
    2|raw-stats)
        run_raw_sniffer
        ;;
    3|mitm-http)
        run_mitm_http
        ;;
    4|mitm-https)
        run_mitm_https
        ;;
    5|migrate-db)
        run_migrate_db
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}❌ Unknown option: $1${NC}"
        show_help
        exit 1
        ;;
esac
