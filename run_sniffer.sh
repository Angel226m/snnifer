#!/bin/bash
# Network Sniffer Pro v2 - Setup & Run Script

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Network Sniffer Pro v2 Setup${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}\n"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python3 no encontrado${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Python3 OK"

# Check if in correct directory
if [ ! -f "sniffer/app_new.py" ]; then
    echo -e "${RED}❌ Ejecuta este script desde la raíz del proyecto${NC}"
    exit 1
fi

# Install sniffer dependencies
echo -e "\n${YELLOW}Instalando dependencias del Sniffer...${NC}"
cd sniffer
pip install -q -r requirements.txt 2>/dev/null || true
cd ..
echo -e "${GREEN}✓${NC} Sniffer dependencies installed"

# Check mitmproxy
echo -e "\n${YELLOW}Verificando mitmproxy...${NC}"
if ! command -v mitmproxy &> /dev/null; then
    echo -e "${YELLOW}⚠ mitmproxy no encontrado${NC}"
    echo -e "${YELLOW}Instálalo con: pip install mitmproxy${NC}"
    read -p "¿Instalarlo ahora? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        pip install -q mitmproxy
        echo -e "${GREEN}✓${NC} mitmproxy instalado"
    fi
else
    echo -e "${GREEN}✓${NC} mitmproxy OK"
fi

# Choose mode
echo -e "\n${YELLOW}Selecciona modo:${NC}"
echo "1) Sniffer solo (proxy reverso en :5000)"
echo "2) Sniffer + mitmproxy (MITM real en :8080)"
echo "3) Ver guía de setup"
read -p "Opción (1-3): " -n 1 -r MODE
echo

case $MODE in
    1)
        echo -e "\n${GREEN}Iniciando Sniffer en :5000${NC}"
        echo -e "${YELLOW}Abre: http://localhost:5000${NC}"
        echo -e "${YELLOW}Configura tu app con: VITE_API_URL=http://localhost:5000/proxy${NC}\n"
        cd sniffer
        python3 app_new.py
        ;;
    2)
        echo -e "\n${GREEN}Modo MITM Real${NC}"
        echo -e "${YELLOW}Inicia en 3 terminales diferentes:${NC}\n"
        echo -e "Terminal 1 (Dashboard):"
        echo -e "  cd sniffer && python3 app_new.py\n"
        echo -e "Terminal 2 (MITM Proxy):"
        echo -e "  mitmproxy -s mitm_addon.py --listen-port 8080 -k\n"
        echo -e "Terminal 3 (Tu App):"
        echo -e "  export http_proxy=http://localhost:8080"
        echo -e "  export https_proxy=http://localhost:8080"
        echo -e "  curl http://localhost:5000/api/traffic\n"
        echo -e "${YELLOW}Para profundizar ver SNIFFER_SETUP.md${NC}"
        ;;
    3)
        cat SNIFFER_SETUP.md
        ;;
    *)
        echo -e "${RED}Opción inválida${NC}"
        ;;
esac
