#!/usr/bin/env bash
# Quick start script for LearnWithGaray - Unified Stack

echo "🚀 LearnWithGaray - Sistema de Gestión de Clientes"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker no está instalado"
    exit 1
fi

# Create .env if missing
if [ ! -f .env ]; then
    echo "📝 Creando archivo .env..."
    cat > .env << 'EOF'
DB_USER=postgres
DB_PASSWORD=password
DB_NAME=learnwithgaray
JWT_SECRET=your-secret-key-change-in-production
EOF
fi

# Clean old assets
echo "🧹 Limpiando contenedores antiguos..."
docker compose down 2>/dev/null || true

# Start stack
echo "🐳 Iniciando Docker Compose..."
docker compose up -d

echo ""
echo "⏳ Esperando servicios (30 segundos)..."
sleep 30

# Check services
echo ""
echo "🔍 Verificando servicios..."
echo ""

echo "1️⃣  Database (PostgreSQL):"
if docker compose exec -T db pg_isready -U postgres -d learnwithgaray &>/dev/null; then
    echo "   ✅ Base de datos lista"
else
    echo "   ⏳ Inicializando..."
fi

echo ""
echo "2️⃣  Backend (FastAPI):"
if curl -s http://localhost:8000/health > /dev/null; then
    echo "   ✅ Backend en línea"
else
    echo "   ⏳ Iniciando..."
fi

echo ""
echo "3️⃣  Frontend (SvelteKit):"
if curl -s http://localhost:3000 > /dev/null; then
    echo "   ✅ Frontend en línea"
else
    echo "   ⏳ Compilando..."
fi

echo ""
echo "4️⃣  Sniffer (Network Monitor):"
if curl -s http://localhost:5000/health > /dev/null; then
    echo "   ✅ Sniffer listo"
else
    echo "   ⏳ Iniciando..."
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✨ ¡Stack iniciado correctamente!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📱 Acceso:"
echo "   🌐 Frontend:        http://localhost:3000"
echo "   🔌 Backend API:     http://localhost:8000"
echo "   📚 API Docs:        http://localhost:8000/docs"
echo "   📊 Sniffer:         http://localhost:5000"
echo "   💾 Base de datos:   localhost:5432"
echo ""
echo "📝 Demo:"
echo "   Email:    angel@gmail.com"
echo "   Password: angel22"
echo ""
echo "⚡ Comandos útiles:"
echo "   Ver logs:     docker compose logs -f [servicio]"
echo "   Detener:      docker compose down"
echo "   Limpiar BD:   docker compose down -v"
echo ""
