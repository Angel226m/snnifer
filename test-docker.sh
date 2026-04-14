#!/usr/bin/env bash
# Test and validate Docker Compose Stack

echo "🧪 Probando stack de Docker..."
echo ""

# Check if services are running
docker compose ps
echo ""

echo "🔍 Estado de servicios:"
echo ""

# Database
echo "1. PostgreSQL:"
if docker compose exec -T db pg_isready -U postgres -d learnwithgaray &>/dev/null; then
    echo "   ✅ Base de datos: OK"
else
    echo "   ❌ Base de datos: No responde"
fi

# Backend
echo ""
echo "2. Backend (FastAPI):"
if curl -s http://localhost:8000/health | grep -q "ok"; then
    CLIENTS=$(curl -s http://localhost:8000/clients -H "Authorization: Bearer dummy" 2>/dev/null | wc -c)
    echo "   ✅ API: OK (health check)"
else
    echo "   ❌ API: No responde"
fi

# Frontend
echo ""
echo "3. Frontend (SvelteKit):"
if curl -s http://localhost:3000 | head -c 100 | grep -q "<"; then
    echo "   ✅ Frontend: OK"
else
    echo "   ❌ Frontend: No responde"
fi

# Sniffer
echo ""
echo "4. Sniffer (Flask):"
if curl -s http://localhost:5000/health 2>/dev/null | grep -q "healthy\|ok"; then
    echo "   ✅ Sniffer: OK"
else
    echo "   ❌ Sniffer: No responde"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Prueba completada"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🌐 Acceso:"
echo "   Frontend:   http://localhost:3000"
echo "   Backend:    http://localhost:8000"
echo "   Sniffer:    http://localhost:5000"
echo ""
