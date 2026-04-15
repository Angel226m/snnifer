#!/bin/bash
# Entrypoint mejorado para sniffer con dashboard Wireshark

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          Advanced Sniffer Dashboard (Wireshark-like)          ║"
echo "║                  Starting up...                               ║"
echo "╚════════════════════════════════════════════════════════════════╝"

# Esperar a DB
echo "⏳ Waiting for PostgreSQL..."
until PGPASSWORD=password psql -h $POSTGRES_HOST -U postgres -d learnwithgaray -c "SELECT 1" 2>/dev/null; do
    echo "  DB not ready, waiting..."
    sleep 2
done
echo "✅ PostgreSQL is ready!"

# Aplicar migraciones
echo "📝 Applying database migrations..."
python migrate_sniffer_db.py
echo "✅ Migrations applied!"

# Crear tablas
python -c "
from app_enhanced import ensure_capture_tables
if ensure_capture_tables():
    print('✅ Capture tables ready!')
else:
    print('⚠️  Tables might already exist')
"

# Iniciar app con gunicorn (multiple workers)
echo ""
echo "🚀 Starting Sniffer Dashboard on http://0.0.0.0:5000"
echo "   - Real-time packet capture"
echo "   - Wireshark-like interface"
echo "   - Automatic vulnerability detection"
echo ""

# Opción 1: Gunicorn (producción)
if [ "$FLASK_ENV" = "production" ]; then
    echo "📦 Running in PRODUCTION mode (gunicorn)"
    exec gunicorn -w 4 -b 0.0.0.0:5000 app_enhanced:app
else
    # Opción 2: Flask dev (con hot-reload)
    echo "🔧 Running in DEVELOPMENT mode (flask)"
    export FLASK_DEBUG=1
    exec python -u app_enhanced.py
fi
