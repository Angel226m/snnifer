#!/bin/bash
echo "🔍 Network Sniffer - Monitor Frontend↔Backend"
echo "Esperando base de datos..."

# Esperar a que PostgreSQL esté disponible
while ! pg_isready -h db -p 5432 -U postgres > /dev/null 2>&1; do
  echo "⏳ Esperando DB..."
  sleep 2
done

echo "✅ Base de datos lista"
echo "🚀 Iniciando Sniffer en puerto 5000"

# 1 worker + 8 threads so SSE long-lived connections work properly
exec gunicorn --bind 0.0.0.0:5000 --workers 1 --threads 8 --timeout 120 --access-logfile - --error-logfile - app:app
