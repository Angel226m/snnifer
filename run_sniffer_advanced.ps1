# Script para ejecutar el Sniffer Avanzado (Windows PowerShell)
# Uso: .\run_sniffer_advanced.ps1 -Mode raw-sniffer

param(
    [Parameter(Mandatory=$false)]
    [string]$Mode = "help",
    
    [Parameter(Mandatory=$false)]
    [string]$Interface = "auto"
)

# Colores
$Colors = @{
    'Blue'     = 'Cyan'
    'Green'    = 'Green'
    'Yellow'   = 'Yellow'
    'Red'      = 'Red'
}

# Header
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║           Advanced Packet Sniffer (Wireshark-like)            ║" -ForegroundColor Cyan
Write-Host "║                   v2.0 - Enhanced Package                     ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Verificar si estamos en Docker
if (Test-Path "/.dockerenv") {
    Write-Host "✅ Running inside Docker container" -ForegroundColor Green
    $InDocker = $true
} else {
    Write-Host "⚠️  Running on Windows local system" -ForegroundColor Yellow
    $InDocker = $false
}

# Función para mostrar ayuda
function Show-Help {
    Write-Host ""
    Write-Host "OPCIONES:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  raw-sniffer      - Capturar paquetes RAW (todas las capas OSI)" -ForegroundColor White
    Write-Host "  raw-stats        - Iniciar captura RAW y mostrar estadísticas" -ForegroundColor White
    Write-Host "  mitm-http        - MITM Proxy para HTTP (puerto 8080)" -ForegroundColor White
    Write-Host "  mitm-https       - MITM Proxy para HTTP + HTTPS (puerto 8080)" -ForegroundColor White
    Write-Host "  migrate-db       - Aplicar migraciones a base de datos" -ForegroundColor White
    Write-Host "  help             - Mostrar esta ayuda" -ForegroundColor White
    Write-Host ""
    Write-Host "EJEMPLOS:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Capturar paquetes RAW:" -ForegroundColor White
    Write-Host "    .\run_sniffer_advanced.ps1 -Mode raw-sniffer" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  MITM Proxy en puerto 8080:" -ForegroundColor White
    Write-Host "    .\run_sniffer_advanced.ps1 -Mode mitm-http" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Migrar base de datos:" -ForegroundColor White
    Write-Host "    .\run_sniffer_advanced.ps1 -Mode migrate-db" -ForegroundColor Gray
    Write-Host ""
}

# Función para capturar paquetes RAW
function Invoke-RawSniffer {
    Write-Host ""
    Write-Host "🎯 Iniciando captura de paquetes RAW..." -ForegroundColor Yellow
    Write-Host "   Presiona Ctrl+C para detener y ver estadísticas" -ForegroundColor Yellow
    Write-Host ""
    
    if ($InDocker) {
        & python /app/packet_sniffer_enhanced.py
    } else {
        if (Test-Path "sniffer/packet_sniffer_enhanced.py") {
            & python sniffer/packet_sniffer_enhanced.py
        } elseif (Test-Path "packet_sniffer_enhanced.py") {
            & python packet_sniffer_enhanced.py
        } else {
            Write-Host "❌ packet_sniffer_enhanced.py not found!" -ForegroundColor Red
            exit 1
        }
    }
}

# Función para MITM Proxy HTTP
function Invoke-MitmHttp {
    Write-Host ""
    Write-Host "🌐 Iniciando MITM Proxy para HTTP (puerto 8080)..." -ForegroundColor Yellow
    Write-Host "   Configura tu navegador con proxy: localhost:8080" -ForegroundColor Yellow
    Write-Host ""
    
    if ($InDocker) {
        & mitmdump -s /app/mitm_addon_advanced.py --mode regular --listen-port 8080 -v
    } else {
        & mitmdump -s sniffer/mitm_addon_advanced.py --mode regular --listen-port 8080 -v
    }
}

# Función para MITM Proxy HTTPS
function Invoke-MitmHttps {
    Write-Host ""
    Write-Host "🔒 Iniciando MITM Proxy para HTTP + HTTPS (puerto 8080)..." -ForegroundColor Yellow
    Write-Host "   Nota: Necesitarás instalar el certificado de mitmproxy" -ForegroundColor Yellow
    Write-Host "   Ubicación: %APPDATA%\.mitmproxy\mitmproxy-ca-cert.pem" -ForegroundColor Yellow
    Write-Host ""
    
    if ($InDocker) {
        & mitmdump -s /app/mitm_addon_advanced.py --mode regular --listen-port 8080 -v
    } else {
        & mitmdump -s sniffer/mitm_addon_advanced.py --mode regular --listen-port 8080 -v
    }
}

# Función para migración de BD
function Invoke-MigrateDb {
    Write-Host ""
    Write-Host "🔧 Applying database migrations..." -ForegroundColor Yellow
    Write-Host ""
    
    if ($InDocker) {
        & python /app/migrate_sniffer_db.py
    } else {
        if (Test-Path "migrate_sniffer_db.py") {
            & python migrate_sniffer_db.py
        } else {
            Write-Host "❌ migrate_sniffer_db.py not found!" -ForegroundColor Red
            exit 1
        }
    }
}

# Procesar modo
switch ($Mode.ToLower()) {
    "raw-sniffer" {
        Invoke-RawSniffer
    }
    "raw-stats" {
        Invoke-RawSniffer
    }
    "mitm-http" {
        Invoke-MitmHttp
    }
    "mitm-https" {
        Invoke-MitmHttps
    }
    "migrate-db" {
        Invoke-MigrateDb
    }
    "help" {
        Show-Help
    }
    default {
        Write-Host ""
        Write-Host "❌ Unknown option: $Mode" -ForegroundColor Red
        Show-Help
        exit 1
    }
}
