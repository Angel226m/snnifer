# Network Sniffer Pro v2 - Setup Script (Windows PowerShell)

Write-Host "════════════════════════════════════════" -ForegroundColor Green
Write-Host "  Network Sniffer Pro v2 Setup" -ForegroundColor Green
Write-Host "════════════════════════════════════════" -ForegroundColor Green
Write-Host ""

# Check Python
$pythonPath = & where python 2>$null
if (-not $pythonPath) {
    Write-Host "❌ Python3 no encontrado" -ForegroundColor Red
    exit 1
}
Write-Host "✓ Python OK" -ForegroundColor Green

# Install dependencies
Write-Host ""
Write-Host "Instalando dependencias..." -ForegroundColor Yellow
Set-Location sniffer
& python -m pip install -q -r requirements.txt
Set-Location ..
Write-Host "✓ Dependencias instaladas" -ForegroundColor Green

# Check mitmproxy
Write-Host ""
Write-Host "Verificando mitmproxy..." -ForegroundColor Yellow
$mitmExists = & where mitmproxy 2>$null
if (-not $mitmExists) {
    Write-Host "⚠ mitmproxy no encontrado" -ForegroundColor Yellow
    $install = Read-Host "¿Instalar mitmproxy? (y/n)"
    if ($install -eq 'y') {
        & python -m pip install -q mitmproxy
        Write-Host "✓ mitmproxy instalado" -ForegroundColor Green
    }
} else {
    Write-Host "✓ mitmproxy OK" -ForegroundColor Green
}

# Menu
Write-Host ""
Write-Host "Selecciona modo:" -ForegroundColor Yellow
Write-Host "1) Sniffer solo (proxy en :5000)"
Write-Host "2) Sniffer + mitmproxy (MITM real :8080)"
Write-Host "3) Ver instrucciones"

$choice = Read-Host "Opción (1-3)"

switch ($choice) {
    "1" {
        Write-Host ""
        Write-Host "Iniciando Sniffer en :5000" -ForegroundColor Green
        Write-Host "Abre: http://localhost:5000" -ForegroundColor Yellow
        Write-Host "Configura tu app: VITE_API_URL=http://localhost:5000/proxy" -ForegroundColor Yellow
        Write-Host ""
        Set-Location sniffer
        & python app_new.py
    }
    "2" {
        Write-Host ""
        Write-Host "Modo MITM Real" -ForegroundColor Green
        Write-Host "Inicia en 3 PowerShell diferentes:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "PowerShell 1 (Dashboard):" -ForegroundColor Cyan
        Write-Host "  cd sniffer; python app_new.py" -ForegroundColor Gray
        Write-Host ""
        Write-Host "PowerShell 2 (MITM):" -ForegroundColor Cyan
        Write-Host "  mitmproxy -s mitm_addon.py --listen-port 8080 -k" -ForegroundColor Gray
        Write-Host ""
        Write-Host "PowerShell 3 (Tu App):" -ForegroundColor Cyan
        Write-Host "  `$env:http_proxy='http://localhost:8080'" -ForegroundColor Gray
        Write-Host "  curl http://localhost:5000/api/traffic" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Ver SNIFFER_SETUP.md para más detalles" -ForegroundColor Yellow
    }
    "3" {
        & cat SNIFFER_SETUP.md | more
    }
    default {
        Write-Host "Opción inválida" -ForegroundColor Red
    }
}
