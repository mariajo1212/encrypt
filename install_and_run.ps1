# Script de instalación y ejecución automática del proyecto CaaS
# Para Windows PowerShell

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Instalador Automático - CaaS Prototype" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Verificar si Python está instalado
Write-Host "[1/5] Verificando Python..." -ForegroundColor Yellow
$pythonInstalled = $false

try {
    $pythonVersion = python --version 2>&1
    if ($pythonVersion -match "Python 3\.\d+") {
        Write-Host "✓ Python ya está instalado: $pythonVersion" -ForegroundColor Green
        $pythonInstalled = $true
    }
} catch {
    Write-Host "✗ Python no encontrado" -ForegroundColor Red
}

# Instalar Python si no está instalado
if (-not $pythonInstalled) {
    Write-Host ""
    Write-Host "[2/5] Instalando Python 3.11..." -ForegroundColor Yellow
    Write-Host "Esto puede tardar unos minutos..." -ForegroundColor Gray

    # Intentar instalar con winget (Windows Package Manager)
    try {
        winget install Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements

        # Agregar Python al PATH para esta sesión
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

        Write-Host "✓ Python instalado correctamente" -ForegroundColor Green
        Write-Host ""
        Write-Host "IMPORTANTE: Cierra y vuelve a abrir PowerShell para que los cambios surtan efecto," -ForegroundColor Yellow
        Write-Host "y luego ejecuta este script nuevamente." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Presiona Enter para salir..."
        Read-Host
        exit
    } catch {
        Write-Host "✗ No se pudo instalar Python automáticamente" -ForegroundColor Red
        Write-Host ""
        Write-Host "Por favor, instala Python manualmente:" -ForegroundColor Yellow
        Write-Host "1. Ve a: https://www.python.org/downloads/" -ForegroundColor White
        Write-Host "2. Descarga Python 3.11 o superior" -ForegroundColor White
        Write-Host "3. Durante la instalación, MARCA la casilla 'Add Python to PATH'" -ForegroundColor White
        Write-Host "4. Instala y ejecuta este script nuevamente" -ForegroundColor White
        Write-Host ""
        Write-Host "Presiona Enter para abrir la página de descargas..."
        Read-Host
        Start-Process "https://www.python.org/downloads/"
        exit
    }
}

Write-Host ""
Write-Host "[3/5] Instalando dependencias del proyecto..." -ForegroundColor Yellow

# Navegar al directorio del proyecto
Set-Location -Path "c:\Users\maria\Desktop\unir\TFM\Codigo"

# Instalar dependencias
try {
    python -m pip install --upgrade pip --quiet
    python -m pip install -r requirements.txt --quiet
    Write-Host "✓ Dependencias instaladas" -ForegroundColor Green
} catch {
    Write-Host "✗ Error al instalar dependencias" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[4/5] Inicializando base de datos y usuarios..." -ForegroundColor Yellow

# Inicializar base de datos
try {
    python app/db/seed.py
    Write-Host "✓ Base de datos inicializada" -ForegroundColor Green
} catch {
    Write-Host "✗ Error al inicializar base de datos" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  ✓ Instalación Completada" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Usuarios de prueba creados:" -ForegroundColor Yellow
Write-Host "  • Usuario: admin    | Password: Admin123!" -ForegroundColor White
Write-Host "  • Usuario: testuser | Password: Test123!" -ForegroundColor White
Write-Host "  • Usuario: demo     | Password: Demo123!" -ForegroundColor White
Write-Host ""
Write-Host "[5/5] Iniciando servidor CaaS..." -ForegroundColor Yellow
Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "  Servidor iniciado en:" -ForegroundColor Green
Write-Host "  • API: http://localhost:8000" -ForegroundColor White
Write-Host "  • Docs: http://localhost:8000/api/docs" -ForegroundColor White
Write-Host "  • Health: http://localhost:8000/api/health" -ForegroundColor White
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Presiona Ctrl+C para detener el servidor" -ForegroundColor Gray
Write-Host ""

# Ejecutar la aplicación
python run.py
