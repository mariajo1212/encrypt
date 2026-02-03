# ============================================================
# Script para transferir CaaS al servidor de producción
# Servidor: 68.183.174.203
# ============================================================

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Transferencia de CaaS a Producción" -ForegroundColor Cyan
Write-Host "  IP: 68.183.174.203" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Verificar que estamos en el directorio correcto
$currentDir = Get-Location
if (-not (Test-Path "run.py") -or -not (Test-Path "app")) {
    Write-Host "ERROR: Este script debe ejecutarse desde el directorio del proyecto" -ForegroundColor Red
    Write-Host "Asegúrate de estar en: C:\Users\maria\Desktop\unir\TFM\Codigo" -ForegroundColor Red
    exit 1
}

Write-Host "Directorio actual: $currentDir" -ForegroundColor Green
Write-Host ""

# Preguntar confirmación
$confirm = Read-Host "¿Deseas continuar con la transferencia? (s/n)"
if ($confirm -ne "s" -and $confirm -ne "S") {
    Write-Host "Transferencia cancelada" -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "[1/4] Creando archivo tar.gz del proyecto..." -ForegroundColor Yellow

# Verificar si tar está disponible (Windows 10+)
try {
    $tarVersion = & tar --version 2>&1
    Write-Host "Usando tar nativo de Windows" -ForegroundColor Green
} catch {
    Write-Host "ERROR: tar no está disponible" -ForegroundColor Red
    Write-Host "Solución alternativa: Usa WSL o Git Bash para crear el archivo tar" -ForegroundColor Yellow
    exit 1
}

# Crear archivo tar excluyendo archivos innecesarios
$excludePatterns = @(
    "--exclude=.git",
    "--exclude=__pycache__",
    "--exclude=*.pyc",
    "--exclude=venv",
    "--exclude=data",
    "--exclude=logs",
    "--exclude=.env",
    "--exclude=*.tar.gz",
    "--exclude=node_modules"
)

Write-Host "Empaquetando archivos..." -ForegroundColor Cyan
& tar -czf caas.tar.gz $excludePatterns .

if (-not (Test-Path "caas.tar.gz")) {
    Write-Host "ERROR: No se pudo crear el archivo tar.gz" -ForegroundColor Red
    exit 1
}

$fileSize = (Get-Item "caas.tar.gz").Length / 1MB
Write-Host "Archivo creado: caas.tar.gz ($("{0:N2}" -f $fileSize) MB)" -ForegroundColor Green
Write-Host ""

Write-Host "[2/4] Transfiriendo archivo al servidor..." -ForegroundColor Yellow
Write-Host "Se te pedirá la contraseña del servidor" -ForegroundColor Cyan
Write-Host ""

# Transferir usando SCP (requiere OpenSSH en Windows)
$serverIP = "68.183.174.203"
$serverUser = "root"

try {
    & scp caas.tar.gz "${serverUser}@${serverIP}:/tmp/"

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Transferencia completada exitosamente" -ForegroundColor Green
    } else {
        throw "Error en la transferencia"
    }
} catch {
    Write-Host "ERROR: No se pudo transferir el archivo" -ForegroundColor Red
    Write-Host "Verifica que:" -ForegroundColor Yellow
    Write-Host "  1. Tienes acceso SSH al servidor" -ForegroundColor Yellow
    Write-Host "  2. La IP 68.183.174.203 es correcta" -ForegroundColor Yellow
    Write-Host "  3. OpenSSH está instalado en Windows" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "[3/4] Preparando comandos de despliegue..." -ForegroundColor Yellow

# Crear script de comandos para ejecutar en el servidor
$deployCommands = @"
#!/bin/bash
echo "Preparando despliegue en el servidor..."
cd /tmp
mkdir -p caas-deploy
tar -xzf caas.tar.gz -C caas-deploy
cd caas-deploy
chmod +x *.sh
echo ""
echo "Archivos preparados. Ejecuta el siguiente comando:"
echo "  sudo bash deploy.sh"
echo ""
"@

$deployCommands | Out-File -FilePath "remote-deploy-commands.sh" -Encoding ASCII -NoNewline

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "  Transferencia Completada" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Próximos pasos:" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Conectarse al servidor:" -ForegroundColor White
Write-Host "   ssh root@68.183.174.203" -ForegroundColor Yellow
Write-Host ""
Write-Host "2. Extraer y preparar los archivos:" -ForegroundColor White
Write-Host "   cd /tmp" -ForegroundColor Yellow
Write-Host "   mkdir -p caas-deploy" -ForegroundColor Yellow
Write-Host "   tar -xzf caas.tar.gz -C caas-deploy" -ForegroundColor Yellow
Write-Host "   cd caas-deploy" -ForegroundColor Yellow
Write-Host "   chmod +x *.sh" -ForegroundColor Yellow
Write-Host ""
Write-Host "3. Ejecutar el despliegue:" -ForegroundColor White
Write-Host "   sudo bash deploy.sh" -ForegroundColor Yellow
Write-Host ""
Write-Host "4. Una vez completado, acceder a:" -ForegroundColor White
Write-Host "   http://68.183.174.203:8000/web" -ForegroundColor Yellow
Write-Host "   http://68.183.174.203:8000/api/docs" -ForegroundColor Yellow
Write-Host ""
Write-Host "Para más detalles, consulta: DEPLOY-PRODUCTION.md" -ForegroundColor Cyan
Write-Host ""

# Limpiar archivo temporal
Write-Host "[4/4] Limpieza..." -ForegroundColor Yellow
Remove-Item "caas.tar.gz" -ErrorAction SilentlyContinue

Write-Host "Listo! El archivo ha sido transferido al servidor." -ForegroundColor Green
Write-Host ""
