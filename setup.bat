@echo off
chcp 65001 >nul
echo ================================================
echo   CaaS Prototype - Instalador Automatico
echo ================================================
echo.

REM Verificar si Python esta instalado
echo [1/4] Verificando Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python no esta instalado
    echo.
    echo Por favor instala Python 3.10 o superior desde:
    echo https://www.python.org/downloads/
    echo.
    echo IMPORTANTE: Durante la instalacion, marca la casilla "Add Python to PATH"
    echo.
    pause
    exit /b 1
)

python --version
echo OK: Python encontrado
echo.

REM Cambiar al directorio del proyecto
cd /d "%~dp0"

echo [2/4] Instalando dependencias...
python -m pip install --upgrade pip --quiet
python -m pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo ERROR: No se pudieron instalar las dependencias
    pause
    exit /b 1
)
echo OK: Dependencias instaladas
echo.

echo [3/4] Inicializando base de datos...
python app\db\seed.py
if %errorlevel% neq 0 (
    echo ADVERTENCIA: Error al inicializar la base de datos
)
echo OK: Base de datos inicializada
echo.

echo ================================================
echo   Instalacion Completada
echo ================================================
echo.
echo Usuarios de prueba:
echo   - admin    / Admin123!
echo   - testuser / Test123!
echo   - demo     / Demo123!
echo.
echo [4/4] Iniciando servidor...
echo.
echo ================================================
echo   Servidor CaaS en:
echo   - API:    http://localhost:8000
echo   - Docs:   http://localhost:8000/api/docs
echo   - Health: http://localhost:8000/api/health
echo ================================================
echo.
echo Presiona Ctrl+C para detener el servidor
echo.

REM Ejecutar la aplicacion
python run.py

pause
