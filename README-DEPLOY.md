# 🚀 Despliegue de CaaS en Producción

Esta guía te ayudará a desplegar CaaS en tu servidor de DigitalOcean.

**Servidor**: 68.183.174.203 (Ubuntu 22.04 LTS)

---

## 📋 Archivos de Despliegue Disponibles

| Archivo | Descripción |
|---------|-------------|
| `QUICK-DEPLOY.md` | ⚡ Guía rápida - pasos esenciales |
| `DEPLOY-PRODUCTION.md` | 📖 Guía completa con troubleshooting |
| `transfer-to-server.ps1` | 💻 Script PowerShell para transferir desde Windows |
| `deploy.sh` | 🔧 Script maestro de despliegue (ejecutar en servidor) |
| `install.sh` | 📦 Instalación de la aplicación |
| `setup-service.sh` | ⚙️ Configuración de systemd service |
| `setup-nginx.sh` | 🌐 Configuración de Nginx reverse proxy |
| `setup-firewall.sh` | 🔒 Configuración del firewall UFW |

---

## 🎯 Inicio Rápido

### Opción 1: Transferencia Automática (Windows)

```powershell
# En PowerShell (Windows)
cd C:\Users\maria\Desktop\unir\TFM\Codigo
.\transfer-to-server.ps1
```

Luego en el servidor:
```bash
ssh root@68.183.174.203
cd /tmp/caas-deploy
sudo bash deploy.sh
```

### Opción 2: Manual

```powershell
# En Windows - Crear y transferir
cd C:\Users\maria\Desktop\unir\TFM\Codigo
tar -czf caas.tar.gz --exclude=.git --exclude=venv --exclude=data .
scp caas.tar.gz root@68.183.174.203:/tmp/
```

```bash
# En el servidor
ssh root@68.183.174.203
cd /tmp
tar -xzf caas.tar.gz -C /tmp/caas-deploy
cd /tmp/caas-deploy
chmod +x *.sh
sudo bash deploy.sh
```

---

## ✅ Verificación

Después del despliegue, verifica:

```bash
# Estado del servicio
sudo systemctl status caas

# Ver logs en tiempo real
sudo journalctl -u caas -f

# Probar el health check
curl http://localhost:8000/api/health
```

Acceder desde el navegador:
- 🌐 Web: http://68.183.174.203:8000/web
- 📚 API Docs: http://68.183.174.203:8000/api/docs

**Usuarios de prueba**:
- `admin` / `Admin123!`
- `testuser` / `Test123!`

---

## 🔐 Seguridad Post-Despliegue

1. ✅ Cambiar contraseñas por defecto
2. ✅ Configurar HTTPS con Let's Encrypt (si tienes dominio)
3. ✅ Revisar configuración del firewall
4. ✅ Configurar backups automáticos
5. ✅ Revisar archivo `.env` en `/opt/caas/.env`

---

## 📂 Estructura en el Servidor

```
/opt/caas/
├── app/                  # Código de la aplicación
├── web/                  # Frontend
├── data/                 # Base de datos SQLite
│   └── caas.db
├── logs/                 # Logs de la aplicación
│   └── app.log
├── venv/                 # Virtual environment de Python
├── .env                  # Configuración (¡SECRETO!)
├── run.py               # Script de inicio
└── requirements.txt     # Dependencias de Python
```

---

## 🛠️ Comandos Útiles

### Gestión del Servicio
```bash
sudo systemctl status caas      # Ver estado
sudo systemctl restart caas     # Reiniciar
sudo systemctl stop caas        # Detener
sudo systemctl start caas       # Iniciar
```

### Logs
```bash
sudo journalctl -u caas -f              # Logs en tiempo real
sudo journalctl -u caas -n 100          # Últimos 100 logs
tail -f /opt/caas/logs/app.log          # Logs de aplicación
```

### Base de Datos
```bash
sqlite3 /opt/caas/data/caas.db          # Acceder a la DB
# Backup manual
cp /opt/caas/data/caas.db /opt/caas/data/backup_$(date +%Y%m%d).db
```

---

## 🆘 Solución de Problemas

### El servicio no inicia
```bash
sudo journalctl -u caas -xe            # Ver error detallado
ls -la /opt/caas/venv                  # Verificar virtual env
cat /opt/caas/.env                     # Revisar configuración
```

### Puerto en uso
```bash
sudo lsof -i :8000                     # Ver qué usa el puerto
sudo kill -9 <PID>                     # Matar proceso
```

### Problemas de firewall
```bash
sudo ufw status                        # Ver reglas
sudo ufw allow 8000/tcp               # Permitir puerto 8000
sudo ufw reload                        # Recargar reglas
```

---

## 🌐 Configurar Dominio (Opcional)

Si tienes un dominio apuntando a 68.183.174.203:

```bash
cd /opt/caas
sudo bash setup-nginx.sh

# El script te preguntará:
# - Dominio: caas.tudominio.com
# - SSL: Responde 'y' para Let's Encrypt
# - Email: tu@email.com
```

Luego accederás vía:
- https://caas.tudominio.com/web
- https://caas.tudominio.com/api/docs

---

## 📞 Contacto y Soporte

- Ver documentación completa: `DEPLOY-PRODUCTION.md`
- Guía rápida: `QUICK-DEPLOY.md`
- Logs del servidor: `sudo journalctl -u caas -f`

---

## 📊 URLs de Acceso

### Con IP (sin Nginx)
- Web: http://68.183.174.203:8000/web
- API Docs: http://68.183.174.203:8000/api/docs
- Health: http://68.183.174.203:8000/api/health

### Con Dominio + Nginx
- Web: https://tudominio.com/web
- API Docs: https://tudominio.com/api/docs
- Health: https://tudominio.com/api/health

---

**¡Listo para producción! 🎉**
