# CaaS Deployment Guide - Ubuntu Server (Digital Ocean)

Esta guía te ayudará a desplegar el CaaS API en un droplet de Digital Ocean con Ubuntu 20.04 o 22.04.

## Requisitos

- Droplet de Digital Ocean con Ubuntu 20.04 o 22.04
- Mínimo 1GB RAM, 1 vCPU, 25GB SSD
- Acceso SSH como root o usuario con sudo
- (Opcional) Dominio apuntando a la IP del droplet

## Despliegue Automático (Recomendado)

### 1. Conectar al servidor

```bash
ssh root@YOUR_SERVER_IP
```

### 2. Subir archivos al servidor

Desde tu máquina local:

```bash
# Comprimir el proyecto
tar -czf caas.tar.gz -C "C:\Users\maria\Desktop\unir\TFM\Codigo" .

# Subir al servidor
scp caas.tar.gz root@YOUR_SERVER_IP:/root/

# Conectar al servidor
ssh root@YOUR_SERVER_IP
```

### 3. Descomprimir y ejecutar el script de despliegue

```bash
# En el servidor
cd /root
tar -xzf caas.tar.gz -C caas
cd caas

# Dar permisos de ejecución
chmod +x *.sh

# Ejecutar despliegue completo
sudo bash deploy.sh
```

El script te preguntará:
- Si quieres continuar con la instalación
- Si quieres configurar Nginx (recomendado)
- Tu dominio (si tienes uno)
- Si quieres SSL con Let's Encrypt (recomendado)

## Despliegue Manual (Paso a Paso)

Si prefieres hacer cada paso manualmente:

### 1. Instalar la aplicación

```bash
sudo bash install.sh
```

Esto instalará:
- Python 3 y dependencias
- Paquetes del sistema
- Dependencias de Python en un virtualenv
- Inicializará la base de datos
- Creará usuarios de prueba

### 2. Configurar como servicio systemd

```bash
sudo bash setup-service.sh
```

Esto:
- Creará un servicio systemd
- Lo habilitará para que inicie automáticamente
- Iniciará el servicio

### 3. Configurar firewall

```bash
sudo bash setup-firewall.sh
```

Esto:
- Instalará y configurará UFW
- Permitirá SSH (22), HTTP (80), HTTPS (443)
- Habilitará el firewall

### 4. Configurar Nginx (Opcional pero recomendado)

```bash
sudo bash setup-nginx.sh
```

Esto:
- Instalará Nginx
- Configurará un reverse proxy
- (Opcional) Configurará SSL con Let's Encrypt

## Verificar la Instalación

### Verificar el servicio

```bash
sudo systemctl status caas
```

Deberías ver "active (running)" en verde.

### Verificar logs

```bash
# Logs del servicio
sudo journalctl -u caas -f

# Logs de acceso
sudo tail -f /var/log/caas/access.log

# Logs de error
sudo tail -f /var/log/caas/error.log
```

### Probar la API

```bash
# Health check
curl http://localhost:8000/api/health

# Con Nginx
curl http://YOUR_DOMAIN/api/health
```

## Gestión del Servicio

### Comandos básicos

```bash
# Ver estado
sudo systemctl status caas

# Iniciar
sudo systemctl start caas

# Detener
sudo systemctl stop caas

# Reiniciar
sudo systemctl restart caas

# Ver logs en tiempo real
sudo journalctl -u caas -f
```

### Actualizar la aplicación

```bash
# Detener el servicio
sudo systemctl stop caas

# Ir al directorio de la aplicación
cd /opt/caas

# Actualizar código (si usas git)
git pull

# O copiar nuevos archivos
# scp -r ./app root@YOUR_SERVER_IP:/opt/caas/

# Actualizar dependencias si es necesario
source venv/bin/activate
pip install -r requirements.txt

# Reiniciar el servicio
sudo systemctl start caas
```

## Acceso a la Aplicación

### Con Nginx (Recomendado)

- **Web Interface**: `https://your-domain.com/web`
- **API Docs**: `https://your-domain.com/api/docs`
- **Health Check**: `https://your-domain.com/api/health`

### Sin Nginx (Acceso directo)

- **Web Interface**: `http://YOUR_SERVER_IP:8000/web`
- **API Docs**: `http://YOUR_SERVER_IP:8000/api/docs`
- **Health Check**: `http://YOUR_SERVER_IP:8000/api/health`

**Nota**: Si no usas Nginx, necesitas abrir el puerto 8000:
```bash
sudo ufw allow 8000/tcp
```

## Usuarios por Defecto

Después de la instalación, hay dos usuarios de prueba:

| Usuario    | Contraseña  |
|-----------|-------------|
| admin     | Admin123!   |
| testuser  | Test123!    |

**IMPORTANTE**: Cambia estas contraseñas inmediatamente en producción.

## Seguridad en Producción

### 1. Cambiar secretos en .env

```bash
cd /opt/caas
sudo nano .env
```

Cambia:
- `JWT_SECRET`
- `MASTER_KEY_SECRET`
- `MASTER_KEY_SALT`

Genera nuevos secretos con:
```bash
openssl rand -hex 32
```

### 2. Cambiar contraseñas de usuarios

Accede a `/web`, inicia sesión y cambia las contraseñas desde la interfaz.

### 3. Deshabilitar debug mode

En `/opt/caas/.env`:
```
DEBUG=False
ENVIRONMENT=production
```

### 4. Configurar HTTPS

Si no lo hiciste durante la instalación:
```bash
sudo bash setup-nginx.sh
# Responde "y" cuando pregunte por SSL
```

### 5. Configurar backups

```bash
# Crear script de backup
sudo nano /opt/caas/backup.sh
```

Contenido:
```bash
#!/bin/bash
BACKUP_DIR="/opt/caas/backups"
mkdir -p $BACKUP_DIR
DATE=$(date +%Y%m%d_%H%M%S)
tar -czf $BACKUP_DIR/caas_backup_$DATE.tar.gz /opt/caas/data /opt/caas/.env
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete
```

Agregar a crontab:
```bash
sudo chmod +x /opt/caas/backup.sh
sudo crontab -e
```

Agregar línea:
```
0 2 * * * /opt/caas/backup.sh
```

## Solución de Problemas

### El servicio no inicia

```bash
# Ver logs de error
sudo journalctl -u caas -n 50 --no-pager

# Verificar permisos
ls -la /opt/caas

# Probar manualmente
cd /opt/caas
source venv/bin/activate
python run.py
```

### Nginx muestra 502 Bad Gateway

```bash
# Verificar que el servicio esté corriendo
sudo systemctl status caas

# Verificar que escuche en el puerto correcto
sudo netstat -tulpn | grep 8000

# Ver logs de nginx
sudo tail -f /var/log/nginx/caas_error.log
```

### No puedo acceder desde internet

```bash
# Verificar firewall
sudo ufw status

# Verificar que nginx esté corriendo
sudo systemctl status nginx

# Verificar DNS (si usas dominio)
dig your-domain.com
```

### Base de datos corrupta

```bash
cd /opt/caas
sudo systemctl stop caas

# Backup de la BD actual
cp data/caas.db data/caas.db.backup

# Recrear BD
rm data/caas.db
source venv/bin/activate
python3 -c "from app.db.session import init_db; init_db()"
python3 -c "from app.db.seed import seed_database; seed_database()"

sudo systemctl start caas
```

## Monitoreo

### Verificar uso de recursos

```bash
# CPU y memoria
htop

# Espacio en disco
df -h

# Logs del sistema
dmesg | tail
```

### Logs de la aplicación

```bash
# En tiempo real
sudo journalctl -u caas -f

# Últimas 100 líneas
sudo journalctl -u caas -n 100

# Filtrar por fecha
sudo journalctl -u caas --since "2024-01-01" --until "2024-01-31"
```

## Desinstalación

```bash
# Detener y deshabilitar servicio
sudo systemctl stop caas
sudo systemctl disable caas

# Eliminar servicio
sudo rm /etc/systemd/system/caas.service
sudo systemctl daemon-reload

# Eliminar aplicación
sudo rm -rf /opt/caas

# Eliminar configuración de nginx
sudo rm /etc/nginx/sites-available/caas
sudo rm /etc/nginx/sites-enabled/caas
sudo systemctl restart nginx

# Eliminar logs
sudo rm -rf /var/log/caas
```

## Soporte

Para problemas o preguntas:
1. Revisa los logs: `sudo journalctl -u caas -f`
2. Verifica la configuración en `/opt/caas/.env`
3. Revisa la documentación de la API en `/api/docs`
