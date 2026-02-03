# Guía de Despliegue en Producción - DigitalOcean

**Servidor**: Ubuntu 22.04 LTS
**IP**: 68.183.174.203
**Fecha**: Febrero 2026

---

## Paso 1: Preparar el Servidor

### 1.1 Conectarse al servidor
```bash
ssh root@68.183.174.203
```

### 1.2 Actualizar el sistema (si es necesario)
```bash
apt update && apt upgrade -y
```

---

## Paso 2: Transferir los Archivos

### Opción A: Usando SCP (desde tu máquina local)
```bash
# Desde tu máquina Windows (PowerShell)
cd C:\Users\maria\Desktop\unir\TFM\Codigo

# Crear tar del proyecto (excluir archivos innecesarios)
tar -czf caas.tar.gz --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' --exclude='venv' --exclude='data' --exclude='logs' .

# Transferir al servidor
scp caas.tar.gz root@68.183.174.203:/tmp/
```

### Opción B: Usando Git (si tienes repositorio)
```bash
# En el servidor
cd /tmp
git clone <tu-repositorio-url> caas
```

---

## Paso 3: Desplegar en el Servidor

### 3.1 Conectarse al servidor
```bash
ssh root@68.183.174.203
```

### 3.2 Preparar los archivos
```bash
# Si usaste SCP:
cd /tmp
tar -xzf caas.tar.gz -C /tmp/caas-deploy
cd /tmp/caas-deploy

# Si usaste Git:
cd /tmp/caas
```

### 3.3 Ejecutar el script de despliegue
```bash
# Dar permisos de ejecución
chmod +x *.sh

# Ejecutar deploy completo
sudo bash deploy.sh
```

El script te preguntará:
1. **Confirmación inicial**: Presiona `y` para continuar
2. **Setup de Nginx**:
   - Si tienes un dominio: Presiona `y` e ingresa tu dominio
   - Si solo usas IP: Presiona `n` (usarás http://68.183.174.203:8000)

---

## Paso 4: Verificación Post-Despliegue

### 4.1 Verificar que el servicio esté corriendo
```bash
sudo systemctl status caas
```

Deberías ver: `Active: active (running)`

### 4.2 Ver los logs en tiempo real
```bash
sudo journalctl -u caas -f
```

### 4.3 Verificar el firewall
```bash
sudo ufw status
```

Deberías ver:
- Puerto 22 (SSH) - ALLOW
- Puerto 8000 (si no usas nginx) - ALLOW
- Puerto 80/443 (si usas nginx) - ALLOW

### 4.4 Probar la API
```bash
# Desde el servidor
curl http://localhost:8000/api/health

# Desde tu navegador
http://68.183.174.203:8000/web
http://68.183.174.203:8000/api/docs
```

---

## Paso 5: Configuración Adicional (Opcional pero Recomendado)

### 5.1 Configurar Nginx con SSL (Let's Encrypt)
Si tienes un dominio apuntando a 68.183.174.203:
```bash
cd /opt/caas
sudo bash setup-nginx.sh
# Ingresa tu dominio (ej: caas.tudominio.com)
# Responde 'y' para configurar SSL
# Ingresa tu email para Let's Encrypt
```

### 5.2 Cambiar contraseñas por defecto
```bash
# Acceder a la interfaz web
http://68.183.174.203:8000/web

# Login con usuarios por defecto:
# Usuario: admin    Contraseña: Admin123!
# Usuario: testuser Contraseña: Test123!

# IMPORTANTE: Cambiar las contraseñas inmediatamente
```

### 5.3 Configurar backups automáticos
```bash
# Crear script de backup
cat > /opt/caas/backup.sh <<'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/caas"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR
cp /opt/caas/data/caas.db $BACKUP_DIR/caas_$DATE.db
# Mantener solo los últimos 7 backups
find $BACKUP_DIR -name "caas_*.db" -mtime +7 -delete
EOF

chmod +x /opt/caas/backup.sh

# Agregar a crontab (backup diario a las 2 AM)
echo "0 2 * * * /opt/caas/backup.sh" | sudo crontab -
```

---

## Comandos Útiles

### Gestión del Servicio
```bash
# Ver estado
sudo systemctl status caas

# Reiniciar
sudo systemctl restart caas

# Detener
sudo systemctl stop caas

# Iniciar
sudo systemctl start caas

# Ver logs
sudo journalctl -u caas -f

# Ver últimos 100 logs
sudo journalctl -u caas -n 100
```

### Nginx (si está configurado)
```bash
# Ver estado
sudo systemctl status nginx

# Reiniciar
sudo systemctl restart nginx

# Ver logs de acceso
sudo tail -f /var/log/nginx/caas_access.log

# Ver logs de error
sudo tail -f /var/log/nginx/caas_error.log
```

### Base de Datos
```bash
# Ver base de datos
sqlite3 /opt/caas/data/caas.db

# Backup manual
cp /opt/caas/data/caas.db /opt/caas/data/caas_backup_$(date +%Y%m%d).db
```

---

## Solución de Problemas

### El servicio no inicia
```bash
# Ver logs detallados
sudo journalctl -u caas -xe

# Verificar que el virtual environment existe
ls -la /opt/caas/venv

# Verificar permisos
ls -la /opt/caas

# Verificar configuración
cat /opt/caas/.env
```

### Error de puerto en uso
```bash
# Ver qué está usando el puerto 8000
sudo lsof -i :8000

# Matar proceso si es necesario
sudo kill -9 <PID>
```

### Problemas de firewall
```bash
# Verificar reglas
sudo ufw status numbered

# Agregar regla si falta
sudo ufw allow 8000/tcp
sudo ufw reload
```

---

## Información de la Instalación

### Ubicaciones Importantes
- **Aplicación**: `/opt/caas`
- **Virtual Environment**: `/opt/caas/venv`
- **Base de Datos**: `/opt/caas/data/caas.db`
- **Logs de aplicación**: `/opt/caas/logs/app.log`
- **Logs del sistema**: `/var/log/caas/`
- **Configuración**: `/opt/caas/.env`
- **Servicio systemd**: `/etc/systemd/system/caas.service`
- **Nginx config**: `/etc/nginx/sites-available/caas` (si está configurado)

### Usuarios por Defecto
- **admin** / Admin123!
- **testuser** / Test123!

**⚠️ IMPORTANTE**: Cambiar estas contraseñas inmediatamente en producción.

---

## Seguridad en Producción

### Checklist de Seguridad
- [ ] Cambiar contraseñas por defecto
- [ ] Configurar HTTPS/SSL con Let's Encrypt
- [ ] Configurar firewall correctamente
- [ ] Configurar backups automáticos
- [ ] Revisar y fortalecer el archivo `.env`
- [ ] Habilitar monitoreo de logs
- [ ] Actualizar el sistema regularmente
- [ ] Configurar fail2ban (opcional)
- [ ] Limitar acceso SSH con llaves públicas
- [ ] Configurar logrotate para los logs

### Fortalecer SSH
```bash
# Deshabilitar login de root (después de crear otro usuario)
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
sudo systemctl restart sshd
```

---

## URLs de Acceso

### Sin Nginx (acceso directo)
- Web: http://68.183.174.203:8000/web
- API Docs: http://68.183.174.203:8000/api/docs
- Health Check: http://68.183.174.203:8000/api/health

### Con Nginx + Dominio
- Web: https://tudominio.com/web
- API Docs: https://tudominio.com/api/docs
- Health Check: https://tudominio.com/api/health

---

## Soporte

Para problemas o preguntas:
1. Revisar los logs: `sudo journalctl -u caas -f`
2. Verificar el estado: `sudo systemctl status caas`
3. Revisar la documentación en `/opt/caas/README.md`
