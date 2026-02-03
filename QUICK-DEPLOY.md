# Despliegue Rápido - CaaS en Producción

**Servidor**: 68.183.174.203 (Ubuntu 22.04)

---

## Método 1: Usando el Script PowerShell (Recomendado)

### Desde Windows (tu máquina):
```powershell
# 1. Abrir PowerShell en el directorio del proyecto
cd C:\Users\maria\Desktop\unir\TFM\Codigo

# 2. Ejecutar el script de transferencia
.\transfer-to-server.ps1
```

### En el servidor (después de la transferencia):
```bash
# 1. Conectar al servidor
ssh root@68.183.174.203

# 2. Preparar archivos
cd /tmp
mkdir -p caas-deploy
tar -xzf caas.tar.gz -C caas-deploy
cd caas-deploy

# 3. Dar permisos y ejecutar deploy
chmod +x *.sh
sudo bash deploy.sh

# El script te preguntará:
# - Confirmación: presiona 'y'
# - Nginx setup: presiona 'n' (o 'y' si tienes dominio)
```

---

## Método 2: Manual con SCP

### Desde Windows:
```powershell
# 1. Crear archivo tar
cd C:\Users\maria\Desktop\unir\TFM\Codigo
tar -czf caas.tar.gz --exclude=.git --exclude=__pycache__ --exclude=venv --exclude=data --exclude=logs .

# 2. Transferir al servidor
scp caas.tar.gz root@68.183.174.203:/tmp/
```

### En el servidor:
```bash
# Igual que el método 1 (pasos 2 y 3)
```

---

## Verificación Post-Despliegue

### 1. Verificar servicio
```bash
sudo systemctl status caas
```
Debe mostrar: `Active: active (running)`

### 2. Probar en el navegador
- Web: http://68.183.174.203:8000/web
- API Docs: http://68.183.174.203:8000/api/docs

### 3. Login con usuarios por defecto
- Usuario: `admin` / Contraseña: `Admin123!`
- Usuario: `testuser` / Contraseña: `Test123!`

**⚠️ IMPORTANTE**: Cambiar las contraseñas inmediatamente

---

## Comandos Útiles

```bash
# Ver logs en tiempo real
sudo journalctl -u caas -f

# Reiniciar servicio
sudo systemctl restart caas

# Ver estado
sudo systemctl status caas

# Detener servicio
sudo systemctl stop caas
```

---

## Si algo falla

### Ver logs detallados
```bash
sudo journalctl -u caas -xe
```

### Ver qué está usando el puerto 8000
```bash
sudo lsof -i :8000
```

### Verificar firewall
```bash
sudo ufw status
# Debe mostrar puerto 8000 permitido
```

---

## Notas Importantes

1. **Firewall**: El script configura automáticamente UFW para permitir SSH (22) y el puerto 8000
2. **Base de datos**: Se crea automáticamente con usuarios de prueba
3. **Nginx**: Opcional - solo si tienes un dominio configurado
4. **SSL**: Solo se puede configurar si tienes un dominio apuntando al servidor

---

## Ubicaciones en el Servidor

- Aplicación: `/opt/caas`
- Base de datos: `/opt/caas/data/caas.db`
- Logs: `/opt/caas/logs/app.log`
- Configuración: `/opt/caas/.env`
- Servicio: `/etc/systemd/system/caas.service`

---

## ¿Necesitas más detalles?

Consulta el archivo `DEPLOY-PRODUCTION.md` para instrucciones detalladas.
