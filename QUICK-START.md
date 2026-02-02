# Quick Start - Deploy to Ubuntu Server

## TL;DR

```bash
# En tu máquina local
cd "C:\Users\maria\Desktop\unir\TFM\Codigo"
tar -czf caas.tar.gz *
scp caas.tar.gz root@YOUR_SERVER_IP:/root/

# En el servidor
ssh root@YOUR_SERVER_IP
mkdir caas && cd caas
tar -xzf ../caas.tar.gz
chmod +x *.sh
sudo bash deploy.sh
```

Eso es todo! El script te guiará paso a paso.

## Qué hace el script?

1. Instala Python 3, Nginx, UFW y dependencias
2. Crea un virtualenv e instala paquetes Python
3. Genera secretos seguros aleatorios
4. Inicializa la base de datos SQLite
5. Crea usuarios de prueba (admin/Admin123!, testuser/Test123!)
6. Configura systemd para que corra como demonio
7. Configura firewall (SSH, HTTP, HTTPS)
8. (Opcional) Configura Nginx con SSL/Let's Encrypt

## Después del despliegue

### Acceder a la aplicación

Con Nginx:
- Web: `https://tu-dominio.com/web`
- API Docs: `https://tu-dominio.com/api/docs`

Sin Nginx:
- Web: `http://SERVER_IP:8000/web`
- API Docs: `http://SERVER_IP:8000/api/docs`

### Comandos útiles

```bash
# Ver estado del servicio
sudo systemctl status caas

# Reiniciar servicio
sudo systemctl restart caas

# Ver logs en tiempo real
sudo journalctl -u caas -f

# Ver logs de acceso
sudo tail -f /var/log/caas/access.log

# Ver logs de error
sudo tail -f /var/log/caas/error.log
```

### Seguridad IMPORTANTE

1. **Cambiar contraseñas**: Inicia sesión y cambia las contraseñas de admin y testuser
2. **Configurar HTTPS**: Si no lo hiciste durante instalación, ejecuta `sudo bash setup-nginx.sh`
3. **Secretos**: Los secretos en `/opt/caas/.env` fueron generados aleatoriamente, pero revísalos

## Solución rápida de problemas

### El servicio no inicia
```bash
sudo journalctl -u caas -n 50
```

### No puedo acceder desde internet
```bash
# Verificar firewall
sudo ufw status

# Si no usas Nginx, abre puerto 8000
sudo ufw allow 8000/tcp
```

### Nginx muestra 502
```bash
# Verificar que el servicio esté corriendo
sudo systemctl status caas
```

## Más información

Lee [DEPLOYMENT.md](DEPLOYMENT.md) para la guía completa.
