# CaaS Prototype - Crypto as a Service

Prototipo funcional de un proveedor de servicios criptográficos bajo el modelo Crypto as a Service (CaaS). Este sistema expone operaciones criptográficas a través de una API REST con FastAPI.

## Características

- **Cifrado Simétrico**: AES-256 (GCM y CBC)
- **Hashing**: SHA-256, SHA-384, SHA-512
- **Firmas Digitales**: RSA (PSS, PKCS#1) y ECC (ECDSA)
- **Gestión Segura de Claves**: Almacenamiento cifrado con master key
- **Autenticación JWT**: Tokens de acceso y refresh
- **Auditoría Completa**: Registro de todas las operaciones
- **API REST**: Documentación Swagger/OpenAPI automática

## Tecnologías

- Python 3.10+
- FastAPI
- SQLAlchemy + SQLite
- Cryptography library
- PyJWT
- Docker

## Instalación

### Requisitos Previos

- Python 3.10 o superior
- pip (gestor de paquetes de Python)
- Opcional: Docker para contenedores

### Instalación Local

1. **Clonar o descargar el proyecto**

2. **Crear entorno virtual (recomendado)**

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

3. **Instalar dependencias**

```bash
pip install -r requirements.txt
```

4. **Configurar variables de entorno**

El archivo `.env` ya está creado con valores de desarrollo. Para producción, modifica los secretos:

```env
JWT_SECRET=tu-secreto-jwt-para-produccion
MASTER_KEY_SECRET=tu-master-key-secreto-para-produccion
MASTER_KEY_SALT=tu-salt-aleatorio
```

5. **Inicializar base de datos y usuarios de prueba**

```bash
python app/db/seed.py
```

Esto creará usuarios de prueba:
- Usuario: `admin` | Password: `Admin123!`
- Usuario: `testuser` | Password: `Test123!`
- Usuario: `demo` | Password: `Demo123!`

6. **Ejecutar la aplicación**

```bash
python run.py
```

La API estará disponible en: `http://localhost:8000`

## Instalación con Docker

1. **Construir imagen**

```bash
docker build -t caas-prototype .
```

2. **Ejecutar contenedor**

```bash
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  --name caas \
  caas-prototype
```

3. **Inicializar usuarios (primera vez)**

```bash
docker exec -it caas python app/db/seed.py
```

## Uso de la API

### Documentación Interactiva

Una vez iniciada la aplicación, accede a:

- **Swagger UI**: http://localhost:8000/api/docs
- **ReDoc**: http://localhost:8000/api/redoc

### Ejemplos de Uso

#### 1. Autenticación

```bash
# Obtener token de acceso
curl -X POST http://localhost:8000/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "Admin123!"
  }'

# Respuesta:
# {
#   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
#   "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
#   "token_type": "Bearer",
#   "expires_in": 1800
# }
```

**Nota**: Usa el `access_token` en todas las peticiones posteriores.

#### 2. Crear Clave Simétrica

```bash
curl -X POST http://localhost:8000/api/keys \
  -H "Authorization: Bearer TU_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_name": "mi-clave-aes",
    "key_type": "symmetric",
    "algorithm": "AES-256",
    "expires_in_days": 365
  }'

# Respuesta:
# {
#   "key_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
#   "key_name": "mi-clave-aes",
#   "key_type": "symmetric",
#   "algorithm": "AES-256",
#   ...
# }
```

Guarda el `key_id` para usarlo en operaciones de cifrado.

#### 3. Cifrar Datos

```bash
curl -X POST http://localhost:8000/api/crypto/encrypt \
  -H "Authorization: Bearer TU_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "plaintext": "Mensaje secreto",
    "mode": "GCM",
    "encoding": "base64"
  }'

# Respuesta:
# {
#   "ciphertext": "base64_encoded_ciphertext",
#   "iv": "base64_encoded_iv",
#   "mode": "GCM",
#   "tag": "base64_encoded_tag",
#   "algorithm": "AES-256",
#   "key_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
# }
```

#### 4. Descifrar Datos

```bash
curl -X POST http://localhost:8000/api/crypto/decrypt \
  -H "Authorization: Bearer TU_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "ciphertext": "base64_encoded_ciphertext",
    "iv": "base64_encoded_iv",
    "mode": "GCM",
    "tag": "base64_encoded_tag"
  }'

# Respuesta:
# {
#   "plaintext": "Mensaje secreto"
# }
```

#### 5. Generar Hash

```bash
curl -X POST http://localhost:8000/api/crypto/hash \
  -H "Authorization: Bearer TU_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": "Datos a hashear",
    "algorithm": "SHA-256",
    "return_format": "hex"
  }'

# Respuesta:
# {
#   "hash": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
#   "algorithm": "SHA-256"
# }
```

#### 6. Crear Par de Claves RSA y Firmar

```bash
# Crear par de claves RSA
curl -X POST http://localhost:8000/api/keys \
  -H "Authorization: Bearer TU_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_name": "mi-clave-rsa",
    "key_type": "rsa_private",
    "algorithm": "RSA-2048"
  }'

# Respuesta incluye:
# {
#   "key_id": "private-key-uuid",
#   "metadata": {
#     "public_key_id": "public-key-uuid"
#   }
# }

# Firmar datos con clave privada
curl -X POST http://localhost:8000/api/crypto/sign \
  -H "Authorization: Bearer TU_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "private-key-uuid",
    "data": "Documento importante",
    "algorithm": "RSA-PSS",
    "hash_algorithm": "SHA-256"
  }'

# Verificar firma con clave pública
curl -X POST http://localhost:8000/api/crypto/verify \
  -H "Authorization: Bearer TU_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "public-key-uuid",
    "data": "Documento importante",
    "signature": "base64_encoded_signature",
    "algorithm": "RSA-PSS",
    "hash_algorithm": "SHA-256"
  }'

# Respuesta:
# {
#   "verified": true
# }
```

#### 7. Consultar Logs de Auditoría

```bash
curl -X GET "http://localhost:8000/api/audit/logs?page=1&limit=10" \
  -H "Authorization: Bearer TU_ACCESS_TOKEN"

# Respuesta:
# {
#   "logs": [
#     {
#       "id": 1,
#       "timestamp": "2026-02-01T10:30:00Z",
#       "username": "admin",
#       "operation": "encrypt",
#       "status": "success",
#       ...
#     }
#   ],
#   "total": 5,
#   "page": 1,
#   "limit": 10
# }
```

## Estructura del Proyecto

```
├── app/
│   ├── main.py                  # Aplicación FastAPI principal
│   ├── config.py                # Configuración
│   ├── dependencies.py          # Dependencias FastAPI
│   ├── api/v1/endpoints/        # Endpoints REST
│   ├── core/                    # Lógica de negocio
│   │   ├── auth/               # Autenticación JWT
│   │   ├── crypto/             # Operaciones criptográficas
│   │   ├── kms/                # Gestión de claves
│   │   └── audit/              # Auditoría
│   ├── models/                  # Modelos Pydantic y SQLAlchemy
│   ├── db/                      # Base de datos
│   └── utils/                   # Utilidades
├── tests/                       # Tests
├── data/                        # Base de datos SQLite
├── logs/                        # Logs de aplicación
├── Dockerfile                   # Contenedor Docker
├── docker-compose.yml           # Orquestación Docker
├── requirements.txt             # Dependencias Python
├── .env                         # Variables de entorno
├── run.py                       # Script de ejecución
└── README.md                    # Este archivo
```

## Casos de Prueba Implementados

El prototipo incluye todos los casos de prueba especificados:

1. ✅ Autenticación exitosa y obtención de token JWT
2. ✅ Rechazo de solicitudes sin token válido
3. ✅ Cifrado de texto con AES-256 y descifrado exitoso
4. ✅ Verificación de que datos cifrados no son legibles sin clave
5. ✅ Generación de hash SHA-256 consistente
6. ✅ Detección de alteración de datos mediante verificación de hash
7. ✅ Firma digital y verificación exitosa
8. ✅ Detección de firma inválida cuando datos son modificados
9. ✅ Creación, listado y eliminación de claves
10. ✅ Registro de operaciones en log de auditoría

## Seguridad

### Consideraciones de Seguridad

- **Claves en Reposo**: Todas las claves se almacenan cifradas con AES-256-GCM usando una master key derivada con PBKDF2
- **Comunicación**: Se recomienda usar HTTPS en producción
- **Secretos**: NUNCA commitear `.env` con secretos reales al control de versiones
- **Master Key**: Usar secretos diferentes para desarrollo y producción
- **JWT**: Rotar secretos periódicamente
- **Rate Limiting**: Límites configurables por endpoint
- **Logs**: No se registran datos sensibles (plaintexts, claves, tokens completos)

## Solución de Problemas

### Error: "Python no encontrado"

Si recibes este error en Windows, instala Python desde [python.org](https://www.python.org/downloads/) o Microsoft Store.

### Error: "Module not found"

Asegúrate de haber instalado las dependencias:
```bash
pip install -r requirements.txt
```

### Error de base de datos

Elimina la base de datos y reinicializa:
```bash
rm data/caas.db
python app/db/seed.py
```

### Puerto 8000 en uso

Cambia el puerto en `.env`:
```env
PORT=8001
```

## Licencia

Proyecto académico para demostración del concepto CaaS.

## Contacto

Para preguntas o issues relacionados con el prototipo, consulta la documentación o contacta al administrador del proyecto.

---

**Nota**: Este es un prototipo académico. Para uso en producción, se recomienda:
- Implementar HSM (Hardware Security Module) para claves críticas
- Usar base de datos empresarial (PostgreSQL, MySQL)
- Configurar TLS/SSL con certificados válidos
- Implementar logging centralizado
- Añadir monitoreo y alertas
- Realizar auditorías de seguridad regulares
- Implementar backup y recuperación de desastres
