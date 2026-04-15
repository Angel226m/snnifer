# 🔥 Network Sniffer Pro v2 - MITM REAL

**Captura, desencripta y modifica tráfico HTTP en tiempo real entre frontend-backend**

---

## 🎯 Qué hace (En el punto)

### ✅ Captura TOTAL
- **TODOS** los requests/responses entre frontend ↔ backend
- Desencriptación automática de HTTPS
- Decodificación recursiva: Base64 → URL → Hex → JSON

### ✅ Análisis de Seguridad
- Detección de datos sensibles (emails, tokens, API keys, hashes)
- Análisis de vulnerabilidades (plaintext passwords, weak tokens)
- Clasificación de tipos de encriptación (JWT RS256, HS256, Base64, etc)

### ✅ Modificación en Tránsito (MITM REAL)
- Cambia valores en JSON requests/responses en vivo
- Inyecta nuevos campos
- Remueve campos sensibles
- Todo mientras pasa por el proxy

### ✅ Análisis Profundo
- Extracta patrones de múltiples capas de encoding
- Decodifica automáticamente hasta 5 niveles de profundidad
- Cache de decodings para análisis posterior

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                      Tu Navegador/CLI                         │
│                    (curl, Postman, etc)                       │
└────────────────────────┬────────────────────────────────────┘
                         │ proxy=localhost:8080
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              mitmproxy:8080 (MITM Real)                       │
│  ┌───────────────────────────────────────────────────────┐   │
│  │  mitm_addon.py - Captura & Desencripta (opcional)    │   │
│  └───────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────┘
                         │ http request
                         ▼
┌─────────────────────────────────────────────────────────────┐
│           Sniffer App:5000 (Dashboard + Storage)              │
│  ┌───────────────────────────────────────────────────────┐   │
│  │  PayloadDecoder - Desencripta & Analiza             │   │
│  │  SecurityAnalyzer - Detecta vulnerabilidades         │   │
│  │  PayloadModifier - Modifica en tránsito              │   │
│  └───────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────┘
                         │ postgresql
                         ▼
                    [PostgreSQL]
         traffic_logs, modifications, decryption_log
```

---

## 🚀 Instalación Rápida

### Opción 1: Con mitmproxy (RECOMENDADO - MITM REAL)

```bash
# 1. Instalar mitmproxy globalmente
pip install mitmproxy

# 2. Instalar deps del sniffer
cd sniffer
pip install -r requirements.txt

# Terminal 1: Inicia el dashboard
cd sniffer && python app_new.py

# Terminal 2: Inicia mitmproxy
mitmproxy -s ../mitm_addon.py --listen-port 8080 -k

# Terminal 3: Configura tu app (export http_proxy=...)
# O en navegador: Settings → Proxy → HTTP: localhost:8080
```

### Opción 2: Solo Sniffer (proxy reverso, no MITM de HTTPS)

```bash
# Terminal 1
cd sniffer && python app_new.py

# Terminal 2: Tu app debe apuntar a:
# VITE_API_URL=http://localhost:5000/proxy
```

---

## 📊 URLs del Dashboard

Abre en navegador: **http://localhost:5000**

### Vistas Principales
- `/` - Dashboard principal (lista de tráfico capturado)
- `/api/traffic` - JSON con todo el tráfico
- `/api/sensitive-data` - Datos sensibles encontrados
- `/api/mitm-stats` - Estadísticas de MITM

### Decodificación On-Demand
```bash
# Decodificar un payload
curl -X POST http://localhost:5000/api/decode/auto \
  -H "Content-Type: application/json" \
  -d '{"payload": "aGVsbG8gd29ybGQ="}'

# Respuesta:
# {
#   "decodings": [
#     {"type": "base64", "result": "hello world", ...}
#   ],
#   "sensitive": {...},
#   "layers": 1
# }
```

---

## 🎮 Cómo Funciona el MITM Real

### Con mitmproxy + mitm_addon.py

1. **Tu navegador → mitmproxy:8080**
2. **mitmproxy desencripta HTTPS** automáticamente
3. **mitm_addon.py captura el request desencriptado**
4. **Envía al Sniffer:5000 para análisis**
5. **Sniffer almacena todo en PostgreSQL**
6. **mitm_addon.py deja pasar el request** (o lo modifica)

### Ejemplo: Modificar un Login en Tránsito

En `mitm_addon.py`, línea ~40:

```python
def request(self, flow: http.HTTPFlow) -> None:
    # ... código actual ...
    
    if "/login" in path and req_body and "password" in req_body:
        # REEMPLAZ LA CONTRASEÑA EN TRÁNSITO
        req_body["password"] = "HACKED_BY_SNIFFER"
        flow.request.text = json.dumps(req_body)
        print("🔥 Password modificado en tránsito!")
```

Resultado: El backend recibe el password modificado, el usuario ve un error de login falso.

---

## 📦 Tablas de Base de Datos

### traffic_logs
```sql
CREATE TABLE traffic_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP,
    method VARCHAR(10),          -- GET/POST/PUT/DELETE
    endpoint VARCHAR(500),        -- /api/login, /api/users, etc
    status_code INTEGER,          -- 200, 401, 500, etc
    request_body JSONB,          -- El JSON del request
    response_body TEXT,          -- El JSON del response
    request_headers JSONB,       -- Headers (Authorization, etc)
    response_headers JSONB,      -- Response headers
    execution_time_ms FLOAT,     -- Cuánto tardó
    encryption_type VARCHAR(50), -- JWT_RS256, PLAINTEXT, etc
    vulnerabilities JSONB,       -- Array de vulnerabilidades detectadas
    sensitive_data JSONB,        -- {emails: [...], tokens: [...]}
    client_ip VARCHAR(45),       -- IP del cliente
    user_agent VARCHAR(500),     -- Browser/User-Agent
    mitm_intercepted BOOLEAN,    -- Fue capturado por MITM?
    mitm_modified BOOLEAN        -- Fue modificado?
);
```

### decryption_log
```sql
CREATE TABLE decryption_log (
    id SERIAL PRIMARY KEY,
    traffic_id INTEGER,          -- FK a traffic_logs
    decoded_type VARCHAR(50),    -- 'base64', 'url_encoded', 'hex'
    depth INTEGER,               -- Nivel de desencriptación (0-5)
    decoded_value TEXT          -- El payload desencriptado
);
```

---

## 🔍 Ejemplos Prácticos

### 1. Capturar Login

```bash
# Configura proxy en navegador: localhost:8080
# Abre http://app.local/login
# Entra usuario/contraseña

# Ver qué se envió:
curl http://localhost:5000/api/traffic?limit=10

# Busca el endpoint /login:
# {
#   "method": "POST",
#   "endpoint": "/login",
#   "request_body": {"email": "user@example.com", "password": "123456"},
#   "sensitive_data": {"emails": ["user@example.com"]},
#   "vulnerabilities": [{"type": "PLAINTEXT_PASSWORD", ...}]
# }
```

### 2. Desencriptar Token Capturado

```bash
curl -X POST http://localhost:5000/api/decode/auto \
  -H "Content-Type: application/json" \
  -d '{"payload": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzcWIiOjE..."}'

# Respuesta decodifica el JWT y extrae el payload:
# {
#   "decodings": [
#     {
#       "type": "base64",
#       "result": "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
#       "depth": 0
#     }
#   ],
#   "sensitive": {"jwt_tokens": [...]}
# }
```

### 3. Modificar API Keys en Tránsito

En mitm_addon.py:

```python
def request(self, flow: http.HTTPFlow) -> None:
    if "/api/" in flow.request.path:
        # Cambiar Authorization header
        if "Authorization" in flow.request.headers:
            flow.request.headers["Authorization"] = "Bearer FAKE_TOKEN"
            print("🔥 Token modificado!")
```

---

## 🏆 Qué Detecta Automáticamente

### Patches Sensibles Extraídos
✅ Emails: `user@example.com`
✅ JWT Tokens: `eyJ...`
✅ Bearer Tokens: `Bearer abc123...`
✅ API Keys: `api_key=secret123`
✅ URLs: `https://api.example.com`
✅ IP Addresses: `192.168.1.1`
✅ Hashes: MD5, SHA1, SHA256

### Vulnerabilidades Detectadas
❌ Plaintext passwords en HTTP
❌ Base64-only tokens (sin encriptación real)
❌ JWT con algoritmo débil (HS256 simétrico)
✅ JWT RS256 (seguro)

---

## 📝 Configuración

### Variables de Entorno

```bash
export SNIFFER_DB_URL="postgresql://user:pass@db:5432/sniffer"
export BACKEND_URL="http://backend:8000"
```

---

## 🎓 Casos de Uso

1. **Seguridad**: Audita qué datos transmite tu app
2. **Testing**: Modifica responses para simular errores
3. **Debugging**: Ve exactamente qué se envía/recibe
4. **Learning**: Aprende cómo funcionan los protocolos
5. **Penetration Testing**: (Con permiso) Test vulnerabilidades

---

## ⚠️ Notas

- **Educativo**: No uses para actividades ilegales
- **HTTPS**: mitmproxy puede desencriptar HTTPS en tu máquina
- **Performance**: No recomendado para producción
- **Database**: Necesita PostgreSQL corriendo

---

## 🐛 Troubleshooting

### mitmproxy no captura HTTPS
```bash
# Asegúrate de usar -k (kiss = aceptar certificados autofirmados)
mitmproxy -s mitm_addon.py --listen-port 8080 -k
```

### Dashboard vacío
```bash
# Revisa que el proxy está apuntando a :8080
# En navegador: Configure proxy → HTTP Proxy Host: 127.0.0.1 Puerto: 8080
```

### PostgreSQL connection error
```bash
# Revisa variable SNIFFER_DB_URL
echo $SNIFFER_DB_URL
# Debe ser: postgresql://postgres:password@db:5432/learnwithgaray
```

---

**Made with 🔥 for network analysis**
