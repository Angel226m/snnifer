# 📡 Network Sniffer v3 - Guía de Uso

## ¿Qué es el Sniffer Mejorado?

El **Network Sniffer v3** es un dashboard que **captura y visualiza todos los datos** que se envían entre tu aplicación frontend (Svelte) y backend (FastAPI).

### ✨ Características

✅ **Captura automática** - Detecta todos los requests/responses sin configuración extra  
✅ **Análisis de riesgos** - Identifica contraseñas, emails, API keys, tokens automáticamente  
✅ **Visualización JSON** - Muestra los datos exactos que se están enviando  
✅ **Interfaz Wireshark-like** - Dashboard profesional en tiempo real  
✅ **Filtros avanzados** - Busca por endpoint y nivel de riesgo  
✅ **Datos sensibles resaltados** - 🔐 Contraseñas, 📧 Emails, 📱 Teléfono destacados  

---

## 🚀 Cómo Iniciar

### Opción 1: Usar la app mejorada (RECOMENDADO)

```bash
cd c:\Users\angel\Desktop\learnWithGaray\sniffer
python app_improved.py
```

Abre el navegador en: **http://localhost:5000**

### Opción 2: Integración con Docker (si está en contenedor)

```bash
docker compose up -d
# El sniffer estará en http://localhost:5000
```

---

## 📊 Interfaz del Dashboard

### **1. Barra Superior (Top Bar)**

```
┌─────────────────────────────────────────────────────────────┐
│ 📡 Network Sniffer v3 │ 0 Paq │ ⛔ 0 Crítico │ 🟠 0 Alto │
└─────────────────────────────────────────────────────────────┘
```

- **Estadísticas en vivo** de paquetes capturados
- **Indicador de estado** (verde = en línea)
- **Botones de control**: Actualizar, Limpiar datos

### **2. Panel Izquierdo - Lista de Paquetes**

```
┌─────────────────────────┐
│ 🔍 Filtro de endpoint   │
│ SELECT Nivel de riesgo  │
├─────────────────────────┤
│ POST /api/clients  06:45│   ← Selecciona un paquete
│ GET  /dashboard    06:46│
│ POST /auth/login   06:47│
└─────────────────────────┘
```

- **POST, GET, PUT, DELETE** con colores diferentes
- **⛔ CRÍTICO** (rojo) = Contraseñas/API keys
- **🟠 ALTO** = Datos sensibles
- **🟡 MEDIO** = Información potencialmente riesgosa
- **🟢 BAJO** = Datos no sensitivos

### **3. Panel Derecho - Detalles del Paquete**

Cuando selecciones un paquete, verás:

#### **a) Metadata**
```
Timestamp: 15/04/2026 06:45:30
Tamaño: 137 bytes
Riesgo: CRÍTICO
Dirección: REQUEST
```

#### **b) Datos JSON Capturados (Lo más importante)**
```json
{
  "name": "Carlos",
  "surname": "Carlos Segundo",
  "age": 15,
  "dni": "19156131",
  "phone": "899898784",
  "email": "angel@gmail.com",
  "address": "mi jato2"
}
```

#### **c) Datos Sensibles Detectados**
```
⚠️ DATOS SENSIBLES DETECTADOS
🔐 Contraseñas: [mostradas]
📧 Email: angel@gmail.com
📱 Teléfono: 899898784
```

---

## 🎯 Casos de Uso

### **Caso 1: Cliente envía datos personales**

1. Abre el dashboard en http://localhost:5000
2. Haz clic en **"Agregar Cliente"** en tu app Svelte
3. Llena el formulario y haz clic en **Guardar**
4. **El sniffer capturará automáticamente**:
   - El JSON enviado
   - Todos los campos
   - Nivel de riesgo
   - Lo que está en plaintext (sin encripción)

### **Caso 2: Login con contraseña**

1. En tu app, ve a login
2. Ingresa contraseña: `mi_contraseña_secreto`
3. **El sniffer verá**:
   - 🔴 **CRÍTICO** (rojo)
   - 🔐 **Contraseña detectada**: `mi_contraseña_secreto`
   - Aviso de estar en plaintext

### **Caso 3: Filtrar datos sensibles**

1. Haz clic en **SELECT "⛔ Crítico"**
2. Solo se muestran los paquetes con datos sensibles
3. Perfecto para **auditoría de seguridad**

---

## 🔐 Qué se Detecta Automáticamente

### **1. Contraseñas**
```json
{"password": "mi_clave"}  ← DETECTADO
```

### **2. Emails**
```json
{"email": "usuario@ejemplo.com"}  ← DETECTADO
```

### **3. Teléfonos**
```
Formatos: 123-456-7890, (123) 456-7890, etc.
```

### **4. API Keys & Tokens**
```json
{"api_key": "sk_live_xxxx"}  ← DETECTADO
{"token": "eyJhbGc..."}      ← JWT DETECTADO
```

### **5. Números de Documento**
```json
{"dni": "19156131"}  ← DETECTADO
```

---

## 🛠️ API Endpoints

Si quieres integrar el sniffer de forma manual:

### **GET /api/packets**
Obtiene todos los paquetes capturados como JSON:
```json
{
  "success": true,
  "count": 5,
  "packets": [
    {
      "id": 1,
      "method": "POST",
      "endpoint": "/api/clients",
      "payload": {...},
      "risk_level": "CRÍTICO",
      "sensitive_data": {...}
    }
  ]
}
```

### **POST /api/packets/clear**
Elimina todos los paquetes:
```bash
curl -X POST http://localhost:5000/api/packets/clear
```

### **GET /api/stats**
Obtiene estadísticas:
```json
{
  "total_packets": 10,
  "critical": 2,
  "high": 3,
  "total_requests": 8
}
```

### **GET /api/stream** (SSE)
Streaming en tiempo real:
```javascript
const es = new EventSource('/api/stream');
es.onmessage = (event) => {
    const packet = JSON.parse(event.data);
    console.log('Nuevo paquete capturado:', packet);
};
```

---

## 📝 Fórmula de Riesgo

El sistema calcula el riesgo así:

```python
RIESGO = 0

if "password" en datos:
    RIESGO += 100

if email detectado:
    RIESGO += 30

if api_key o token:
    RIESGO += 50

if teléfono o DNI:
    RIESGO += 40

# Entonces:
if RIESGO >= 100:
    Nivel = "CRÍTICO" 🔴
elif RIESGO >= 50:
    Nivel = "ALTO" 🟠
elif RIESGO >= 20:
    Nivel = "MEDIO" 🟡
else:
    Nivel = "BAJO" 🟢
```

---

## 🎓 Ejemplo Educativo

### **Escenario: Usuario crea una cuenta**

#### Paso 1: Usuario llena el formulario
```
Nombre: Juan
Email: juan@ejemplo.com
Teléfono: 555-123-4567
Password: mi_secreto123
```

#### Paso 2: Se envía al backend
El sniffer ve en **tiempo real**:

```
POST /auth/register
⛔ CRÍTICO - 137 bytes

📊 DATOS JSON CAPTURADOS:
{
  "name": "Juan",
  "email": "juan@ejemplo.com",
  "phone": "555-123-4567",
  "password": "mi_secreto123"
}

⚠️ DATOS SENSIBLES DETECTADOS
🔐 Contraseña: mi_secreto123
📧 Email: juan@ejemplo.com  
📱 Teléfono: 555-123-4567
```

#### Paso 3: Aprendizaje
**¿Por qué es CRÍTICO?**
- La contraseña está en **plaintext** (sin encripción)
- Si alguien intercepta el tráfico, ve todo
- **Solución**: Usar HTTPS + Hash contraseña en backend

---

## ⚙️ Configuración Avanzada

### **Cambiar puerto del sniffer**

En `app_improved.py`, línea final:
```python
app.run(
    host='0.0.0.0',
    port=5001,  # ← Cambiar a 5001, 8080, etc.
    debug=False,
    threaded=True
)
```

### **Cambiar límite de paquetes guardados**

En `app_improved.py`, línea ~200:
```python
packet_manager = PacketManager(max_packets=1000)  # ← Aumentar de 500 a 1000
```

### **Agregar más capturas sensibles**

En la clase `DataAnalyzer`, método `extract_sensitive_data()`:
```python
# Ejemplo: Detectar tarjetas de crédito
cc_pattern = r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
sensitive['credit_cards'] = re.findall(cc_pattern, data_str)
```

---

## 🐛 Troubleshooting

### **Problema: "No se capturan paquetes"**

**Solución 1**: Verifica que el sniffer esté corriendo
```bash
# En otra terminal
python app_improved.py
# Debe decir: "🚀 Sniffer v3 - Dashboard mejorado iniciando..."
```

**Solución 2**: Si la app está en Docker, el sniffer debe estar en el mismo contenedor o conectado por red
```bash
# En docker-compose.yml, asegúrate que el sniffer está activado
```

**Solución 3**: Verifica que la URL del backend sea correcta
```python
BACKEND_URL = os.getenv('BACKEND_URL', 'http://backend:8000')
```

### **Problema: "Error al conectar a la base de datos"**

La versión mejorada `app_improved.py` **NO requiere PostgreSQL** - funciona solo con memoria.

Si quieres guardar en BD:
```python
# Descomenta la integración con PostgreSQL (opcional)
# Ver sección DATABASE en el código
```

---

## 📚 Archivos Relacionados

| Archivo | Propósito |
|---------|-----------|
| `app_improved.py` | **↑ USA ESTE** - Sniffer mejorado |
| `dashboard_improved.html` | **↑ USA ESTE** - Dashboard moderno |
| `app.py` | Versión antigua (deprecated) |
| `app_new.py` | Versión intermedia (deprecated) |

---

## 🎯 Resumen

**El sniffer mejorado es tu herramienta educativa para**:

1. ✅ **Ver exactamente** qué datos se envían entre frontend-backend
2. ✅ **Identificar riesgos** automáticamente (contraseñas, datos sensibles)
3. ✅ **Aprender seguridad** viendo datos en plaintext
4. ✅ **Auditar tu app** en desarrollo sin producción
5. ✅ **Entender flujo de datos** en tiempo real

---

## 🚀 Para Empezar AHORA

```bash
cd c:\Users\angel\Desktop\learnWithGaray\sniffer
python app_improved.py
# Abre: http://localhost:5000
# Usa tu app Svelte y ve los datos capturados en tiempo real
```

¡Listo! Tu sniffer está funcionando. 🎉
