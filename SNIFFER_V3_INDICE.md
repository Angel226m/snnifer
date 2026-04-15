# 📡 Network Sniffer v3 - Índice de Archivos

## 📁 Estructura Aditiva

Tu proyecto ahora tiene:

```
c:\Users\angel\Desktop\learnWithGaray\

├── START_SNIFFER.md                     ⭐ Empieza aquí (30 secs)
├── SNIFFER_V3_RESUMEN.md                📊 Qué se hizo (5 mins)
├── SNIFFER_V3_GUIA.md                   📚 Guía completa (15 mins)
│
├── sniffer/
│   │
│   ├── app_improved.py                  ⭐⭐⭐ APP MEJORADA
│   │   └── 400 líneas
│   │   ├── Clase DataAnalyzer (80 líneas)
│   │   │   ├── Detecta contraseñas ✓
│   │   │   ├── Detecta emails ✓
│   │   │   ├── Detecta teléfonos ✓
│   │   │   ├── Detecta API keys ✓
│   │   │   ├── Detecta tokens JWT ✓
│   │   │   └── Calcula riesgo automático ✓
│   │   │
│   │   ├── Clase PacketManager (100 líneas)
│   │   │   ├── Almacena en memoria (500 paquetes máx)
│   │   │   ├── add_packet() ✓
│   │   │   ├── get_all() ✓
│   │   │   ├── get_stats() ✓
│   │   │   └── clear() ✓
│   │   │
│   │   ├── Middleware de Captura (80 líneas)
│   │   │   ├── @before_request → captura POST/PUT
│   │   │   └── @after_request → captura responses
│   │   │
│   │   └── API REST (100 líneas)
│   │       ├── GET  /                    Dashboard HTML
│   │       ├── GET  /api/packets          JSON de todos
│   │       ├── GET  /api/packets/<id>    Detalles específico
│   │       ├── GET  /api/stats            Estadísticas
│   │       ├── GET  /api/stream           SSE streaming
│   │       ├── POST /api/packets/clear   Limpiar datos
│   │       └── POST /api/test-capture    Endpoint de test
│   │
│   ├── templates/
│   │   └── dashboard_improved.html       ⭐⭐⭐ DASHBOARD MODERNO
│   │       └── 750 líneas HTML + CSS + JS
│   │       ├── Diseño Wireshark-like
│   │       ├── Tema oscuro profesional
│   │       ├── Panel izquierdo (lista paquetes)
│   │       ├── Panel derecho (detalles)
│   │       ├── Filtros en tiempo real
│   │       ├── Color-coding automático
│   │       ├── Datos sensibles resaltados
│   │       ├── Auto-refresh cada 2 segundos
│   │       └── Responsive design
│   │
│   ├── app.py                            ⚠️ Antiguo
│   ├── app_new.py                        ⚠️ Antiguo
│   └── requirements.txt                  ✓ Sin cambios
│
├── [Otros archivos sin cambios]
```

---

## 🎯 Rutas Principales

### **Dashboard (lo qué usarás)**
```
GET http://localhost:5000/
→ dashboard_improved.html
```

### **APIs (para integración)**
```
GET  /api/packets
GET  /api/packets/<id>
POST /api/packets/clear
GET  /api/stats
GET  /api/stream          (Server-Sent Events)
```

---

## 📊 Comparación: Antes vs Después

### **ANTES (Versiones antiguas)**
```
app.py / app_new.py
├─ Captura basada en logs
├─ Requiere PostgreSQL
├─ Dashboard HTML básico
├─ Difícil de entender datos
└─ Sin análisis automático
```

### **DESPUÉS (v3 Mejorada)**
```
app_improved.py ✨
├─ Captura con middleware automático
├─ SIN base de datos requerida
├─ Dashboard Wireshark-like moderno
├─ Datos sensibles detectados automáticamente
├─ Risk scoring en tiempo real
└─ Interfaz intuitiva y visual
```

---

## 🔄 Flujo de Operación

```
1. Usuario abre http://localhost:3000 (Svelte)
   ↓
2. Hace clic en "Agregar Cliente"
   ↓
3. Frontend envía POST /api/clients con JSON
   ↓
4. app_improved.py middleware intercepta
   ↓
5. Middleware extrae datos y analiza riesgos
   ↓
6. Se guarda en PacketManager (memoria)
   ↓
7. Dashboard (http://localhost:5000) lo muestra
   ↓
8. Usuario VE los datos en tiempo real
```

---

## 📈 Capacidades del Sniffer v3

### **Detección Automática**
```python
✓ Palabras clave "password"
✓ Patrón email: xxxxx@xxx.xx
✓ Patrón teléfono: (123) 456-7890
✓ Patrón DNI/ID: \d{5,}
✓ JWT tokens: eyJhbGc...
✓ API Keys: sk_live_, key_...
✓ Hashes: MD5, SHA1, SHA256, bcrypt
```

### **Scoring de Riesgo**
```
Contraseña detectada    → +100 puntos
Email encontrado        → +30 puntos
API key/Token           → +50 puntos
Teléfono/DNI            → +40 puntos

Total >= 100 → 🔴 CRÍTICO
Total >= 50  → 🟠 ALTO
Total >= 20  → 🟡 MEDIO
Total < 20   → 🟢 BAJO
```

### **Interfaces Disponibles**
```
✓ Dashboard visual en http://localhost:5000
✓ REST API en /api/packets
✓ Server-Sent Events en /api/stream
✓ Auto-refresh cada 2 segundos
✓ Filtros en tiempo real
```

---

## 🚀 Para Usar

### **Opción Rápida (Recomendado)**
```bash
# Terminal
cd c:\Users\angel\Desktop\learnWithGaray\sniffer
python app_improved.py

# Navegador
http://localhost:5000

# ¡Listo!
```

### **Opción Docker (Si quieres integrar)**
```bash
# En docker-compose.yml (opcional)
services:
  sniffer:
    build: ./sniffer
    ports:
      - "5000:5000"
    environment:
      - FLASK_APP=app_improved.py
```

---

## 📚 Archivos de Documentación

| Archivo | Lee esto si... | Tiempo |
|---------|---|---|
| **START_SNIFFER.md** | Quieres iniciar YA | 30 seg |
| **SNIFFER_V3_RESUMEN.md** | Quieres entender cambios | 5 min |
| **SNIFFER_V3_GUIA.md** | Quieres documentación completa | 15 min |
| **Este archivo** | Quieres ver la estructura técnica | 3 min |

---

## 🎓 Ejemplo de Uso Completo

### **Escenario: Registrar usuario nuevo**

#### 1. Frontend (tu app Svelte)
```javascript
// Formulario de registro
POST /api/clients
{
  "name": "Juan",
  "email": "juan@ejemplo.com",
  "phone": "555-1234",
  "password": "mi_secreto"
}
```

#### 2. El Sniffer Captura Instantáneamente
```
✨ Nuevo paquete detectado
ID: 1
Timestamp: 15/04/2026 10:30:45
Método: POST
Endpoint: /api/clients
Riesgo: 🔴 CRÍTICO
Tamaño: 120 bytes
```

#### 3. Análisis Automático
```
✅ JSON Detectado (es JSON válido)
✅ Contraseña: "mi_secreto" (Detectada)
✅ Email: "juan@ejemplo.com" (Detectado)
✅ Teléfono: "555-1234" (Detectado)

RIESGO SCORE:
- Contraseña: +100
- Email: +30
- Teléfono: +40
= 170 puntos → 🔴 CRÍTICO
```

#### 4. Dashboard Muestra
```
┌── POST /api/clients 🔴 CRÍTICO ──┐
│                                  │
│ 📊 DATOS JSON CAPTURADOS:         │
│ {                                │
│   "name": "Juan",                │
│   "email": "juan@ejemplo.com",   │
│   "phone": "555-1234",           │
│   "password": "mi_secreto"       │
│ }                                │
│                                  │
│ ⚠️ DATOS SENSIBLES:               │
│ 🔐 mi_secreto                    │
│ 📧 juan@ejemplo.com              │
│ 📱 555-1234                      │
└──────────────────────────────────┘
```

---

## 🔧 Técnica Implementación

### **Middleware de Flask**
```python
@app.before_request
def capture_request():
    # Se ejecuta ANTES de la ruta
    request.raw_data = request.get_data(as_text=True)
    packet_manager.add_packet(...)

@app.after_request  
def capture_response(response):
    # Se ejecuta DESPUÉS de la ruta
    packet_manager.add_packet(...)
    return response
```

### **Almacenamiento en Memoria**
```python
class PacketManager:
    def __init__(self, max_packets=500):
        self.packets = deque(maxlen=500)  # Último 500 paquetes
        # Automáticamente elimina los más antiguos
```

### **API REST**
```python
@app.route('/api/packets', methods=['GET'])
def get_packets():
    return jsonify({
        'packets': packet_manager.get_all()
    })
```

---

## ✨ Lo Mejor del v3

1. **No requiere PostgreSQL** - Usa memoria directamente
2. **Captura automática** - Sin código adicional
3. **Análisis inteligente** - Detecta riesgos automáticamente
4. **UI moderna** - Dashboard hermoso y funcional
5. **API limpia** - Fácil de integrar con otras herramientas
6. **Documentación completa** - En español, con ejemplos

---

## 🎉 Resumen

Has mejorado tu sniffer de:
```
❌ app.py (básico)
```

A:
```
✅ app_improved.py (profesional)
   ✅ dashboard_improved.html (moderno)
   ✅ Documentación completa
   ✅ Sin dependencias de BD
   ✅ Análisis automático
   ✅ API REST
   ✅ Interfaz Wireshark-like
```

---

## 🚀 Siguiente Paso

```bash
python c:\Users\angel\Desktop\learnWithGaray\sniffer\app_improved.py
# Abre: http://localhost:5000
# ¡A capturar datos!
```

¡Enhorabuena! Tu sniffer ahora está a nivel profesional. 🎉
