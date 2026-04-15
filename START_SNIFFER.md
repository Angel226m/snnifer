# 🚀 INICIO RÁPIDO - Sniffer v3

## 📋 Los 3 Pasos Básicos

### **PASO 1: Instalar dependencias** (si es necesario)
```bash
cd c:\Users\angel\Desktop\learnWithGaray\sniffer
# Las dependencias ya están en requirements.txt del backend
# Flask ya está instalado si tienes el backend corriendo
```

### **PASO 2: Iniciar el Sniffer**
```bash
cd c:\Users\angel\Desktop\learnWithGaray\sniffer
python app_improved.py
```

Deberías ver:
```
🚀 Sniffer v3 - Dashboard mejorado iniciando...
📊 Dirección: http://localhost:5000
📡 Stream SSE disponible en: http://localhost:5000/api/stream
📝 Prueba en: http://localhost:5000/api/test-capture (POST)
```

### **PASO 3: Abre el Dashboard**
```
http://localhost:5000
```

---

## ✨ Eso es TODO

Ahora:
- ✅ Abre tu app en `http://localhost:3000`
- ✅ Crea un cliente
- ✅ Mira el sniffer capturar los datos en tiempo real
- ✅ Haz clic en un paquete para ver los detalles

---

## 📊 Qué ves en el Dashboard

### **Panel Izquierdo**
Lista de todos los paquetes capturados:
```
POST /api/clients      ← Haz clic aquí
GET  /api/clients
POST /auth/login
```

### **Panel Derecho**
Detalles del paquete seleccionado:
```json
{
  "name": "Carlos",
  "email": "angel@gmail.com",
  "phone": "899898784"
}

⚠️ DATOS SENSIBLES DETECTADOS
📧 angel@gmail.com
📱 899898784
```

---

## 🎨 Colores de Riesgo

| Color | Riesgo | Ejemplo |
|-------|--------|---------|
| 🔴 Rojo | CRÍTICO | Contraseña detectada |
| 🟠 Naranja | ALTO | Email + Teléfono |
| 🟡 Amarillo | MEDIO | Solo DNI o documento |
| 🟢 Verde | BAJO | Datos públicos |

---

## 🤔 ¿Problemas?

### "No funciona Python"
```bash
# Verifica que Python está instalado
python --version

# Si no está, descarga de https://www.python.org/
```

### "Puerto 5000 en uso"
```bash
# Cambiar a otro puerto en app_improved.py (línea final)
# Busca: app.run(port=5000)
# Cambia a: app.run(port=5001)
```

### "No aparecen paquetes"
```bash
# Verifica que estés usando http://localhost:3000 (Svelte)
# No http://localhost:8000 (Backend)
# El sniffer ✓ es separado
```

---

## 📚 Documentación Completa

- **SNIFFER_V3_GUIA.md** - Guía detallada (casos, APIs, configuración)
- **SNIFFER_V3_RESUMEN.md** - Resumen de cambios
- **app_improved.py** - Código fuente comentado

---

## 🎯 TL;DR (Si no tienes tiempo)

```bash
# Terminal 1 - Backend (si no está corriendo)
cd backend
python -m uvicorn app.main:app --reload

# Terminal 2 - Sniffer
cd sniffer
python app_improved.py

# Terminal 3 - Frontend (si no está corriendo)
cd frontend
npm run dev

# Navegador
# 🌐 http://localhost:3000       (Tu app)
# 📡 http://localhost:5000       (Sniffer) ← AQUÍ VES LOS DATOS
# 🔧 http://localhost:8000/docs  (APIs del backend)
```

---

## ✅ Listo!

Tu sniffer está funcionando. Ahora:

1. Usa tu app normalmente
2. Mira el dashboard en tiempo real
3. Aprende qué datos se envían
4. Descubre vulnerabilidades

🚀 **¡Comienza ahora!**
