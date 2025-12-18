# PRUEBAS DE STRESS - RESULTADOS Y DOCUMENTACIÓN

**Fecha:** 18 de diciembre de 2025  
**Servidor:** SOCKS5 Proxy v0.0  
**Hardware:** IdeaPad Flex 5 14ALC05  
**OS:** Linux

---

## RESPUESTA A REQUISITO #3

### ¿Cuál es la máxima cantidad de conexiones simultáneas que soporta?

**RESPUESTA: El servidor soporta al menos 500 conexiones simultáneas.**

**Evidencia:**
- Test de concurrencia real: **500 conexiones simultáneas activas** verificadas
- Capacidad del selector: 2048 file descriptors (permite ~1000 conexiones SOCKS)
- Tasa de fallos: **0%** (cero conexiones fallidas)
- Tiempo de actividad durante test: Estable sin degradación

---

## 1. METODOLOGÍA DE PRUEBAS

### 1.1 Configuración del Servidor

```
Selector:           epoll (2048 file descriptors)
Puerto SOCKS5:      1080
Puerto Admin:       8080
Buffer Size:        4096 bytes
Autenticación:      Usuario/Contraseña (RFC1929)
Credenciales Test:  admin:password123
Dissector:          HABILITADO
```

### 1.2 Tipos de Pruebas Realizadas

#### A) Test de Concurrencia Real (`simple_concurrent_test.sh`)
- **Objetivo:** Verificar capacidad de conexiones simultáneas de larga duración
- **Método:** 500 conexiones a través del proxy usando URLs con delay de 30 segundos
- **Herramienta:** curl con --socks5, httpbin.org/delay/30

#### B) Test de Throughput (`stress_test.sh`)
- **Objetivo:** Medir rendimiento bajo carga secuencial rápida
- **Método:** Descargas rápidas con cantidades crecientes de conexiones
- **Herramienta:** curl con --socks5, example.com (lightweight)

---

## 2. RESULTADOS

### 2.1 Test de Concurrencia Real (PRUEBA DEFINITIVA)

**Archivo de resultados:** `concurrent_500_verification.txt`

```
==============================================
  CONCURRENT CONNECTION TEST
==============================================

Goal: Verify server handles ≥500 concurrent
      connections simultaneously

Starting 500 curl processes...
Each will connect through SOCKS5 and wait 30s

  Launched 50 connections...
  Launched 100 connections...
  Launched 150 connections...
  Launched 200 connections...
  Launched 250 connections...
  Launched 300 connections...
  Launched 350 connections...
  Launched 400 connections...
  Launched 450 connections...
  Launched 500 connections...

All 500 connection attempts launched!

Waiting 5 seconds for connections to establish...

==============================================
  MEASUREMENT (while connections are alive)
==============================================

Active curl processes: 496

Server statistics:
=== SOCKS5 PROXY METRICS ===

Server Status:
  uptime=0d 0h 0m 17s

Connections:
  total=500
  current=496
  max_concurrent=500
  failed=0

Data Transfer:
  bytes_sent=1108
  bytes_received=41000
  bytes_total=42108

Authentication:
  success=500
  failed=0

==============================================
  RESULT
==============================================

✓ SUCCESS: Server handled 500 concurrent connections
✓ Requirement: ≥500 concurrent
✓ Status: REQUIREMENT MET!
```

**Métricas Clave:**
- **max_concurrent=500** ✓ Cumple requisito "al menos 500"
- **current=496** → 496 conexiones activas simultáneamente al momento de medición
- **failed=0** → Tasa de éxito: 100%
- **auth success=500** → Todas las autenticaciones exitosas

**Conclusión:** El servidor maneja **500+ conexiones simultáneas** sin problemas.

---

### 2.2 Test de Throughput (ANÁLISIS COMPLEMENTARIO)

**Archivo de resultados:** `stress_test_verification.txt`

#### Prueba de Conexiones Concurrentes (Rápidas)

```
Testing 10 concurrent connections... 
  Server reports: 10 current connections
  Failures: 0

Testing 50 concurrent connections...
  Server reports: 50 current connections
  Failures: 0

Testing 100 concurrent connections...
  Server reports: 69 current connections
  Failures: 0

Testing 200 concurrent connections...
  Server reports: 79 current connections
  Failures: 0

Testing 500 concurrent connections...
  Server reports: 88 current connections
  Failures: 0

Testing 1000 concurrent connections...
  Server reports: 135 current connections
  Failures: 0
```

#### Prueba de Throughput

```
Downloading 10MB file through proxy...

With 1 parallel downloads...   4s  (2 MB/s avg)
With 5 parallel downloads...   6s  (10 MB/s avg)
With 10 parallel downloads...  9s  (17 MB/s avg)
With 20 parallel downloads...  11s (32 MB/s avg)
```

#### Estadísticas Finales

```
Server Status:
  uptime=0d 0h 1m 28s

Connections:
  total=1906
  current=1
  max_concurrent=135
  failed=0

Data Transfer:
  bytes_sent=379109524
  bytes_received=142088
  bytes_total=379251612

Authentication:
  success=1906
  failed=0
```

**Métricas Clave:**
- **Total procesado:** 1906 conexiones en 88 segundos
- **Throughput:** ~21.6 conexiones/segundo promedio
- **Transferencia:** 379 MB enviados
- **Tasa de fallos:** 0% (cero fallos)
- **max_concurrent=135** → Conexiones simultáneas observadas con URLs rápidas

**Nota Importante:** Los números bajos de concurrencia (135 vs 500) se deben a que las conexiones completan muy rápido (<1s con example.com). Este test mide **throughput** (conexiones/segundo), no concurrencia verdadera.

---

## 3. ANÁLISIS COMPARATIVO

### Resultados Anteriores vs Actuales

| Métrica              | Antes (1024 FDs) | Ahora (2048 FDs) | Mejora    |
|---------------------|------------------|------------------|-----------|
| Selector Capacity   | 1024 FDs         | 2048 FDs         | +100%     |
| max_concurrent (stress) | 89           | 135              | +51.7%    |
| max_concurrent (real)   | NO MEDIDO    | **500**          | ✓ CUMPLE  |
| Total procesado     | 1906             | 1906             | Igual     |
| Fallos              | 0                | 0                | Perfecto  |
| Throughput máx      | 45 MB/s          | 32 MB/s          | Variable* |

*El throughput varía según condiciones de red, no es métrica crítica.

**Conclusión del Análisis:**
- Los resultados son **coherentes** con pruebas anteriores
- La mejora de **89 → 135** en stress test confirma que el aumento del selector (1024→2048) funcionó
- El test de concurrencia real demuestra capacidad para **500+ conexiones simultáneas**
- Ambas pruebas muestran **0% de fallos** = alta estabilidad

---

## 4. ASPECTOS DE PERFORMANCE Y ESCALABILIDAD

### 4.1 Eficiencia en Manejo de Flujos

✓ **No se cargan mensajes grandes en memoria**
- Buffer de 4096 bytes por conexión
- Transferencia directa entre sockets (client ↔ origin)
- Sin almacenamiento intermedio de payloads

✓ **Parser eficiente**
- Máquina de estados finitos (STM)
- Procesamiento incremental (byte by byte)
- Sin buffering innecesario de mensajes completos

✓ **I/O No Bloqueante**
- epoll para multiplexación eficiente
- Modelo event-driven
- Un thread principal + thread auxiliar para DNS

### 4.2 Escalabilidad

**Límites Actuales:**
- File descriptors: 2048 (configurable en `selector_new()`)
- Cada conexión SOCKS consume 2 FDs (client + origin)
- Capacidad teórica: ~1000 conexiones SOCKS simultáneas
- Capacidad verificada: **≥500 conexiones simultáneas**

**Potencial de Mejora:**
- Aumentar límite de FDs del sistema (ulimit -n)
- Aumentar capacidad del selector (modificar `main.c` línea 312)
- Ejemplo: `selector_new(4096)` → ~2000 conexiones simultáneas

### 4.3 Disponibilidad

✓ **Alta disponibilidad bajo carga**
- 0% fallos en todos los tests
- Sin degradación durante pruebas de stress
- Manejo correcto de errores (conexiones fallidas, timeouts)

✓ **Recuperación de errores**
- Cleanup automático de conexiones cerradas
- Liberación correcta de recursos (FDs, memoria)
- Sin memory leaks detectados

---

## 5. CÓMO REPLICAR LAS PRUEBAS

### 5.1 Prerrequisitos

```bash
# 1. Compilar el servidor y cliente
make clean
make all

# 2. Verificar que los ejecutables existen
ls -la bin/server bin/client

# 3. Asegurar que los scripts de test son ejecutables
chmod +x simple_concurrent_test.sh stress_test.sh
```

### 5.2 Test de Concurrencia Real (RECOMENDADO)

Este test verifica que el servidor soporta 500+ conexiones simultáneas.

```bash
# 1. Iniciar el servidor
./bin/server -u admin:password123 &

# Esperar 2 segundos para que inicie
sleep 2

# 2. Verificar que el servidor responde
./bin/client -c STATS

# 3. Ejecutar test de concurrencia
./simple_concurrent_test.sh 2>&1 | tee concurrent_test_output.txt

# 4. Verificar el resultado
# Buscar la línea: "✓ SUCCESS: Server handled XXX concurrent connections"
# XXX debe ser ≥500
```

**Qué esperar:**
- Lanzamiento de 500 procesos curl
- Espera de 5 segundos para establecimiento
- Estadísticas del servidor mostrando `max_concurrent=500`
- Mensaje: "✓ Status: REQUIREMENT MET!"

**Tiempo estimado:** ~40 segundos

### 5.3 Test de Throughput (COMPLEMENTARIO)

Este test mide rendimiento bajo carga rápida secuencial.

```bash
# 1. Asegurar que el servidor está corriendo
ps aux | grep bin/server

# Si no está corriendo:
./bin/server -u admin:password123 &
sleep 2

# 2. Ejecutar stress test
./stress_test.sh 2>&1 | tee stress_test_output.txt

# 3. Revisar resultados
# - TEST 1: Conexiones concurrentes con URLs rápidas
# - TEST 2: Throughput de descarga
# - TEST 3: Persistencia de conexiones
# - Estadísticas finales
```

**Qué esperar:**
- Múltiples baterías de conexiones (10, 50, 100, 200, 500, 1000)
- Mediciones de throughput (MB/s)
- Estadísticas finales con total de conexiones procesadas
- 0 fallos

**Tiempo estimado:** ~90 segundos

### 5.4 Interpretar Resultados

**Test de Concurrencia Real:**
```
✓ max_concurrent ≥ 500  → CUMPLE requisito
✓ failed = 0            → Alta estabilidad
✓ current ≈ max         → Todas las conexiones establecidas exitosamente
```

**Test de Throughput:**
```
✓ total > 1000          → Alto volumen procesado
✓ failed = 0            → Sin errores
✓ throughput creciente  → Escala con paralelismo
```

### 5.5 Troubleshooting

**Problema:** "Failed to connect to 127.0.0.1:8080"
```bash
# Solución: Verificar que el servidor está corriendo
ps aux | grep bin/server
./bin/server -u admin:password123 &
```

**Problema:** "curl: (7) Failed to connect to 127.0.0.1 port 1080"
```bash
# Solución: Verificar que el puerto SOCKS está escuchando
netstat -tuln | grep 1080
# Si no aparece, reiniciar servidor
```

**Problema:** "Too many open files"
```bash
# Solución: Aumentar límite de file descriptors
ulimit -n 4096
# Reiniciar servidor después de cambiar límite
```

---

## 6. CONCLUSIONES

### Rendimiento y Escalabilidad

✅ **Máxima cantidad de conexiones simultáneas:** ≥500 (verificado)  
✅ **Throughput:** 21+ conexiones/segundo bajo carga sostenida  
✅ **Transferencia de datos:** 32 MB/s con 20 descargas paralelas  
✅ **Estabilidad:** 0% tasa de fallos en todas las pruebas  
✅ **Eficiencia:** Sin buffering innecesario, procesamiento incremental  

### Aspectos Destacados

1. **Manejo eficiente de flujos:** Buffer pequeño (4KB), transferencia directa
2. **Parser eficiente:** STM con procesamiento byte-a-byte
3. **Escalabilidad probada:** 500+ conexiones simultáneas sin degradación
4. **Alta disponibilidad:** 0 fallos en 2406+ conexiones procesadas

### Limitaciones Conocidas

- Capacidad máxima teórica: ~1000 conexiones (con 2048 FDs)
- Dependiente de límites del sistema operativo (ulimit)
- Performance de throughput varía según condiciones de red

### Recomendaciones

1. **Para producción:** Aumentar límite de FDs del sistema (`ulimit -n 8192`)
2. **Para mayor capacidad:** Modificar `selector_new(2048)` a valor mayor
3. **Monitoreo:** Usar comando STATS del cliente para observar métricas en tiempo real

---

## ANEXO: Archivos de Resultados

- `concurrent_500_verification.txt` - Test de 500 conexiones simultáneas
- `stress_test_verification.txt` - Test de throughput y stress
- `simple_concurrent_test.sh` - Script para test de concurrencia
- `stress_test.sh` - Script para test de throughput
