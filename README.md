# Trabajo Práctico Especial - Protocolos de Comunicación

Este proyecto implementa una aplicación cliente/servidor con sockets, siguiendo los requerimientos de la materia Protocolos de Comunicación (ITBA, 2025/2).

## Requisitos

- **Docker** (recomendado para entorno homogéneo)
- O bien: **gcc**, **make** y dependencias estándar de C en tu sistema

## Estructura del Proyecto

- `src/` — Código fuente del cliente y servidor
- `Makefile` — Compilación y targets útiles
- `dockerfile` — Imagen mínima para compilar y correr el proyecto
- `doc/` — Documentación y consigna


## Compilación y Ejecución (Recomendado: Docker)

### 1. Construir la imagen Docker

**En MacBook Pro M1/M2/M3 (Apple Silicon):**
```sh
docker build --platform linux/amd64 -t tpe-pdc .
```

**En Linux/Windows (x86_64):**
```sh
docker build -t tpe-pdc .
```


### 2. Levantar un contenedor persistente y acceder desde varias terminales

**Paso 1: Iniciar el contenedor en modo persistente (con nombre)**

**En MacBook Pro M1/M2/M3 (Apple Silicon):**
```sh
docker run --platform linux/amd64 -it --name tpe-pdc-dev -v "$PWD":/workspace -w /workspace -p 1080:1080 -p 8080:8080 tpe-pdc /bin/bash
```

**En Linux/Mac Intel:**
```sh
docker run -it --name tpe-pdc-dev -v "$PWD":/workspace -w /workspace -p 1080:1080 -p 8080:8080 tpe-pdc /bin/bash
```

**En Windows PowerShell:**
```powershell
docker run -it --name tpe-pdc-dev -v "${PWD}:/workspace" -w /workspace -p 1080:1080 -p 8080:8080 tpe-pdc /bin/bash
```

**Paso 2: Abrir una nueva terminal en el mismo contenedor**

En una terminal diferente, ejecuta:
```sh
docker exec -it tpe-pdc-dev /bin/bash
```

Ahora puedes correr el server en una terminal y el client en otra, ambos dentro del mismo contenedor.


### 3. Limpiar y compilar dentro del contenedor

> **IMPORTANTE:** Si cambiaste de sistema operativo o arquitectura, ejecuta siempre primero:
> ```sh
> make clean
> ```

Luego compila:
```sh
make
```

### 4. Ejecutar servidor o cliente

```sh
make run-server   # Ejecuta el servidor
make run-client   # Ejecuta el cliente
```

O directamente:
```sh
./bin/server
./bin/client
```

## Compilación y Ejecución (Sin Docker)

Asegúrate de tener `gcc` y `make` instalados. Luego:

```sh
make
./bin/server
./bin/client
```


## Notas de Compatibilidad y Arquitectura

- **Nunca mezcles archivos `.o` entre sistemas/arquitecturas diferentes.**
- **Siempre ejecuta `make clean` antes de compilar si cambiaste de entorno (Mac, Linux, Docker, Windows, Apple Silicon, etc).**
- **Apple Silicon (M1/M2/M3):** Docker Desktop emula x86_64 por defecto, pero debes forzar la plataforma con `--platform linux/amd64` para máxima compatibilidad.
- **Windows:** se recomienda usar Docker o WSL2. Usa rutas absolutas o `${PWD}` en PowerShell.

## Exposición de Puertos

- `1080`: Puerto SOCKS5
- `8080`: Puerto de administración


## Limpieza

```sh
make clean
```


## Ayuda

```sh
make help
```

---


**Documentación completa y consigna:** ver `doc/20252-r0.txt`

---


Cualquier duda o problema, consultar al equipo docente o abrir un issue.
