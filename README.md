# PAEA — Platform for Autonomous Edge Agents

Sistema multi-agente con **auto-sanación** (auto-healing), **cumplimiento**
(compliance) y **aprendizaje** (learning). Ejecuta tareas, detecta errores,
genera parches y aprende de cada resultado, todo con una cadena de auditoría
tamper-evident (SHA-256).

## Requisitos

- **Python 3.9+** (solo biblioteca estándar, sin dependencias externas).

## Uso — CLI

```bash
# Ejecutar una tarea
python paea.py execute "analyze this codebase"

# Estado del sistema
python paea.py status

# Tareas recientes
python paea.py tasks

# Patrones aprendidos
python paea.py learnings

# Verificar integridad de la cadena de auditoría
python paea.py audit
python paea.py verify

# Gestión de consentimientos
python paea.py consent <user_id> <type> <yes|no>

# Modo interactivo
python paea.py interactive

# Servidor web + dashboard
python paea.py serve [port]        # default 8080
```

### Dashboard web

```
python paea.py serve
```

Abre `http://localhost:8080/dashboard`. El dashboard (dark, KPIs, tablas,
JS vanilla) consume los endpoints internos:

| Endpoint       | Método | Descripción                              |
|----------------|--------|------------------------------------------|
| `/api/status`  | GET    | KPIs: tareas, learnings, cadena de auditoría, ruta de DB |
| `/api/tasks`   | GET    | Últimas 10 tareas                        |
| `/api/learnings` | GET  | Patrones aprendidos                       |
| `/api/health`  | GET    | Healthcheck simple                        |
| `/api/execute` | POST   | Ejecuta una tarea `{ "task": "...", "context": {} }` |

El dashboard auto-refresca cada 5 segundos y permite ejecutar tareas desde el
formulario superior.

## Almacenamiento

La base de datos SQLite vive en **`~/.paea/paea.db`** (se crea automáticamente).
Puede redirigirse con la variable de entorno **`PAEA_DB_PATH`**:

```bash
# Windows (PowerShell)
$env:PAEA_DB_PATH = "D:\data\paea.db"; python paea.py status

# Linux / macOS
PAEA_DB_PATH=/var/lib/paea/paea.db python paea.py status
```

Esto es útil para entornos aislados y para los tests (que usan una DB temporal).

Tablas: `tasks`, `audit_log` (append-only con hash chain), `learnings`,
`consents` (cumplimiento / consentimientos por jurisdicción).

## Configuración (variables de entorno)

| Variable          | Default                  | Descripción                          |
|-------------------|--------------------------|--------------------------------------|
| `PAEA_LLM_PROVIDER` | `ollama`               | `ollama`, `openai`, `groq` o `mock`  |
| `PAEA_LLM_MODEL`    | `qwen2.5:latest`        | Modelo a usar                        |
| `PAEA_LLM_URL`      | `http://localhost:11434`| Base URL (Ollama)                    |
| `PAEA_LLM_KEY`      | *(vacío)*               | API key (OpenAI / Groq)              |
| `PAEA_LOG`          | `info`                  | Nivel de log (`info`, `debug`)       |
| `PAEA_DB_PATH`      | `~/.paea/paea.db`       | Ruta de la base de datos             |

> Sin un proveedor configurado, el sistema usa un **modo mock** que procesa la
> entrada localmente (lectura de archivos, listado de directorios, ejecución de
> snippets, procesos, git, etc.) sin salir de la máquina.

## Arquitectura

```
paea.py  (un solo archivo)
├── Config          → variables de entorno PAEA_*
├── init_db         → SQLite en ~/.paea/paea.db (WAL + row_factory)
├── AuditLedger     → log append-only con cadena SHA-256; verify_chain
├── start_web_server→ HTTP + endpoints /api/* + dashboard
├── start_repl      → CLI interactivo
├── LLMClient       → ollama / openai / groq / mock
├── Agentes
│   ├── Executor    → acciones locales (archivos, código, procesos, git) o LLM
│   ├── Monitor     → diagnostica errores
│   ├── Doctor      → genera parches (estrategias locales + LLM)
│   └── Evolver     → registra learnings (éxito/fallo)
└── Orchestrator    → pipeline: Execute → Monitor → Doctor → Retry → Evolve
```

## Tests

```bash
python test_paea.py
```

Cubre: integridad de la cadena de auditoría (incluida la detección de
manipulación), consultas del orquestador, acciones locales del Executor,
robustez de subprocess y esquema de la DB. Los tests usan una base temporal
(`PAEA_DB_PATH`) y no tocan `~/.paea`.

## Seguridad y compliance

- Cadena de auditoría SHA-256 append-only; `verify_chain` detecta cualquier
  modificación retroactiva.
- Tabla `consents` para registrar consentimientos explícitos con jurisdicción
  (default EU).
- No se registran secretos; las API keys van por variables de entorno.
