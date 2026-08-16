#!/usr/bin/env python3
"""
PAEA — Platform for Autonomous Edge Agents
Multi-agent system with auto-healing, compliance, and learning.

Usage:
    python paea.py execute "analyze this codebase"
    python paea.py status
    python paea.py heal <task_id>
    python paea.py learn
"""

import os
import sys
import json
import uuid
import hashlib
import shlex
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any
from abc import ABC, abstractmethod

# ============================================================
# CONFIGURATION
# ============================================================

# Base de datos local. Por defecto vive en ~/.paea/paea.db.
# Se puede redirigir con la variable de entorno PAEA_DB_PATH
# (util para tests y despliegues en contenedores).
DB_PATH = Path(os.getenv("PAEA_DB_PATH", str(Path.home() / ".paea" / "paea.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

class Config:
    """Configuracion en runtime via variables de entorno (PAEA_*)."""

    LLM_PROVIDER = os.getenv("PAEA_LLM_PROVIDER", "ollama")  # ollama | openai | groq
    LLM_MODEL = os.getenv("PAEA_LLM_MODEL", "qwen2.5:latest")
    LLM_BASE_URL = os.getenv("PAEA_LLM_URL", "http://localhost:11434")
    LLM_API_KEY = os.getenv("PAEA_LLM_KEY", "")
    MAX_RETRIES = 3
    LOG_LEVEL = os.getenv("PAEA_LOG", "info")

# ============================================================
# DATABASE
# ============================================================

def init_db():
    # check_same_thread=False permite compartir la conexion entre los hilos
    # del servidor web (ThreadingHTTPServer). Python sqlite3 se compila en modo
    # serializado, por lo que el uso compartido es seguro.
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row  # acceso por nombre de columna en todo el codigo
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            input TEXT NOT NULL,
            context TEXT DEFAULT '{}',
            status TEXT DEFAULT 'pending',
            result TEXT,
            error TEXT,
            fix TEXT,
            agent_id TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            task_id TEXT,
            event_type TEXT NOT NULL,
            detail TEXT,
            hash_prev TEXT,
            hash_current TEXT,
            timestamp TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS learnings (
            id TEXT PRIMARY KEY,
            error_pattern TEXT NOT NULL,
            fix_applied TEXT,
            success_count INTEGER DEFAULT 0,
            fail_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS consents (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            consent_type TEXT NOT NULL,
            granted INTEGER DEFAULT 0,
            jurisdiction TEXT DEFAULT 'EU',
            timestamp TEXT NOT NULL
        );
    """)
    conn.commit()
    return conn

DB = init_db()

# ============================================================
# AUDIT (Append-only, hash chain)
# ============================================================

class AuditLedger:
    """Libro de auditoria append-only con cadena de hashes tamper-evident."""

    # Nombres de columna como constantes: el acceso por nombre (sqlite3.Row)
    # evita indices posicionales fragiles ante cambios de esquema.
    COL_HASH_PREV = "hash_prev"
    COL_HASH_CURRENT = "hash_current"

    def __init__(self, conn):
        self.conn = conn
        self._last_hash = "0" * 64

    def log(self, task_id: str, event_type: str, detail: str = "") -> str:
        """Registra un evento y devuelve el hash del nuevo bloque."""
        row = self.conn.execute(
            "SELECT hash_current FROM audit_log ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        self._last_hash = row[0] if row else "0" * 64

        event_id = str(uuid.uuid4())
        ts = datetime.now(timezone.utc).isoformat()
        payload = f"{event_id}{task_id}{event_type}{detail}{ts}{self._last_hash}"
        hash_current = hashlib.sha256(payload.encode()).hexdigest()

        self.conn.execute(
            "INSERT INTO audit_log (id, task_id, event_type, detail, hash_prev, hash_current, timestamp) VALUES (?,?,?,?,?,?,?)",
            (event_id, task_id, event_type, detail, self._last_hash, hash_current, ts)
        )
        self.conn.commit()

        if Config.LOG_LEVEL == "debug":
            print(f"  [AUDIT] {event_type}: {detail[:80]}")

        return hash_current

    def verify_chain(self) -> bool:
        """Verifica que la cadena de hashes este intacta (sin manipulaciones)."""
        rows = self.conn.execute(
            f"SELECT {self.COL_HASH_PREV}, {self.COL_HASH_CURRENT} FROM audit_log ORDER BY rowid"
        ).fetchall()
        prev_hash = "0" * 64
        for row in rows:
            if row[self.COL_HASH_PREV] != prev_hash:
                return False
            prev_hash = row[self.COL_HASH_CURRENT]
        return True

audit = AuditLedger(DB)

# ============================================================
# WEB SERVER (simple HTTP)
# ============================================================

def start_web_server(port: int = 8080):
    """Start a simple HTTP server with API endpoints."""
    import http.server
    import urllib.parse

    class PaeaHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            if path == "/" or path == "/dashboard":
                self._serve_file("web/dashboard/index.html", "text/html")
            elif path == "/api/status":
                self._json_response(orchestrator.status())
            elif path == "/api/tasks":
                self._json_response(orchestrator.recent_tasks())
            elif path == "/api/learnings":
                self._json_response(orchestrator.learnings())
            elif path == "/api/health":
                self._json_response({"status": "ok", "version": "1.0.0"})
            else:
                self.send_error(404)

        def do_POST(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/api/execute":
                content_length = int(self.headers.get("Content-Length", 0))
                try:
                    body = json.loads(self.rfile.read(content_length)) if content_length else {}
                except (json.JSONDecodeError, UnicodeDecodeError):
                    self._json_response({"error": "Invalid JSON body"}, 400)
                    return
                if not isinstance(body, dict):
                    self._json_response({"error": "JSON body must be an object"}, 400)
                    return
                task = body.get("task", "")
                if not task:
                    self._json_response({"error": "Missing 'task' field"}, 400)
                    return
                result = orchestrator.execute(task, body.get("context", {}))
                self._json_response(result)
            else:
                self.send_error(404)

        def _json_response(self, data, code=200):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(data, indent=2, default=str).encode())

        def _serve_file(self, filepath, content_type):
            full = Path(__file__).parent / filepath
            if full.exists():
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.end_headers()
                self.wfile.write(full.read_bytes())
            else:
                self.send_error(404)

        def log_message(self, format, *args):
            print(f"  [HTTP] {args[0]}")

    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), PaeaHandler)
    print(f"\n  PAEA Web Server running on http://localhost:{port}")
    print(f"  Dashboard: http://localhost:{port}/dashboard")
    print(f"  API Status: http://localhost:{port}/api/status")
    print(f"  API Execute: POST http://localhost:{port}/api/execute")
    print("\n  Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
        server.server_close()

# ============================================================
# INTERACTIVE REPL
# ============================================================

def start_repl():
    """Start an interactive REPL session."""
    print("\n  PAEA Interactive Mode v1.0.0")
    print("  Type 'help' for commands, 'exit' to quit.\n")

    while True:
        try:
            user_input = input("paea> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Bye.")
            break

        if not user_input:
            continue
        if user_input in ("exit", "quit", "q"):
            print("  Bye.")
            break
        if user_input == "help":
            print("  Commands:")
            print("    <task>           — Execute a task")
            print("    status           — Show system status")
            print("    tasks            — List recent tasks")
            print("    learnings        — Show learned patterns")
            print("    audit            — Verify audit chain")
            print("    consent <u> <t> <yes|no> — Manage consent")
            print("    verify           — Verify audit integrity")
            print("    exit             — Quit")
            continue
        if user_input == "status":
            print(json.dumps(orchestrator.status(), indent=2))
            continue
        if user_input == "tasks":
            for t in orchestrator.recent_tasks():
                print(f"  [{t['status']:>9}] {t['id']} | {t['input'][:50]}")
            continue
        if user_input == "learnings":
            for l in orchestrator.learnings():
                print(f"  [OK] {l['success']}x | [FAIL] {l['failures']}x | {l['pattern'][:60]}")
            continue
        if user_input == "audit":
            ok = audit.verify_chain()
            print(f"  Audit: {'VALID' if ok else 'BROKEN'}")
            continue
        if user_input == "verify":
            ok = audit.verify_chain()
            print(f"  Integrity: {'PASS' if ok else 'FAIL'}")
            continue

        # Execute as task
        result = orchestrator.execute(user_input)
        status = result.get("status", "unknown")
        output = result.get("result", {}).get("output", result.get("error", ""))
        icon = "[OK]" if status in ("completed", "healed") else "[FAIL]"
        print(f"  {icon} [{status}] {output[:200] if output else 'no output'}")
        if result.get("fix"):
            print(f"  [FIX] Fix applied: {result['fix'][:100]}")

# ============================================================
# LLM CLIENT
# ============================================================

class LLMClient:
    def __init__(self):
        self.provider = Config.LLM_PROVIDER
        self.model = Config.LLM_MODEL
        self.base_url = Config.LLM_BASE_URL

    def generate(self, prompt: str, system: str = "", max_tokens: int = 2048) -> str:
        if self.provider == "ollama":
            return self._ollama(prompt, system, max_tokens)
        elif self.provider == "openai":
            return self._openai(prompt, system, max_tokens)
        elif self.provider == "groq":
            return self._groq(prompt, system, max_tokens)
        else:
            return self._mock(prompt, system)

    def _ollama(self, prompt: str, system: str, max_tokens: int) -> str:
        import urllib.request
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system or "You are a helpful AI assistant.",
            "stream": False,
            "options": {"num_predict": max_tokens}
        }
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
                return data.get("response", "")
        except Exception as e:
            print(f"  [LLM] Ollama error: {e}")
            return self._mock(prompt, system)

    def _openai(self, prompt: str, system: str, max_tokens: int) -> str:
        import urllib.request
        url = "https://api.openai.com/v1/chat/completions"
        payload = {
            "model": self.model or "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": system or "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": max_tokens
        }
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {Config.LLM_API_KEY}"
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"  [LLM] OpenAI error: {e}")
            return self._mock(prompt, system)

    def _groq(self, prompt: str, system: str, max_tokens: int) -> str:
        import urllib.request
        url = "https://api.groq.com/openai/v1/chat/completions"
        payload = {
            "model": self.model or "llama-3.1-8b-instant",
            "messages": [
                {"role": "system", "content": system or "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": max_tokens
        }
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {Config.LLM_API_KEY}"
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"  [LLM] Groq error: {e}")
            return self._mock(prompt, system)

    def _mock(self, prompt: str, system: str) -> str:
        return f"[MOCK LLM] Processed: {prompt[:100]}..."

llm = LLMClient()

# ============================================================
# AGENTS
# ============================================================

class Agent(ABC):
    def __init__(self, agent_id: str, name: str):
        self.agent_id = agent_id
        self.name = name
        self.status = "idle"

    @abstractmethod
    def execute(self, **kwargs) -> Any:
        pass

class ExecutorAgent(Agent):
    def __init__(self):
        super().__init__("executor", "Executor")

    def _run_process(self, cmd: list, timeout: int = 10) -> str:
        """Ejecuta un subproceso de forma segura y devuelve su salida combinada.

        Corrige el `except:` desnudo: captura errores de subprocess/OS y
        devuelve un mensaje claro en lugar de crashear la tarea.
        """
        import subprocess
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (subprocess.SubprocessError, OSError) as exc:
            return f"[PROCESS ERROR] {cmd[0]}: {exc}"
        output = (result.stdout + result.stderr).strip()
        if output:
            return output
        return f"[no output, exit code={result.returncode}]"

    def _try_local_action(self, prompt: str) -> Optional[str]:
        """Try to perform real actions based on the prompt."""
        import re

        # Try to read a file — detect any path with known extension
        file_match = re.search(r'([A-Za-z]:\\[^\s]+\.(?:txt|md|py|json|html|csv|log))', prompt)
        if not file_match:
            file_match = re.search(r'([^\s/]+\.(?:txt|md|py|json|html|csv|log))', prompt)
        if file_match:
            filepath = file_match.group(1)
            # Try exact path first
            exact = Path(filepath)
            if exact.exists():
                content = exact.read_text(encoding="utf-8", errors="replace")
                return f"[FILE READ] {exact}\n\n{content[:3000]}"
            # Try common base directories
            for base in [Path.cwd(), Path.home() / "Desktop", Path.home() / "Documents", Path.home() / "Downloads", Path.home() / "Videos" / "DRIVE"]:
                full = base / filepath
                if full.exists():
                    content = full.read_text(encoding="utf-8", errors="replace")
                    return f"[FILE READ] {full}\n\n{content[:3000]}"
            # File not found — raise error to trigger auto-healing
            raise FileNotFoundError(f"File not found: {filepath}. Searched in: CWD, Desktop, Documents, Downloads, DRIVE")

        # Try to list a directory
        dir_match = re.search(r'(?:lista|list|ls|dir|muestra|show)\s+(?:el\s+)?(?:directorio\s+)?([^\s]+)', prompt, re.IGNORECASE)
        if dir_match:
            dirpath = Path(dir_match.group(1))
            if dirpath.exists() and dirpath.is_dir():
                items = sorted([f.name for f in dirpath.iterdir()][:50])
                return f"[DIR LIST] {dirpath}\n\n" + "\n".join(items)

        # Try to run Python code
        code_match = re.search(r'(?:ejecuta|run|exec|python)\s*[:\-]?\s*(?:```)?(import\s+.+|from\s+.+|def\s+.+)', prompt, re.IGNORECASE)
        if code_match:
            code = code_match.group(1)
            # Extract full code block if present
            block = re.search(r'```(?:python)?\s*\n(.*?)```', prompt, re.DOTALL)
            if block:
                code = block.group(1)
            try:
                result = {}
                exec(code, {"__builtins__": __builtins__}, result)
                return f"[CODE EXECUTED]\n{json.dumps({k: str(v)[:200] for k, v in result.items() if not k.startswith('_')}, indent=2)}"
            except Exception as e:
                raise RuntimeError(f"Code execution failed: {e}")

        # Try to count files
        count_match = re.search(r'(?:cuantos|count|cuenta|how many)\s+(?:archivos|files|txt|md|py)\s+(?:hay|are|exist|estan)\s+(?:en|in|at)\s+(.+)', prompt, re.IGNORECASE)
        if count_match:
            dirpath = Path(count_match.group(1).strip())
            if dirpath.exists():
                count = sum(1 for _ in dirpath.rglob("*") if _.is_file())
                return f"[COUNT] {dirpath}: {count} files"

        # Try to write/create a file
        write_match = re.search(r'(?:escribe|write|create|crea|guarda|save)\s+(?:el\s+)?(?:archivo\s+)?([^\s]+\.(?:txt|md|py|json|html))', prompt, re.IGNORECASE)
        if write_match:
            filepath = write_match.group(1)
            # Extract content between quotes or after "con contenido:" or "content:"
            content_match = re.search(r'(?:contenido|content|texto|text)[:\s]+"([^"]+)"', prompt, re.IGNORECASE)
            if not content_match:
                content_match = re.search(r'```(?:\w+)?\s*\n(.*?)```', prompt, re.DOTALL)
            if content_match:
                content = content_match.group(1)
                Path(filepath).parent.mkdir(parents=True, exist_ok=True)
                Path(filepath).write_text(content, encoding="utf-8")
                return f"[FILE CREATED] {filepath} ({len(content)} chars)"
            else:
                raise ValueError(f"No content provided for file creation: {filepath}")

        # Try to search the web
        search_match = re.search(r'(?:busca|search|google|investiga|research)\s+(.+)', prompt, re.IGNORECASE)
        if search_match:
            query = search_match.group(1).strip()[:200]
            try:
                import urllib.request
                import urllib.parse
                url = f"https://lite.duckduckgo.com/lite/?q={urllib.parse.quote(query)}"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    html = resp.read().decode("utf-8", errors="replace")
                    # Extract text snippets
                    snippets = re.findall(r'<td[^>]*class="result-snippet"[^>]*>(.*?)</td>', html, re.DOTALL)
                    results = [re.sub(r'<[^>]+>', '', s).strip() for s in snippets[:5]]
                    if results:
                        return f"[SEARCH] {query}\n\n" + "\n".join(f"• {r}" for r in results)
                    return f"[SEARCH] {query}\n\nNo results found (or blocked by rate limit)"
            except Exception as e:
                return f"[SEARCH FAILED] {query}: {e}"

        # Try to list processes
        ps_match = re.search(r'(?:procesos|processes|ps|tasklist|que corre|what.*running)', prompt, re.IGNORECASE)
        if ps_match:
            if os.name == "nt":
                output = self._run_process(["tasklist", "/FO", "CSV", "/NH"], timeout=10)
            else:
                output = self._run_process(["ps", "aux"], timeout=10)
            lines = output.split("\n")[:20]
            return "[PROCESSES] Top 20:\n" + "\n".join(lines)

        # Try to get system info
        sys_match = re.search(r'(?:sistema|system|info|hostname|ip|disco|disk|memoria|memory|cpu)', prompt, re.IGNORECASE)
        if sys_match:
            import platform
            import socket
            info = {
                "os": platform.system(),
                "os_version": platform.version(),
                "machine": platform.machine(),
                "python": platform.python_version(),
                "hostname": socket.gethostname(),
                "cwd": str(Path.cwd()),
            }
            return "[SYSTEM INFO]\n" + "\n".join(f"  {k}: {v}" for k, v in info.items())

        # Try git operations
        git_match = re.search(r'(?:git|commits|historial)\s+(.+)', prompt, re.IGNORECASE)
        if git_match:
            arg = git_match.group(1).strip()
            # shlex.split evita pasar "log --oneline" como un unico argumento
            cmd = ["git"] + shlex.split(arg)
            output = self._run_process(cmd, timeout=10)
            return f"[GIT {' '.join(cmd[1:])}]\n{output[:2000]}"

        # Try to check if a port is in use
        port_match = re.search(r'(?:puerto|port)\s+(\d+)', prompt, re.IGNORECASE)
        if port_match:
            import socket
            port = int(port_match.group(1))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(("127.0.0.1", port))
            sock.close()
            status = "OPEN (in use)" if result == 0 else "CLOSED (available)"
            return f"[PORT {port}] {status}"

        return None  # No local action found, use LLM

    def execute(self, task_id: str = "", prompt: str = "", context: dict = None) -> dict:
        self.status = "running"
        audit.log(task_id, "executor_start", f"Executing: {prompt[:100]}")

        # Try local action first
        local_result = self._try_local_action(prompt)
        if local_result:
            self.status = "idle"
            audit.log(task_id, "executor_done", f"Local action: {len(local_result)} chars")
            return {"output": local_result, "tokens": len(local_result.split())}

        # Fall back to LLM
        system = """You are an autonomous task executor.
Given a task, produce a clear, actionable result.
If the task requires code, provide the code.
If the task requires analysis, provide the analysis.
Be concise and precise."""

        result = llm.generate(prompt, system)

        self.status = "idle"
        audit.log(task_id, "executor_done", f"Result length: {len(result)}")
        return {"output": result, "tokens": len(result.split())}

class MonitorAgent(Agent):
    def __init__(self):
        super().__init__("monitor", "Monitor")

    def execute(self, task_id: str = "", error: str = "", context: dict = None) -> dict:
        self.status = "running"
        audit.log(task_id, "monitor_start", f"Diagnosing: {error[:100]}")

        system = """You are a diagnostic agent. Analyze the error and suggest a fix.
Be specific about the root cause and provide a concrete code fix if applicable."""

        diagnosis = llm.generate(
            f"Error occurred during task execution:\n\nError: {error}\n\nContext: {json.dumps(context or {}, indent=2)}\n\nDiagnose the root cause and suggest a fix:",
            system
        )

        self.status = "idle"
        audit.log(task_id, "monitor_done", f"Diagnosis: {diagnosis[:100]}")
        return {"diagnosis": diagnosis, "confidence": 0.6}

class DoctorAgent(Agent):
    def __init__(self):
        super().__init__("doctor", "Doctor")

    def _local_fix_strategies(self, error: str) -> Optional[str]:
        """Try to fix common errors without LLM."""
        lower = error.lower()

        # File not found — suggest checking path or creating it
        if "file not found" in lower or "no such file" in lower:
            return """LOCAL FIX: File not found.
1. Check if the path is correct (case-sensitive on Linux)
2. Create the directory: mkdir -p <parent>
3. Create the file: touch <filepath>
4. Alternative: search for similar files with glob pattern"""

        # Permission denied
        if "permission denied" in lower or "access" in lower:
            return """LOCAL FIX: Permission denied.
1. Check file permissions: ls -la <filepath>
2. Fix: chmod 644 <filepath> or chmod 755 <dir>
3. On Windows: run as Administrator"""

        # Import error
        if "import" in lower or "module" in lower:
            return """LOCAL FIX: Module not found.
1. Install: pip install <module_name>
2. Check virtual environment is active
3. Verify Python version compatibility"""

        # Connection refused
        if "connection refused" in lower or "10061" in lower:
            return """LOCAL FIX: Connection refused.
1. Check if the service is running
2. Verify the port number
3. Check firewall rules
4. Try: netstat -an | grep <port>"""

        # Syntax error
        if "syntax" in lower or "invalid syntax" in lower:
            return """LOCAL FIX: Syntax error.
1. Check for missing colons, brackets, or quotes
2. Verify indentation (tabs vs spaces)
3. Run: python -m py_compile <file>"""

        # Timeout
        if "timeout" in lower or "timed out" in lower:
            return """LOCAL FIX: Request timed out.
1. Increase timeout value
2. Check network connectivity
3. Verify the service is responsive"""

        return None

    def execute(self, task_id: str = "", diagnosis: str = "", context: dict = None) -> dict:
        self.status = "healing"
        audit.log(task_id, "doctor_start", "Generating patch")

        # Try local fix strategies first
        local_fix = self._local_fix_strategies(diagnosis)
        if local_fix:
            self.status = "idle"
            audit.log(task_id, "doctor_done", "Local fix applied")
            return {"patch": local_fix, "confidence": 0.8, "source": "local_strategy"}

        # Search for similar past fixes
        past_fixes = DB.execute(
            "SELECT fix_applied, success_count FROM learnings WHERE success_count > 0 ORDER BY success_count DESC LIMIT 3"
        ).fetchall()

        system = """You are an auto-healing agent. Generate a code patch or fix for the given error.
If similar past fixes exist, consider them. Provide a concrete, working solution."""

        prompt = f"Diagnosis: {diagnosis}\n\nPast successful fixes: {json.dumps(past_fixes)}\n\nGenerate a patch:"
        patch = llm.generate(prompt, system)

        self.status = "idle"
        audit.log(task_id, "doctor_done", f"Patch generated: {patch[:100]}")
        return {"patch": patch, "confidence": 0.7, "source": "llm"}

class EvolverAgent(Agent):
    def __init__(self):
        super().__init__("evolver", "Evolver")

    def execute(self, task_id: str = "", error: str = "", fix: str = "", success: bool = False) -> dict:
        self.status = "evolving"
        audit.log(task_id, "evolver_start", f"Learning from: {error[:60]}")

        # Find or create learning entry
        pattern = error[:200]
        row = DB.execute(
            "SELECT id, success_count, fail_count FROM learnings WHERE error_pattern = ?",
            (pattern,)
        ).fetchone()

        if row:
            if success:
                DB.execute("UPDATE learnings SET success_count = success_count + 1 WHERE id = ?", (row[0],))
            else:
                DB.execute("UPDATE learnings SET fail_count = fail_count + 1 WHERE id = ?", (row[0],))
        else:
            DB.execute(
                "INSERT INTO learnings (id, error_pattern, fix_applied, success_count, fail_count, created_at) VALUES (?,?,?,?,?,?)",
                (str(uuid.uuid4()), pattern, fix, 1 if success else 0, 0 if success else 1, datetime.now(timezone.utc).isoformat())
            )
        DB.commit()

        self.status = "idle"
        audit.log(task_id, "evolver_done", f"Pattern recorded: {pattern[:60]}")
        return {"learned": True}

# ============================================================
# ORCHESTRATOR
# ============================================================

class Orchestrator:
    def __init__(self):
        self.executor = ExecutorAgent()
        self.monitor = MonitorAgent()
        self.doctor = DoctorAgent()
        self.evolver = EvolverAgent()

    def execute(self, task_input: str, context: dict = None) -> dict:
        task_id = str(uuid.uuid4())
        ts = datetime.now(timezone.utc).isoformat()

        # Store task
        DB.execute(
            "INSERT INTO tasks (id, input, context, status, created_at) VALUES (?,?,?,?,?)",
            (task_id, task_input, json.dumps(context or {}), "running", ts)
        )
        DB.commit()
        audit.log(task_id, "task_created", f"Input: {task_input[:100]}")

        print(f"\n{'='*60}")
        print(f"  TASK: {task_id[:8]}...")
        print(f"  INPUT: {task_input[:80]}")
        print(f"{'='*60}")

        # Phase 1: Execute
        try:
            print("\n[1/5] Executor: running...")
            result = self.executor.execute(task_id=task_id, prompt=task_input, context=context or {})
            print(f"  [OK] Completed. Tokens: {result['tokens']}")

            DB.execute(
                "UPDATE tasks SET status='completed', result=?, completed_at=?, agent_id='executor' WHERE id=?",
                (json.dumps(result), datetime.now(timezone.utc).isoformat(), task_id)
            )
            DB.commit()
            audit.log(task_id, "task_completed", f"Tokens: {result['tokens']}")

            return {"id": task_id, "status": "completed", "result": result}

        except Exception as e:
            error_msg = str(e)
            print(f"  [FAIL] Failed: {error_msg}")

            # Phase 2: Monitor
            try:
                print("\n[2/5] Monitor: diagnosing...")
                diagnosis = self.monitor.execute(task_id=task_id, error=error_msg, context=context or {})
                print(f"  [OK] Diagnosis: {diagnosis['diagnosis'][:80]}...")

                # Phase 3: Doctor
                print("\n[3/5] Doctor: generating patch...")
                patch = self.doctor.execute(task_id=task_id, diagnosis=diagnosis["diagnosis"], context=context or {})
                print(f"  [OK] Patch generated. Confidence: {patch['confidence']}")

                if patch["confidence"] < 0.3:
                    print("  [FAIL] Confidence too low, cannot auto-fix")
                    self._fail_task(task_id, error_msg)
                    return {"id": task_id, "status": "failed", "error": error_msg}

                # Phase 4: Retry with fix
                print("\n[4/5] Executor: retrying with fix...")
                retry_prompt = f"{task_input}\n\n[APPLIED FIX]: {patch['patch']}"
                result = self.executor.execute(task_id=task_id, prompt=retry_prompt, context=context or {})
                print("  [OK] Healed and completed!")

                # Phase 5: Evolver
                print("\n[5/5] Evolver: learning from success...")
                self.evolver.execute(task_id=task_id, error=error_msg, fix=patch["patch"], success=True)

                DB.execute(
                    "UPDATE tasks SET status='completed', result=?, fix=?, completed_at=?, agent_id='executor-healed' WHERE id=?",
                    (json.dumps(result), patch["patch"], datetime.now(timezone.utc).isoformat(), task_id)
                )
                DB.commit()
                audit.log(task_id, "task_healed", f"Fix: {patch['patch'][:80]}")

                return {"id": task_id, "status": "healed", "result": result, "fix": patch["patch"]}

            except Exception as heal_error:
                # Phase 5: Evolver learns from failure
                print("\n[5/5] Evolver: learning from failure...")
                self.evolver.execute(task_id=task_id, error=error_msg, fix="", success=False)
                self._fail_task(task_id, error_msg)
                return {"id": task_id, "status": "failed", "error": str(heal_error)}

    def _fail_task(self, task_id: str, error: str):
        DB.execute(
            "UPDATE tasks SET status='failed', error=?, completed_at=? WHERE id=?",
            (error, datetime.now(timezone.utc).isoformat(), task_id)
        )
        DB.commit()
        audit.log(task_id, "task_failed", error[:200])

    def status(self) -> dict:
        """Resumen del sistema: conteos de tareas, learnings y cadena de auditoria."""
        total = DB.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
        completed = DB.execute("SELECT COUNT(*) FROM tasks WHERE status='completed'").fetchone()[0]
        healed = DB.execute("SELECT COUNT(*) FROM tasks WHERE status='healed'").fetchone()[0]
        failed = DB.execute("SELECT COUNT(*) FROM tasks WHERE status='failed'").fetchone()[0]
        learnings = DB.execute("SELECT COUNT(*) FROM learnings").fetchone()[0]
        chain_ok = audit.verify_chain()

        return {
            "tasks": {"total": total, "completed": completed, "healed": healed, "failed": failed},
            "learnings": learnings,
            "audit_chain": "valid" if chain_ok else "BROKEN",
            "db_path": str(DB_PATH)
        }

    def learnings(self) -> list:
        """Devuelve los patrones aprendidos, ordenados por exito descendente."""
        rows = DB.execute("SELECT error_pattern, fix_applied, success_count, fail_count FROM learnings ORDER BY success_count DESC").fetchall()
        return [{"pattern": r[0][:80], "fix": r[1][:80] if r[1] else None, "success": r[2], "failures": r[3]} for r in rows]

    def recent_tasks(self, limit: int = 10) -> list:
        """Devuelve las tareas mas recientes (limit por defecto = 10)."""
        rows = DB.execute("SELECT id, input, status, agent_id, created_at FROM tasks ORDER BY rowid DESC LIMIT ?", (limit,)).fetchall()
        return [{"id": r[0][:8], "input": r[1][:60], "status": r[2], "agent": r[3], "at": r[4]} for r in rows]

orchestrator = Orchestrator()

# ============================================================
# CLI
# ============================================================

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1]

    if cmd == "execute":
        if len(sys.argv) < 3:
            print("Usage: python paea.py execute \"task description\"")
            return
        task = " ".join(sys.argv[2:])
        result = orchestrator.execute(task)
        print(f"\n{'='*60}")
        print(f"  RESULT: {result['status'].upper()}")
        if result.get("result"):
            print(f"  OUTPUT: {result['result'].get('output', '')[:200]}")
        if result.get("error"):
            print(f"  ERROR: {result['error'][:200]}")
        print(f"{'='*60}")

    elif cmd == "status":
        s = orchestrator.status()
        print(json.dumps(s, indent=2))

    elif cmd == "tasks":
        tasks = orchestrator.recent_tasks()
        for t in tasks:
            print(f"  [{t['status']:>9}] {t['id']} | {t['input'][:50]} | agent: {t['agent']}")

    elif cmd == "learnings":
        learns = orchestrator.learnings()
        if not learns:
            print("  No learnings yet.")
        for l in learns:
            print(f"  [OK] {l['success']}x | [FAIL] {l['failures']}x | {l['pattern']}")
            if l["fix"]:
                print(f"    Fix: {l['fix'][:80]}")

    elif cmd == "audit":
        ok = audit.verify_chain()
        print(f"  Audit chain: {'VALID' if ok else 'BROKEN'}")
        rows = DB.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        print(f"  Total entries: {rows}")

    elif cmd == "consent":
        if len(sys.argv) < 4:
            print("Usage: python paea.py consent <user_id> <type> <yes|no>")
            return
        user_id, ctype, granted = sys.argv[2], sys.argv[3], sys.argv[4].lower() == "yes"
        cid = str(uuid.uuid4())
        DB.execute(
            "INSERT OR REPLACE INTO consents (id, user_id, consent_type, granted, jurisdiction, timestamp) VALUES (?,?,?,?,?,?)",
            (cid, user_id, ctype, int(granted), "EU", datetime.now(timezone.utc).isoformat())
        )
        DB.commit()
        print(f"  Consent {'granted' if granted else 'revoked'}: {ctype} for {user_id}")

    elif cmd == "verify":
        ok = audit.verify_chain()
        print(f"  Audit integrity: {'PASS' if ok else 'FAIL'}")
        if not ok:
            print("  Chain broken — possible tampering detected!")

    elif cmd == "serve":
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
        start_web_server(port)

    elif cmd == "interactive":
        start_repl()

    elif cmd == "help":
        print(__doc__)

    else:
        print(f"  Unknown command: {cmd}")
        print(__doc__)

if __name__ == "__main__":
    main()
