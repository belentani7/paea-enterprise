#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests para PAEA (sin requerir servidor ni LLM).

Usa una base de datos temporal redirigida con PAEA_DB_PATH para no tocar
la base real en ~/.paea.

Ejecutar:
    python test_paea.py
o:
    python -m unittest test_paea -v
"""
import os
import sqlite3
import threading
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Redirige la DB a un directorio temporal ANTES de importar el modulo.
_TMP = Path(tempfile.mkdtemp(prefix="paea_test_"))
os.environ["PAEA_DB_PATH"] = str(_TMP / "paea_test.db")
os.environ["PAEA_LLM_PROVIDER"] = "mock"

sys.path.insert(0, str(Path(__file__).resolve().parent))
import paea


class TestAuditLedger(unittest.TestCase):
    """Verificacion de la cadena de hashes (tamper-evident)."""

    def setUp(self):
        self.conn = paea.init_db()
        self.conn.execute("DELETE FROM audit_log")
        self.conn.commit()
        self.audit = paea.AuditLedger(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_empty_chain_valid(self):
        self.assertTrue(self.audit.verify_chain())

    def test_log_and_verify(self):
        h1 = self.audit.log("t1", "test", "detail")
        h2 = self.audit.log("t2", "test2", "other")
        self.assertTrue(self.audit.verify_chain())
        self.assertNotEqual(h1, h2)
        self.assertNotEqual(h1, "0" * 64)
        self.assertEqual(len(h1), 64)

    def test_concurrent_audit_writes_preserve_hash_chain(self):
        """Two web threads must not read the same previous audit hash."""
        conn = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute(
            "CREATE TABLE audit_log (id TEXT, task_id TEXT, event_type TEXT, "
            "detail TEXT, timestamp TEXT, hash_prev TEXT, hash_current TEXT)"
        )
        second_read = threading.Event()
        read_lock = threading.Lock()
        reads = 0

        class InterleavedConnection:
            def execute(self, sql, params=()):
                cursor = conn.execute(sql, params)
                if not sql.startswith("SELECT hash_current"):
                    return cursor

                class PausedCursor:
                    def fetchone(self):
                        nonlocal reads
                        row = cursor.fetchone()
                        with read_lock:
                            reads += 1
                            number = reads
                        if number == 1:
                            second_read.wait(timeout=0.3)
                        elif number == 2:
                            second_read.set()
                        return row

                return PausedCursor()

            def commit(self):
                conn.commit()

        ledger = paea.AuditLedger(InterleavedConnection())
        errors = []

        def write(number):
            try:
                ledger.log(str(number), "concurrent", "event")
            except Exception as exc:
                errors.append(str(exc))

        threads = [threading.Thread(target=write, args=(n,)) for n in range(2)]
        try:
            for worker in threads:
                worker.start()
            for worker in threads:
                worker.join(timeout=3)
            self.assertFalse(any(worker.is_alive() for worker in threads))
            self.assertEqual(errors, [])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0], 2)
            self.assertTrue(ledger.verify_chain())
        finally:
            for worker in threads:
                worker.join(timeout=3)
            conn.close()

    def test_tamper_detected(self):
        self.audit.log("t1", "test", "detail")
        self.audit.log("t2", "test2", "other")
        # Manipular el hash de un bloque rompe la cadena.
        self.conn.execute(
            "UPDATE audit_log SET hash_current = 'deadbeef' WHERE rowid = 1"
        )
        self.conn.commit()
        self.assertFalse(self.audit.verify_chain())

    def test_payload_tamper_detected_even_when_links_match(self):
        self.audit.log("t1", "test", "original")
        self.audit.log("t2", "other", "next")
        self.conn.execute(
            "UPDATE audit_log SET detail='tampered' WHERE rowid=1"
        )
        self.conn.commit()
        self.assertFalse(self.audit.verify_chain())

    def test_deleted_tail_not_detectable_without_external_anchor(self):
        """Hash chains cannot detect removed suffixes without an external anchor."""
        self.audit.log("t1", "test", "first")
        self.audit.log("t2", "test", "second")
        self.conn.execute("DELETE FROM audit_log WHERE rowid=2")
        self.conn.commit()
        self.assertTrue(self.audit.verify_chain())

    def test_uses_named_columns(self):
        """verify_chain no debe depender de indices posicionales."""
        self.audit.log("t1", "test", "x")
        rows = self.conn.execute(
            f"SELECT {paea.AuditLedger.COL_HASH_PREV}, {paea.AuditLedger.COL_HASH_CURRENT} FROM audit_log"
        ).fetchall()
        row = rows[0]
        # sqlite3.Row soporta acceso por nombre.
        self.assertIn(paea.AuditLedger.COL_HASH_CURRENT, row.keys())


class TestOrchestrator(unittest.TestCase):
    """Estado y consultas del orquestador."""

    def test_status_shape(self):
        s = paea.orchestrator.status()
        self.assertIn("tasks", s)
        self.assertIn("learnings", s)
        self.assertIn("audit_chain", s)
        self.assertIn("db_path", s)
        self.assertEqual(s["audit_chain"], "valid")

    def test_learnings_list(self):
        self.assertIsInstance(paea.orchestrator.learnings(), list)

    def test_recent_tasks_list(self):
        self.assertIsInstance(paea.orchestrator.recent_tasks(), list)

    def test_execute_local_action_file_read(self):
        f = _TMP / "hello_paea.txt"
        f.write_text("hola desde el test", encoding="utf-8")
        agent = paea.ExecutorAgent()
        res = agent._try_local_action(f"lee el archivo {f}")
        self.assertIsNotNone(res)
        self.assertIn("[FILE READ]", res)
        self.assertIn("hola desde el test", res)

    def test_execute_local_action_file_read_unicode_spaces(self):
        folder = _TMP / "carpeta con espacios"
        folder.mkdir(exist_ok=True)
        target = folder / "niño guía.txt"
        target.write_text("lectura de ruta completa", encoding="utf-8")
        agent = paea.ExecutorAgent()
        result = agent._try_local_action(f"lee el archivo {target}")
        self.assertIn("[FILE READ]", result)
        self.assertIn("lectura de ruta completa", result)

    def test_create_file_action_not_misclassified_as_read(self):
        """Create must reach the write handler instead of failing file lookup."""
        target = _TMP / "factory_new_note.txt"
        if target.exists():
            target.unlink()
        agent = paea.ExecutorAgent()
        result = agent._try_local_action(
            f'crea archivo {target} con contenido: "contenido nuevo"'
        )
        self.assertTrue(result.startswith("[FILE CREATED]"), result)
        self.assertEqual(target.read_text(encoding="utf-8"), "contenido nuevo")

    def test_write_existing_file_action_not_misclassified_as_read(self):
        """Explicit write replaces a file instead of returning its old contents."""
        target = _TMP / "factory_existing_note.txt"
        target.write_text("anterior", encoding="utf-8")
        agent = paea.ExecutorAgent()
        result = agent._try_local_action(
            f'write {target} content: "actualizado"'
        )
        self.assertTrue(result.startswith("[FILE CREATED]"), result)
        self.assertEqual(target.read_text(encoding="utf-8"), "actualizado")

    def test_execute_local_action_count_files(self):
        d = _TMP / "countme"
        d.mkdir(exist_ok=True)
        (d / "a.txt").write_text("x", encoding="utf-8")
        (d / "b.md").write_text("y", encoding="utf-8")
        agent = paea.ExecutorAgent()
        res = agent._try_local_action(f"cuantos archivos hay en {d}")
        self.assertIsNotNone(res)
        self.assertIn("[COUNT]", res)
        self.assertIn("2", res)

    def test_run_process_handles_missing_binary(self):
        """El helper de subprocess no crashea con binarios inexistentes."""
        agent = paea.ExecutorAgent()
        out = agent._run_process(["binary_que_no_existe_xyz"], timeout=5)
        self.assertIn("PROCESS ERROR", out)

    def test_git_command_splits_args(self):
        """'git log --oneline' no debe pasarse como un unico argumento."""
        agent = paea.ExecutorAgent()
        res = agent._try_local_action("git status --short")
        self.assertIsNotNone(res)
        self.assertTrue(res.startswith("[GIT status --short]"))


class TestConfig(unittest.TestCase):
    def test_db_path_env_override(self):
        self.assertEqual(os.environ["PAEA_DB_PATH"], str(paea.DB_PATH))

    def test_provider_env(self):
        self.assertEqual(paea.Config.LLM_PROVIDER, "mock")


class TestWebHelpers(unittest.TestCase):
    def test_paea_db_schema(self):
        """Las tablas core existen."""
        conn = paea.init_db()
        tables = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        conn.close()
        for t in ("tasks", "audit_log", "learnings", "consents"):
            self.assertIn(t, tables)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        if hasattr(paea, "DB"):
            try:
                paea.DB.close()
            except Exception:
                pass
        shutil.rmtree(_TMP, ignore_errors=True)
