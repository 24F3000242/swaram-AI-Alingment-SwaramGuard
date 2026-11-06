"""Sandboxed execution of agent-written code (user-directed tasks).

Agents (possibly LLM-driven) write Python that the team then runs to check it works. Three
layers, because none is enough alone (CPython's audit hooks are explicitly not a sandbox):

1. Static check: the code may only import an allowlist of harmless standard-library modules and
   may not call eval/exec/open/__import__/getattr or touch interpreter escape hatches.
2. Runtime guard: an audit hook, installed before any generated code runs, denies file reads
   outside the sandbox folder and Python's own install, any write outside the sandbox folder,
   process creation, networking, ctypes, the registry and environment changes.
3. Process isolation: a fresh temp folder per run, isolated interpreter (-I -B), a minimal
   environment (no API keys) and a timeout.

On by default. Set SWARMGUARD_CODE_EXEC=off to never run agent-written code.
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
import tempfile
from pathlib import Path

CODE_EXEC_FLAG = "SWARMGUARD_CODE_EXEC"  # "sandbox" (default) | "off"

ALLOWED_IMPORTS = frozenset({
    "__future__", "abc", "array", "bisect", "calendar", "cmath", "collections", "contextlib", "copy", "dataclasses",
    "datetime", "decimal", "enum", "fractions", "functools", "heapq", "itertools", "json", "math", "numbers",
    "operator", "random", "re", "statistics", "string", "textwrap", "time", "typing", "unittest", "uuid",
    "solution", "test_solution",
})
BLOCKED_CALLS = frozenset({"eval", "exec", "compile", "__import__", "open", "input", "breakpoint", "globals", "locals",
                           "vars", "getattr", "setattr", "delattr", "memoryview"})
BLOCKED_NAMES = frozenset({"__builtins__", "__import__", "__loader__", "__spec__"})
# Attributes used to climb from any object to arbitrary interpreter internals.
BLOCKED_ATTRS = frozenset({"__class__", "__bases__", "__base__", "__subclasses__", "__mro__", "__globals__", "__builtins__",
                           "__code__", "__closure__", "__func__", "__self__", "__dict__", "__getattribute__", "__reduce__",
                           "__reduce_ex__", "__import__", "__loader__", "__spec__", "f_globals", "f_locals", "f_back",
                           "f_builtins", "gi_frame", "cr_frame", "tb_frame", "co_code"})

BOOT = r'''
import os, sys
SANDBOX = os.path.normcase(os.path.realpath(sys.argv[1]))
MODE = sys.argv[2]
READ_ROOTS = [SANDBOX] + [os.path.normcase(os.path.realpath(p))
                          for p in {sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix} if p]
DENY_PREFIXES = ("os.system", "os.exec", "os.spawn", "os.posix_spawn", "os.fork", "os.kill", "os.startfile",
                 "os.putenv", "os.unsetenv", "os.link", "os.symlink", "os.chmod", "os.chown", "subprocess.",
                 "socket.", "ctypes.", "winreg.", "_winapi.", "msvcrt.", "urllib.", "webbrowser.", "shutil.",
                 "sys.addaudithook", "sys.settrace", "sys.setprofile", "pty.", "resource.", "signal.")
PATH_EVENTS = {"os.remove": True, "os.rename": True, "os.rmdir": True, "os.mkdir": True, "os.truncate": True,
               "os.utime": True, "os.listdir": False, "os.scandir": False, "os.chdir": False}
WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_TRUNC", 0)

def _inside(path, roots):
    p = os.path.normcase(os.path.realpath(os.fsdecode(path)))
    return any(p == r or p.startswith(r + os.sep) for r in roots)

def _guard(event, args):
    if event == "open":
        path, mode, flags = (list(args) + [None, None, None])[:3]
        if path is None or isinstance(path, int):
            return
        writing = bool(mode and any(c in mode for c in "wax+")) or bool(flags and flags & WRITE_FLAGS)
        if not _inside(path, [SANDBOX] if writing else READ_ROOTS):
            raise PermissionError(f"sandbox: {'write' if writing else 'read'} outside the sandbox is not allowed")
    elif event in PATH_EVENTS:
        roots = [SANDBOX] if PATH_EVENTS[event] else READ_ROOTS
        for a in args:
            if isinstance(a, (str, bytes, os.PathLike)) and not _inside(a, roots):
                raise PermissionError(f"sandbox: {event} outside the sandbox is not allowed")
    elif event.startswith(DENY_PREFIXES):
        raise PermissionError(f"sandbox: {event} is not allowed")

os.chdir(SANDBOX)
sys.path.insert(0, SANDBOX)
sys.addaudithook(_guard)  # from here on, nothing can remove or bypass it

import runpy
if MODE == "tests":
    import unittest
    suite = unittest.defaultTestLoader.loadTestsFromName("test_solution")
    if suite.countTestCases() == 0:
        runpy.run_path("test_solution.py", run_name="__main__")
        sys.exit(0)
    sys.exit(0 if unittest.TextTestRunner(stream=sys.stderr, verbosity=1).run(suite).wasSuccessful() else 1)
runpy.run_path("solution.py", run_name="__main__")
'''


def _code_exec_allowed() -> bool:
    return os.getenv(CODE_EXEC_FLAG, "sandbox").strip().lower() != "off"


def _child_env() -> dict[str, str]:
    """Minimal environment for generated code: no API keys or other secrets are inherited."""
    keep = ("PATH", "SYSTEMROOT", "TEMP", "TMP")
    return {k: os.environ[k] for k in keep if k in os.environ} | {"PYTHONDONTWRITEBYTECODE": "1"}


def check_code(code: str, filename: str = "solution.py") -> str | None:
    """Static policy check. Returns the reason the code is refused, or None if it may run."""
    try:
        tree = ast.parse(code, filename=filename)
    except SyntaxError as exc:
        return f"{filename} has a syntax error at line {exc.lineno}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            mods = [node.module or ""] if node.level == 0 else []
        else:
            mods = []
        for m in mods:
            if m.split(".")[0] not in ALLOWED_IMPORTS:
                return f"{filename}:{node.lineno} imports '{m}', which isn't on the sandbox allowlist"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in BLOCKED_CALLS:
            return f"{filename}:{node.lineno} calls '{node.func.id}()', which the sandbox doesn't allow"
        if isinstance(node, ast.Name) and node.id in BLOCKED_NAMES:
            return f"{filename}:{node.lineno} uses '{node.id}', which the sandbox doesn't allow"
        if isinstance(node, ast.Attribute) and node.attr in BLOCKED_ATTRS:
            return f"{filename}:{node.lineno} accesses '.{node.attr}', which the sandbox doesn't allow"
    return None


def _run(tmp: Path, mode: str, timeout: float) -> subprocess.CompletedProcess:
    boot = tmp / "_swarmguard_boot.py"
    boot.write_text(BOOT, encoding="utf-8")
    return subprocess.run([sys.executable, "-I", "-B", str(boot), str(tmp), mode], cwd=str(tmp), env=_child_env(),
                          capture_output=True, text=True, timeout=timeout)


def _execute_code_safely(sol_code: str, test_code: str = "", timeout: float = 6.0) -> tuple[bool, str]:
    """Run agent-written code (and its tests) in the sandbox. Returns (passed, explanation)."""
    if not _code_exec_allowed():
        return False, f"Code execution is turned off ({CODE_EXEC_FLAG}=off)"
    has_tests = bool(test_code and test_code.strip())
    for code, name in ((sol_code, "solution.py"), (test_code, "test_solution.py") if has_tests else ("", "")):
        if name:
            refused = check_code(code, name)
            if refused:
                return False, f"Sandbox refused to run the code: {refused}"
    with tempfile.TemporaryDirectory(prefix="swarmguard-sandbox-") as tmp_dir:
        tmp = Path(tmp_dir)
        (tmp / "solution.py").write_text(sol_code, encoding="utf-8")
        if has_tests:
            (tmp / "test_solution.py").write_text(test_code, encoding="utf-8")
        try:
            res = _run(tmp, "tests" if has_tests else "solution", timeout)
        except subprocess.TimeoutExpired:
            return False, f"{'Unit tests' if has_tests else 'Execution'} timed out after {timeout}s"
        except Exception as exc:  # pragma: no cover - launcher failure
            return False, f"Execution error: {exc}"
        out = (res.stderr or res.stdout).strip()
        blocked = [line for line in out.splitlines() if line.startswith("PermissionError: sandbox:")]
        if blocked and res.returncode != 0:
            return False, f"Sandbox blocked a dangerous action: {blocked[-1].split('sandbox:', 1)[1].strip()}"
        if res.returncode == 0:
            return True, (f"All unit tests passed in the sandbox. Output: {out[:150]}" if has_tests
                          else "Solution ran successfully in the sandbox")
        return False, f"{'Unit tests failed' if has_tests else 'Solution failed'} (exit code {res.returncode}): {out[:200]}"
