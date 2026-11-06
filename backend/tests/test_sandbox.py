"""Sandbox for agent-written code: static policy, runtime guard and process isolation."""
import tempfile
from pathlib import Path

import pytest

from app.modules.simulator.sandbox import _execute_code_safely, _run, check_code

ADD = "def add(a, b):\n    return a + b\n"
ADD_TEST = ("import unittest\nfrom solution import add\n\nclass T(unittest.TestCase):\n"
            "    def test_add(self):\n        self.assertEqual(add(2, 3), 5)\n")


def test_good_code_and_tests_pass():
    ok, msg = _execute_code_safely(ADD, ADD_TEST)
    assert ok and "passed in the sandbox" in msg


def test_wrong_code_fails_its_tests():
    ok, msg = _execute_code_safely(ADD.replace("+", "-"), ADD_TEST)
    assert not ok and "Unit tests failed" in msg


def test_timeout():
    ok, msg = _execute_code_safely("while True:\n    pass\n", timeout=2)
    assert not ok and "timed out" in msg


# ------------------------------------------------------------ layer 1: static policy
@pytest.mark.parametrize("code,needle", [
    ("import os\nos.system('whoami')", "imports 'os'"),
    ("import subprocess", "imports 'subprocess'"),
    ("from socket import socket", "imports 'socket'"),
    ("import importlib\nimportlib.import_module('os')", "imports 'importlib'"),
    ("import ctypes", "imports 'ctypes'"),
    ("open('x.txt', 'w')", "calls 'open()'"),
    ("eval('1+1')", "calls 'eval()'"),
    ("__import__('os')", "calls '__import__()'"),
    ("getattr(1, 'real')", "calls 'getattr()'"),
    ("().__class__.__bases__[0].__subclasses__()", "accesses '.__"),
    ("(lambda: 0).__globals__", "accesses '.__globals__'"),
    ("print(__builtins__)", "uses '__builtins__'"),
])
def test_static_policy_refuses(code, needle):
    reason = check_code(code)
    assert reason and needle in reason


@pytest.mark.parametrize("code", [
    "import math, json, re, collections, itertools, functools, dataclasses, typing, unittest",
    "from collections import Counter\nprint(Counter('aab').most_common(1))",
    "class A:\n    def __init__(self):\n        super().__init__()\n    def __repr__(self):\n        return 'A'",
])
def test_static_policy_allows_ordinary_code(code):
    assert check_code(code) is None


def test_tests_are_checked_too():
    ok, msg = _execute_code_safely(ADD, "import os\nos.system('whoami')")
    assert not ok and "test_solution.py" in msg


# ------------------------------------------------------------ layer 2: runtime guard (static check bypassed)
OUTSIDE = (Path(tempfile.gettempdir()) / "swarmguard_sandbox_probe.txt").as_posix()
HOME = Path.home().as_posix()


@pytest.mark.parametrize("code", [
    f"open({OUTSIDE!r}, 'w').write('pwned')",
    f"import os\nprint(os.listdir({HOME!r}))",
    f"open({(Path(HOME) / 'some_private_file.txt').as_posix()!r}).read()",
    "import os\nos.system('whoami')",
    "import subprocess\nsubprocess.run(['whoami'])",
    "import socket\nsocket.create_connection(('example.com', 80), timeout=2)",
    "import ctypes\nctypes.CDLL('kernel32')",
    "import os\nos.putenv('X', '1')",
    # Hooks can't be removed; adding another is refused and the guard still applies afterwards.
    "import sys, os\nsys.addaudithook(lambda *a: None)\nos.system('whoami')",
], ids=["write-outside", "list-home", "read-home", "os.system", "subprocess", "network", "ctypes", "putenv",
        "remove-guard"])
def test_runtime_guard_blocks(tmp_path, code):
    (tmp_path / "solution.py").write_text(code, encoding="utf-8")
    res = _run(tmp_path, "solution", 15)
    assert res.returncode != 0 and "PermissionError: sandbox:" in res.stderr
    assert not Path(OUTSIDE).exists()


def test_runtime_guard_allows_work_inside_the_sandbox(tmp_path):
    (tmp_path / "solution.py").write_text("open('scratch.txt', 'w').write('ok')\nprint(open('scratch.txt').read())")
    res = _run(tmp_path, "solution", 15)
    assert res.returncode == 0 and res.stdout.strip() == "ok"
