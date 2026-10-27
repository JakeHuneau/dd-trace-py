import os
import subprocess
import sys

import pytest

from tests.process import child_environment
from tests.process import run_process


def test_runner_import_does_not_initialize_ddtrace():
    result = run_process(sys.executable, "-c", "import tests.process, sys; assert 'ddtrace' not in sys.modules")
    result.check_returncode()


def test_environment_overlay_and_replacement(monkeypatch):
    monkeypatch.setenv("PROCESS_PARENT", "parent")
    monkeypatch.setenv("PYTEST_ADDOPTS", "--ddtrace")
    assert child_environment({}, {"CHILD": "child"}) == {"CHILD": "child"}
    env = child_environment(overrides={"PROCESS_PARENT": None, "CHILD": "child"})
    assert "PROCESS_PARENT" not in env
    assert "PYTEST_ADDOPTS" not in env
    assert env["CHILD"] == "child"
    assert os.environ["PROCESS_PARENT"] == "parent"


@pytest.mark.parametrize("ddtrace_run", [False, True])
def test_result_unpacking(python_process, ddtrace_run):
    result = python_process(
        "import os, sys; print(os.getpid()); sys.stderr.write('failure'); sys.exit(7)",
        ddtrace_run=ddtrace_run,
    )
    out, err, status, pid = result
    assert int(out) == pid
    assert pid != os.getpid()
    assert err == b"failure"
    assert status == 7
    assert isinstance(result, tuple)
    result.check_returncode(7)


def test_timeout_is_failure_and_reaps_child(python_process, tmp_path):
    pidfile = tmp_path / "pid"
    code = f"import os, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); time.sleep(30)"
    with pytest.raises(subprocess.TimeoutExpired):
        python_process(code, timeout=1)
    with pytest.raises(ProcessLookupError):
        os.kill(int(pidfile.read_text()), 0)


def test_managed_cleanup_on_parent_failure(python_process, tmp_path):
    ready = tmp_path / "ready"
    with pytest.raises(ValueError, match="parent"):
        with python_process.start(
            f"import pathlib, time; pathlib.Path({str(ready)!r}).touch(); time.sleep(30)"
        ) as child:
            child.wait_until(ready.exists)
            pid = child.pid
            raise ValueError("parent")
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_child_helper_assertions_preserve_product_optimization(tmp_path):
    helper = tmp_path / "process_assertion_helper.py"
    helper.write_text(
        "import unittest\n"
        "class Case(unittest.TestCase):\n"
        "    def runTest(self):\n"
        "        assert False, 'helper assertion'\n"
    )
    (tmp_path / "optimized_product.py").write_text("debug = __debug__\n")
    result = run_process(
        sys.executable,
        "-c",
        f"""
import sys
import tests
from tests.process import case_context, enable_test_assertions
sys.path.insert(0, {str(tmp_path)!r})
tests.__path__.append({str(tmp_path)!r})
enable_test_assertions()
from tests.process_assertion_helper import Case
import optimized_product
if optimized_product.debug or not sys.flags.optimize:
    raise RuntimeError("product optimization was disabled")
with case_context(Case) as case:
    case.runTest()
""",
        env_overrides={"PYTHONOPTIMIZE": "1"},
    )
    result.check_returncode(1)
    assert b"AssertionError: helper assertion" in result.stderr
