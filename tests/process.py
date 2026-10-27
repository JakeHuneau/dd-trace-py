"""Process execution for test scenarios, independent of pytest and ddtrace."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from collections.abc import Iterator
from collections.abc import Mapping
from contextlib import contextmanager
from importlib.abc import MetaPathFinder
from importlib.machinery import PathFinder
from importlib.machinery import SourceFileLoader
import importlib.util
import inspect
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryFile
import time
from typing import Any
from typing import NamedTuple
from typing import Optional
from typing import Union
import unittest

from tests._ddtest_env_helpers import strip_ddtest_leaked_env


DEFAULT_TIMEOUT = 60.0
CLEANUP_TIMEOUT = 5.0

# Prefer the wrapper installed with the running interpreter: the first ddtrace-run found on PATH may
# belong to another environment and import a ddtrace build that does not match sys.executable.
DDTRACE_RUN: str = shutil.which("ddtrace-run", path=os.path.dirname(sys.executable)) or "ddtrace-run"


class ProcessResult(NamedTuple):
    stdout: Union[bytes, str]
    stderr: Union[bytes, str]
    returncode: int
    pid: int

    def check_returncode(self, expected: int = 0) -> ProcessResult:
        if self.returncode != expected:
            raise AssertionError(
                f"Expected exit status {expected}, got {self.returncode}.\n"
                f"STDOUT:\n{self.stdout!r}\nSTDERR:\n{self.stderr!r}"
            )
        return self


def child_environment(
    env: Optional[Mapping[str, Optional[str]]] = None,
    overrides: Optional[Mapping[str, Optional[str]]] = None,
) -> dict[str, str]:
    result = {key: value for key, value in (os.environ if env is None else env).items() if value is not None}
    for key, value in (overrides or {}).items():
        if value is None:
            result.pop(key, None)
        else:
            result[key] = value
    return strip_ddtest_leaked_env(result)


def run_process(
    *args: str,
    env: Optional[Mapping[str, Optional[str]]] = None,
    env_overrides: Optional[Mapping[str, Optional[str]]] = None,
    timeout: Optional[float] = DEFAULT_TIMEOUT,
    **kwargs: Any,
) -> ProcessResult:
    """Run a command without changing its session, process group, or working directory."""
    kwargs.setdefault("close_fds", sys.platform != "win32")
    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=child_environment(env, env_overrides),
        **kwargs,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException as error:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=CLEANUP_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                stdout, stderr = process.communicate(timeout=CLEANUP_TIMEOUT)
            except subprocess.TimeoutExpired as remaining:
                stdout, stderr = remaining.output, remaining.stderr
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
                process.wait(timeout=CLEANUP_TIMEOUT)
        if isinstance(error, subprocess.TimeoutExpired):
            error.output, error.stderr = stdout, stderr
        raise
    return ProcessResult(stdout, stderr, process.returncode, process.pid)


class ManagedProcess:
    """A running application whose output cannot fill a pipe while its parent interacts with it."""

    def __init__(self, args: list[str], **kwargs: Any) -> None:
        self._stdout = TemporaryFile()
        self._stderr = TemporaryFile()
        env = child_environment(
            kwargs.pop("env", None),
            kwargs.pop("env_overrides", None),
        )
        try:
            self.process = subprocess.Popen(
                args,
                stdout=self._stdout,
                stderr=self._stderr,
                env=env,
                **kwargs,
            )
        except BaseException:
            self._stdout.close()
            self._stderr.close()
            raise

    @property
    def pid(self) -> int:
        return self.process.pid

    def _result(self) -> ProcessResult:
        self._stdout.seek(0)
        self._stderr.seek(0)
        return ProcessResult(self._stdout.read(), self._stderr.read(), self.process.returncode, self.pid)

    def wait(self, timeout: float = DEFAULT_TIMEOUT) -> ProcessResult:
        self.process.wait(timeout=timeout)
        return self._result()

    def wait_until(self, ready: Callable[[], bool], timeout: float = DEFAULT_TIMEOUT) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(f"Application exited before becoming ready: {self._result()!r}")
            if ready():
                return
            time.sleep(0.01)
        raise TimeoutError(f"Application {self.pid} did not become ready within {timeout}s")

    def close(self) -> None:
        try:
            self.process.terminate()
            try:
                self.process.wait(timeout=CLEANUP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=CLEANUP_TIMEOUT)
        finally:
            self._stdout.close()
            self._stderr.close()


class PythonProcess:
    """Write application source under a stable service-name directory and run it."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        (self.directory / "__init__.py").touch()
        self._sequence = 0

    def _source(self, code: str) -> Path:
        self._sequence += 1
        path = self.directory / ("test.py" if self._sequence == 1 else f"test_{self._sequence}.py")
        path.write_text(code, encoding="utf-8")
        return path

    @staticmethod
    def _command(target: str, args: tuple[str, ...], ddtrace_run: bool) -> list[str]:
        return ([DDTRACE_RUN] if ddtrace_run else []) + [sys.executable] + [target, *args]

    def __call__(
        self, code: str, *, args: tuple[str, ...] = (), ddtrace_run: bool = False, **kwargs: Any
    ) -> ProcessResult:
        return run_process(*self._command(str(self._source(code)), args, ddtrace_run), **kwargs)

    @contextmanager
    def start(
        self, code: str, *, args: tuple[str, ...] = (), ddtrace_run: bool = False, **kwargs: Any
    ) -> Iterator[ManagedProcess]:
        with self.start_file(self._source(code), args=args, ddtrace_run=ddtrace_run, **kwargs) as process:
            yield process

    @contextmanager
    def start_file(
        self, path: Union[str, Path], *, args: tuple[str, ...] = (), ddtrace_run: bool = False, **kwargs: Any
    ) -> Iterator[ManagedProcess]:
        process = ManagedProcess(self._command(str(path), args, ddtrace_run), **kwargs)
        try:
            yield process
        finally:
            process.close()


class _TestSourceLoader(SourceFileLoader):
    def get_code(self, fullname: str) -> Any:
        filename = self.get_filename(fullname)
        return compile(self.get_data(filename), filename, "exec", dont_inherit=True, optimize=0)


class _TestAssertionFinder(MetaPathFinder):
    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        if not fullname.startswith("tests."):
            return None
        spec = PathFinder.find_spec(fullname, path, target)
        if spec is not None and isinstance(spec.loader, SourceFileLoader):
            spec.loader = _TestSourceLoader(fullname, spec.loader.path)
        return spec


def enable_test_assertions() -> None:
    """Preserve assertions in child test helpers without changing product optimization."""
    if not sys.flags.optimize or any(isinstance(finder, _TestAssertionFinder) for finder in sys.meta_path):
        return
    sys.meta_path.insert(sys.meta_path.index(PathFinder), _TestAssertionFinder())


def _invoke_case_method(case: Any, method_name: str) -> None:
    result = getattr(case, method_name)()
    if inspect.isawaitable(result):
        loop = getattr(case, "loop", None)
        if loop is None:

            async def await_result():
                return await result

            asyncio.run(await_result())
        else:
            loop.run_until_complete(result)


def _call_xunit(hook: Any, argument: Any) -> None:
    if hook is not None:
        hook(argument) if inspect.signature(hook).parameters else hook()


@contextmanager
def _pytest_case_context(case_type: type, method_name: str) -> Iterator[Any]:
    _call_xunit(getattr(case_type, "setup_class", None), case_type)
    try:
        case = case_type()
        method = getattr(case, method_name)
        _call_xunit(getattr(case, "setup_method", None), method)
        try:
            yield case
        finally:
            _call_xunit(getattr(case, "teardown_method", None), method)
    finally:
        _call_xunit(getattr(case_type, "teardown_class", None), case_type)


def run_class_method(module_name: str, class_name: str, method_name: str) -> None:
    """Execute the original method with child-local state, without starting pytest."""
    enable_test_assertions()
    spec = importlib.util.find_spec(module_name)
    if spec is None or spec.origin is None:
        raise ImportError(module_name)
    # Test modules outside tests.* also need assertions when Python is optimized.
    spec.loader = _TestSourceLoader(module_name, spec.origin)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    case_type: Any = module
    for component in class_name.split("."):
        case_type = getattr(case_type, component)
    lifecycle = case_context if issubclass(case_type, unittest.TestCase) else _pytest_case_context
    method = getattr(case_type, method_name)
    if getattr(method, "__unittest_skip__", False):
        raise unittest.SkipTest(method.__unittest_skip_why__)
    with lifecycle(case_type, method_name) as case:
        _invoke_case_method(case, method_name)


@contextmanager
def case_context(case_type: type[unittest.TestCase], method_name: str = "runTest") -> Iterator[Any]:
    """Reuse a unittest class's lifecycle inside an explicit child scenario."""
    if not __debug__ and not any(isinstance(finder, _TestAssertionFinder) for finder in sys.meta_path):
        raise RuntimeError("Class-based scenarios require Python assertions to be enabled")
    if getattr(case_type, "__unittest_skip__", False):
        raise unittest.SkipTest(getattr(case_type, "__unittest_skip_why__", "class skipped"))
    case: Any = case_type(method_name)
    loop: Any = None
    try:
        case_type.setUpClass()
        try:
            try:
                case.setUp()
                loop = getattr(case, "loop", None)
                try:
                    yield case
                finally:
                    teardown = case.tearDown()
                    if hasattr(teardown, "__await__"):
                        loop.run_until_complete(teardown)
            finally:
                if not case.doCleanups():
                    raise AssertionError("Test case cleanup failed")
        finally:
            case_type.tearDownClass()
    finally:
        try:
            case_type.doClassCleanups()
            errors = getattr(case_type, "tearDown_exceptions", ())
            if errors:
                raise errors[0][1]
        finally:
            loop = getattr(case, "loop", None) or loop
            if loop is not None and not loop.is_closed():
                loop.close()
