#!/usr/bin/env python3
from ast import unparse
import logging
import os
import sys
import textwrap
from unittest import mock

import pytest

from ddtrace.appsec._iast._ast import iastpatch
from ddtrace.appsec._iast._ast.ast_patching import astpatch_module
from ddtrace.appsec._iast._ast.ast_patching import visit_ast
from ddtrace.appsec._iast._constants import IAST
from ddtrace.internal.utils.formats import asbool
from tests.utils import DDTRACE_PATH
from tests.utils import call_program
from tests.utils import override_env


_PREFIX = IAST.PATCH_ADDED_SYMBOL_PREFIX


@pytest.mark.parametrize(
    "source_text, module_path, module_name",
    [
        ("print('hi')", "test.py", "test"),
        ("print('str')", "test.py", "test"),
        ("str", "test.py", "test"),
    ],
)
def test_visit_ast_unchanged(source_text, module_path, module_name):
    """
    Source texts not containing:
    - str() calls
    - [...]  // To be filled with more aspects
    won't be modified by ast patching, so will return empty string
    """
    assert visit_ast(source_text, module_path, module_name) is None


@pytest.mark.parametrize(
    "source_text, module_path, module_name",
    [
        ("print(str('hi'))", "test.py", "test"),
        ("print(str('hi' + 'bye'))", "test.py", "test"),
        ("print('hi' + 'bye')", "test.py", "test"),
    ],
)
def test_visit_ast_changed(source_text, module_path, module_name):
    """
    Source texts containing:
    - str() calls
    - [...]  // To be filled with more aspects
    will be modified by ast patching, so will not return empty string
    """
    assert visit_ast(source_text, module_path, module_name) is not None


@pytest.mark.parametrize(
    "module_name",
    [
        ("tests.appsec.iast.fixtures.ast.str.class_str"),
        ("tests.appsec.iast.fixtures.ast.str.function_str"),
        ("tests.appsec.iast.fixtures.ast.str.non_utf8_content"),  # EUC-JP file content
    ],
)
def test_astpatch_module_changed(module_name):
    module_path, new_ast = astpatch_module(__import__(module_name, fromlist=["*"]))
    assert ("", None) != (module_path, new_ast)
    new_code = unparse(new_ast)
    assert new_code.startswith(
        f"import ddtrace.appsec._iast.sources as {_PREFIX}sources"
        f"\nimport ddtrace.appsec._iast.taint_sinks as {_PREFIX}taint_sinks"
        f"\nimport ddtrace.appsec._iast._taint_tracking.aspects as {_PREFIX}aspects"
    )
    assert "ddtrace_aspects.str_aspect(" in new_code


@pytest.mark.parametrize(
    "module_name",
    [
        ("tests.appsec.iast.fixtures.ast.add_operator.basic"),
    ],
)
def test_astpatch_module_changed_add_operator(module_name):
    module_path, new_ast = astpatch_module(__import__(module_name, fromlist=["*"]))
    assert ("", None) != (module_path, new_ast)
    new_code = unparse(new_ast)
    assert new_code.startswith(
        f"import ddtrace.appsec._iast.sources as {_PREFIX}sources"
        f"\nimport ddtrace.appsec._iast.taint_sinks as {_PREFIX}taint_sinks"
        f"\nimport ddtrace.appsec._iast._taint_tracking.aspects as {_PREFIX}aspects"
    )
    assert "ddtrace_aspects.add_aspect(" in new_code


@pytest.mark.parametrize(
    "module_name",
    [
        ("tests.appsec.iast.fixtures.ast.add_operator.inplace"),
    ],
)
def test_astpatch_module_changed_add_inplace_operator(module_name):
    module_path, new_ast = astpatch_module(__import__(module_name, fromlist=["*"]))
    assert ("", None) != (module_path, new_ast)
    new_code = unparse(new_ast)
    assert new_code.startswith(
        f"import ddtrace.appsec._iast.sources as {_PREFIX}sources"
        f"\nimport ddtrace.appsec._iast.taint_sinks as {_PREFIX}taint_sinks"
        f"\nimport ddtrace.appsec._iast._taint_tracking.aspects as {_PREFIX}aspects"
    )
    assert "ddtrace_aspects.add_inplace_aspect(" in new_code


@pytest.mark.parametrize(
    "module_name",
    [
        ("tests.appsec.iast.fixtures.ast.str.future_import_class_str"),
        ("tests.appsec.iast.fixtures.ast.str.future_import_function_str"),
    ],
)
def test_astpatch_source_changed_with_future_imports(module_name):
    module_path, new_ast = astpatch_module(__import__(module_name, fromlist=["*"]))
    assert ("", None) != (module_path, new_ast)
    new_code = unparse(new_ast)
    assert new_code.startswith(
        f"""\"\"\"\nSome\nmulti-line\ndocstring\nhere\n\"\"\"
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import ddtrace.appsec._iast.sources as {_PREFIX}sources
import ddtrace.appsec._iast.taint_sinks as {_PREFIX}taint_sinks
import ddtrace.appsec._iast._taint_tracking.aspects as {_PREFIX}aspects
import html"""
    )
    assert "ddtrace_aspects.str_aspect(" in new_code


@pytest.mark.parametrize(
    "module_name",
    [
        ("tests.appsec.iast.fixtures.ast.str.class_no_str"),
        ("tests.appsec.iast.fixtures.ast.str.function_no_str"),
        ("tests.appsec.iast.fixtures.ast.str.__init__"),  # Empty __init__.py
        ("tests.appsec.iast.fixtures.ast.str.empty_file"),
        ("tests.appsec.iast.fixtures.ast.subscript.store_context"),
    ],
)
def test_astpatch_source_unchanged(module_name):
    assert ("", None) == astpatch_module(__import__(module_name, fromlist=["*"]))


def test_should_iast_patch_allow_first_party():
    assert iastpatch.should_iast_patch("file_in_my_project.main") == iastpatch.ALLOWED_FIRST_PARTY_ALLOWLIST
    assert iastpatch.should_iast_patch("file_in_my_project.print_str") == iastpatch.ALLOWED_FIRST_PARTY_ALLOWLIST
    assert iastpatch.should_iast_patch("html") == iastpatch.ALLOWED_FIRST_PARTY_ALLOWLIST


def test_should_iast_patch_allow_user_allowlist():
    assert iastpatch.should_iast_patch("tests.appsec.iast.integration.main") == iastpatch.ALLOWED_USER_ALLOWLIST
    assert iastpatch.should_iast_patch("tests.appsec.iast.integration.print_str") == iastpatch.ALLOWED_USER_ALLOWLIST


def test_should_not_iast_patch_if_vendored():
    assert iastpatch.should_iast_patch("foobar.vendor.requests") == iastpatch.DENIED_NOT_FOUND
    assert iastpatch.should_iast_patch("vendored.foobar.requests") == iastpatch.DENIED_NOT_FOUND


def test_should_iast_patch_deny_by_default_if_third_party():
    # note that modules here must be in the ones returned by get_package_distributions()
    # but not in ALLOWLIST or DENYLIST. So please don't put astunparse there :)
    assert (
        iastpatch.should_iast_patch("astunparse.foo.bar.not.in.deny.or.allow.list")
        == iastpatch.DENIED_BUILTINS_DENYLIST
    )


def test_should_iast_patch_allow_by_default_if_third_party():
    # note that modules here must be in the ones returned by get_package_distributions()
    # but not in ALLOWLIST or DENYLIST. So please don't put astunparse there :)
    assert iastpatch.should_iast_patch("pygments") == iastpatch.ALLOWED_STATIC_ALLOWLIST
    assert iastpatch.should_iast_patch("pygments.submodule") == iastpatch.ALLOWED_STATIC_ALLOWLIST
    assert iastpatch.should_iast_patch("pygments.submodule.submodule2") == iastpatch.ALLOWED_STATIC_ALLOWLIST


def test_should_not_iast_patch_if_not_in_static_allowlist():
    assert iastpatch.should_iast_patch("ddtrace.internal.module") == iastpatch.DENIED_NOT_FOUND
    assert iastpatch.should_iast_patch("ddtrace.appsec._iast") == iastpatch.DENIED_NOT_FOUND
    assert iastpatch.should_iast_patch("pip.foo.bar") == iastpatch.DENIED_NOT_FOUND


@pytest.mark.parametrize(
    "module_name",
    sorted(
        {
            "__future__",
            "_ast",
            "_compression",
            "_thread",
            "abc",
            "aifc",
            "argparse",
            "array",
            "ast",
            "asynchat",
            "asyncio",
            "asyncore",
            "atexit",
            "audioop",
            "base64",
            "bdb",
            "binascii",
            "bisect",
            "builtins",
            "bz2",
            "cProfile",
            "calendar",
            "cgi",
            "cgitb",
            "chunk",
            "cmath",
            "cmd",
            "code",
            "codecs",
            "codeop",
            "collections",
            "colorsys",
            "compileall",
            "concurrent",
            "configparser",
            "contextlib",
            "contextvars",
            "copy",
            "copyreg",
            "crypt",
            "csv",
            "ctypes",
            "curses",
            "dataclasses",
            "datetime",
            "dbm",
            "decimal",
            "difflib",
            "dis",
            "distutils",
            "doctest",
            "email",
            "encodings",
            "ensurepip",
            "enum",
            "errno",
            "faulthandler",
            "fcntl",
            "filecmp",
            "fileinput",
            "fnmatch",
            "fractions",
            "ftplib",
            "functools",
            "gc",
            "getopt",
            "getpass",
            "gettext",
            "glob",
            "graphlib",
            "grp",
            "gzip",
            "hashlib",
            "heapq",
            "hmac",
            "http",
            "idlelib",
            "imaplib",
            "imghdr",
            "imp",
            "importlib",
            "inspect",
            "io",
            "_io",
            "ipaddress",
            "itertools",
            "json",
            "keyword",
            "lib2to3",
            "linecache",
            "locale",
            "logging",
            "lzma",
            "mailbox",
            "mailcap",
            "marshal",
            "math",
            "mimetypes",
            "mmap",
            "modulefinder",
            "msilib",
            "msvcrt",
            "multiprocessing",
            "netrc",
            "nis",
            "nntplib",
            "ntpath",
            "numbers",
            "opcode",
            "operator",
            "optparse",
            "os",
            "os.path",
            "ossaudiodev",
            "pathlib",
            "pdb",
            "pickle",
            "pickletools",
            "pipes",
            "pkgutil",
            "platform",
            "plistlib",
            "poplib",
            "posix",
            "posixpath",
            "pprint",
            "profile",
            "pstats",
            "pty",
            "pwd",
            "py_compile",
            "pyclbr",
            "pydoc",
            "queue",
            "quopri",
            "random",
            "re",
            "readline",
            "reprlib",
            "resource",
            "rlcompleter",
            "runpy",
            "sched",
            "secrets",
            "select",
            "selectors",
            "shelve",
            "shutil",
            "signal",
            "site",
            "smtpd",
            "smtplib",
            "sndhdr",
            "socket",
            "socketserver",
            "spwd",
            "sqlite3",
            "sre",
            "sre_compile",
            "sre_constants",
            "sre_parse",
            "ssl",
            "stat",
            "statistics",
            "string",
            "stringprep",
            "struct",
            "subprocess",
            "sunau",
            "symtable",
            "sys",
            "sysconfig",
            "syslog",
            "tabnanny",
            "tarfile",
            "telnetlib",
            "tempfile",
            "termios",
            "test",
            "textwrap",
            "threading",
            "time",
            "timeit",
            "tkinter",
            "token",
            "tokenize",
            "tomllib",
            "trace",
            "traceback",
            "tracemalloc",
            "tty",
            "turtle",
            "turtledemo",
            "types",
            "typing",
            "unicodedata",
            "unittest",
            "uu",
            "uuid",
            "venv",
            "warnings",
            "wave",
            "weakref",
            "webbrowser",
            "winreg",
            "winsound",
            "wsgiref",
            "xdrlib",
            "xml",
            "xmlrpc",
            "zipapp",
            "zipfile",
            "zipimport",
            "zlib",
            "zoneinfo",
        }
    ),
)
def test_should_not_iast_patch_if_stdlib(module_name):
    assert iastpatch.should_iast_patch(module_name) == iastpatch.DENIED_BUILTINS_DENYLIST


def test_module_path_none(caplog):
    with caplog.at_level(logging.DEBUG), mock.patch("ddtrace.appsec._iast._ast.ast_patching.origin", return_value=None):
        assert ("", None) == astpatch_module(__import__("tests.appsec.iast.fixtures.ast.str.class_str", fromlist=["*"]))
        assert (
            "iast::instrumentation::ast_patching::compiling::"
            "could not find the module: tests.appsec.iast.fixtures.ast.str.class_str" in caplog.text
        )


@pytest.mark.parametrize(
    "module_name",
    [
        ("tests.appsec.iast.fixtures.ast.io.module_stringio"),
        ("tests.appsec.iast.fixtures.ast.io.function_stringio"),
    ],
)
def test_astpatch_stringio_module_changed(module_name):
    module_path, new_ast = astpatch_module(__import__(module_name, fromlist=["*"]))
    assert ("", None) != (module_path, new_ast)
    new_code = unparse(new_ast)
    assert new_code.startswith(
        f"import ddtrace.appsec._iast.sources as {_PREFIX}sources"
        f"\nimport ddtrace.appsec._iast.taint_sinks as {_PREFIX}taint_sinks"
        f"\nimport ddtrace.appsec._iast._taint_tracking.aspects as {_PREFIX}aspects"
    )
    assert "ddtrace_aspects.stringio_aspect(" in new_code


@pytest.mark.parametrize(
    "module_name",
    [
        ("tests.appsec.iast.fixtures.ast.io.module_bytesio"),
        ("tests.appsec.iast.fixtures.ast.io.function_bytesio"),
    ],
)
def test_astpatch_bytesio_module_changed(module_name):
    module_path, new_ast = astpatch_module(__import__(module_name, fromlist=["*"]))
    assert ("", None) != (module_path, new_ast)
    new_code = unparse(new_ast)
    assert new_code.startswith(
        f"import ddtrace.appsec._iast.sources as {_PREFIX}sources"
        f"\nimport ddtrace.appsec._iast.taint_sinks as {_PREFIX}taint_sinks"
        f"\nimport ddtrace.appsec._iast._taint_tracking.aspects as {_PREFIX}aspects"
    )
    assert "ddtrace_aspects.bytesio_aspect(" in new_code


@pytest.mark.parametrize(
    "module_name",
    [
        ("tests.appsec.iast.fixtures.ast.other.globals_builtin"),
    ],
)
def test_astpatch_globals_module_unchanged(module_name):
    """
    This is a regression test for partially matching function names:
    ``globals()`` was being incorrectly patched with the aspect for ``glob()``
    """
    module_path, new_ast = astpatch_module(__import__(module_name, fromlist=["*"]))
    assert ("", None) == (module_path, new_ast)


@pytest.mark.parametrize(
    "module_name, env_var",
    [
        ("tests.appsec.iast.fixtures.ast.other.with_implemented_dir", "false"),
        ("tests.appsec.iast.fixtures.ast.other.with_implemented_dir", "true"),
        ("tests.appsec.iast.fixtures.ast.other.without_implemented_dir", "false"),
        ("tests.appsec.iast.fixtures.ast.other.without_implemented_dir", "true"),
    ],
)
def test_astpatch_dir_patched_with_env_var(module_name, env_var):
    """
    Check that the ast_patching._DIR_WRAPPER code is added to the end of the module if
    the env var is False and not added otherwise
    """
    with override_env({IAST.ENV_NO_DIR_PATCH: env_var}):
        module_path, new_ast = astpatch_module(__import__(module_name, fromlist=["*"]))
        assert ("", None) != (module_path, new_ast)
        new_code = unparse(new_ast)

        if asbool(env_var):
            # If ENV_NO_DIR_PATCH is set to True our added symbols are not filtered out
            assert f"{_PREFIX}aspects" in new_code
            assert f"{_PREFIX}taint_sinks" in new_code
        else:
            # Check that the added dir code is there
            assert f"def {_PREFIX}dir" in new_code
            assert f"def {_PREFIX}set_dir_filter()" in new_code


@pytest.mark.parametrize(
    "module_name, expected_names",
    [
        (
            "tests.appsec.iast.fixtures.ast.other.with_implemented_dir",
            {"custom_added", "symbol1", "symbol2", "symbol3", "symbol4"},
        ),
        (
            "tests.appsec.iast.fixtures.ast.other.without_implemented_dir",
            {"symbol1", "symbol2", "symbol3", "symbol4"},
        ),
    ],
)
def test_astpatch_dir_patched_with_or_without_custom_dir(module_name, expected_names):
    """
    Check that the patched dir doesn't have any __ddtrace symbols and match the original
    unpatched dir() output, both with or without a previous custom __dir__ implementation
    """
    with override_env({IAST.ENV_NO_DIR_PATCH: "false"}):
        imported_mod = __import__(module_name, fromlist=["*"])
        orig_dir = set(dir(imported_mod))

        for name in expected_names:
            assert name in orig_dir

        module_path, new_ast = astpatch_module(imported_mod)
        assert ("", None) != (module_path, new_ast)

        new_code = unparse(new_ast)
        assert f"def {_PREFIX}dir" in new_code
        assert f"def {_PREFIX}set_dir_filter()" in new_code

        compiled_code = compile(new_ast, module_path, "exec")
        exec(compiled_code, imported_mod.__dict__)
        patched_dir = set(dir(imported_mod))
        for symbol in patched_dir:
            assert not symbol.startswith(_PREFIX)

        # Check that there are no new symbols that were not in the original dir() call
        assert len(patched_dir.difference(orig_dir)) == 0

        # Check that all the symbols in the expected set are in the patched dir() result
        for name in expected_names:
            assert name in patched_dir


@pytest.mark.skipif(sys.version_info < (3, 15), reason="Requires Python 3.15 lazy imports")
@pytest.mark.parametrize("import_mode", ["lazy_import", "lazy_from", "lazy_modules", "global"])
def test_lazy_import_first_call_is_instrumented(tmp_path, import_mode):
    target = """
        import builtins
        builtins._iast_lazy_events.append(__name__)

        def make_query(value):
            return "SELECT '" + value + "'"
    """
    (tmp_path / "iast_lazy_target.py").write_text(textwrap.dedent(target))
    (tmp_path / "iast_lazy_unused.py").write_text("raise AssertionError('Unused lazy import was evaluated')\n")
    declarations = {
        "lazy_import": "lazy import iast_lazy_target\nlazy import iast_lazy_unused",
        "lazy_from": "lazy from iast_lazy_target import make_query\nlazy import iast_lazy_unused",
        "lazy_modules": (
            "__lazy_modules__ = ['iast_lazy_target', 'iast_lazy_unused']\n"
            "import iast_lazy_target\nimport iast_lazy_unused"
        ),
        "global": "import iast_lazy_target\nimport iast_lazy_unused",
    }
    call = "make_query(value)" if import_mode == "lazy_from" else "iast_lazy_target.make_query(value)"
    # The addition requires AST rewriting in the importing module as well as the target.
    importer = (
        f"{declarations[import_mode]}\n"
        "import builtins\n"
        "builtins._iast_lazy_events.append(__name__)\n"
        f"def run(value):\n    return {call} + ' '\n"
    )
    (tmp_path / "iast_lazy_importer.py").write_text(importer)
    driver = """
        import builtins
        import importlib
        import sqlite3
        import sys

        from ddtrace import tracer
        from ddtrace.appsec._iast._iast_request_context import get_iast_reporter
        from ddtrace.appsec._iast._iast_request_context_base import _iast_finish_request
        from ddtrace.appsec._iast._iast_request_context_base import _iast_start_request
        from ddtrace.appsec._iast._overhead_control_engine import oce
        from ddtrace.appsec._iast._taint_tracking import OriginType
        from ddtrace.appsec._iast._taint_tracking._taint_objects import taint_pyobject
        from ddtrace.appsec._iast._taint_tracking._taint_objects_base import get_tainted_ranges
        from ddtrace.appsec._iast.constants import VULN_SQL_INJECTION

        builtins._iast_lazy_events = []
        with tracer.trace("web.request", span_type="web") as span:
            oce.reconfigure()
            _iast_start_request(span)
            try:
                importer = importlib.import_module("iast_lazy_importer")
                assert builtins._iast_lazy_events == ["iast_lazy_importer"]
                assert "iast_lazy_target" not in sys.modules
                assert "iast_lazy_unused" not in sys.modules

                value = taint_pyobject("lazy_input", "parameter", "lazy_input", OriginType.PARAMETER)
                query = importer.run(value)
                assert query == "SELECT 'lazy_input' "
                ranges = get_tainted_ranges(query)
                assert len(ranges) == 1
                assert (ranges[0].start, ranges[0].length) == (len("SELECT '"), len(value))
                assert ranges[0].source == get_tainted_ranges(value)[0].source

                with sqlite3.connect(":memory:") as connection:
                    assert connection.execute(query).fetchone() == ("lazy_input",)
                report = get_iast_reporter()
                assert report is not None
                assert any(v.type == VULN_SQL_INJECTION for v in report.vulnerabilities)

                assert importer.run(value) == query
                assert builtins._iast_lazy_events == ["iast_lazy_importer", "iast_lazy_target"]
                assert "iast_lazy_unused" not in sys.modules
            finally:
                _iast_finish_request(span)
    """
    driver_path = tmp_path / "driver.py"
    driver_path.write_text(textwrap.dedent(driver))
    env = os.environ.copy()
    env.update(
        DD_IAST_ENABLED="true",
        DD_IAST_REQUEST_SAMPLING="100",
        DD_IAST_DEDUPLICATION_ENABLED="false",
        _DD_IAST_PATCH_MODULES="iast_lazy_",
        PYTHONPATH=os.pathsep.join((str(DDTRACE_PATH), str(tmp_path))),
        PYTHON_LAZY_IMPORTS="all" if import_mode == "global" else "normal",
    )
    stdout, stderr, status, _ = call_program(
        sys.executable,
        "-m",
        "ddtrace.commands.ddtrace_run",
        sys.executable,
        str(driver_path),
        env=env,
        cwd=tmp_path,
        timeout=60,
    )
    assert status == 0, f"STDOUT:\n{stdout.decode()}\nSTDERR:\n{stderr.decode()}"
