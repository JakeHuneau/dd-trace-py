import builtins
import os
import sys
import textwrap

import pytest

from ddtrace.appsec._iast._taint_tracking import OriginType
from ddtrace.appsec._iast._taint_tracking._context import is_in_taint_map
from ddtrace.appsec._iast._taint_tracking._taint_objects import taint_pyobject
from ddtrace.appsec._iast._taint_tracking._taint_objects_base import get_tainted_ranges
from ddtrace.appsec._iast._taint_tracking._taint_objects_base import is_pyobject_tainted
from ddtrace.appsec._iast._taint_tracking.aspects import modulo_aspect
from ddtrace.appsec._iast._taint_utils import taint_structure
from tests.utils import DDTRACE_PATH
from tests.utils import call_program


pytestmark = pytest.mark.skipif(sys.version_info < (3, 15), reason="Requires Python 3.15 language features")


@pytest.mark.parametrize("nested", [False, True])
def test_frozendict_source_tainting_preserves_type_and_immutability(iast_context_defaults, nested):
    frozendict = getattr(builtins, "frozendict")
    key = "".join(("request", "_parameter"))
    value = "".join(("frozen", "_input"))
    inner = frozendict({key: value})
    original = frozendict({"nested": inner}) if nested else inner

    result = taint_structure(original, OriginType.PARAMETER_NAME, OriginType.PARAMETER)

    assert type(result) is frozendict
    assert result == original
    with pytest.raises(TypeError):
        result[key] = "changed"
    result_inner = result["nested"] if nested else result
    assert type(result_inner) is frozendict
    result_key = next(iter(result_inner))
    assert is_pyobject_tainted(result_key)
    assert get_tainted_ranges(result_key)[0].source.origin == OriginType.PARAMETER_NAME
    ranges = get_tainted_ranges(result_inner[key])
    assert len(ranges) == 1
    assert (ranges[0].start, ranges[0].length) == (0, len(value))
    assert ranges[0].source.origin == OriginType.PARAMETER
    assert not is_pyobject_tainted(key)
    assert not is_pyobject_tainted(value)


@pytest.mark.parametrize("mapping_type", ["dict", "frozendict"])
def test_python315_mapping_taint_context_lookup(iast_context_defaults, mapping_type):
    value = taint_pyobject("frozen_input", "parameter", "frozen_input", OriginType.PARAMETER)
    mapping = getattr(builtins, mapping_type)({"value": value})

    assert is_pyobject_tainted(value)
    assert is_in_taint_map(mapping)


@pytest.mark.parametrize("mapping_type", ["dict", "frozendict"])
def test_python315_mapping_formatting_preserves_taint(iast_context_defaults, mapping_type):
    value = taint_pyobject("frozen_input", "parameter", "frozen_input", OriginType.PARAMETER)
    mapping = getattr(builtins, mapping_type)({"value": value})

    result = modulo_aspect("prefix:%(value)s:suffix", mapping)

    assert result == "prefix:frozen_input:suffix"
    ranges = get_tainted_ranges(result)
    assert len(ranges) == 1
    assert (ranges[0].start, ranges[0].length) == (len("prefix:"), len(value))
    assert ranges[0].source == get_tainted_ranges(value)[0].source


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
