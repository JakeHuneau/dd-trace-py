import os
from pathlib import Path

import pytest

from tests.utils import TracerTestCase
from tests.utils import override_env


class ConftestTestCase(TracerTestCase):
    """
    Test case to verify conftest code works as expected
    """

    @pytest.fixture(autouse=True)
    def fixtures(self, testdir):
        """
        Fixtures to use in tests
        """
        self.testdir = testdir

    def makeconftest(self, conftest_rel_path="../conftest.py"):
        """
        Copy tests/conftest.py contents to the testdir conftest
        """
        this_dir = os.path.dirname(__file__)
        abs_file_path = os.path.join(this_dir, conftest_rel_path)
        with open(abs_file_path, encoding="utf-8") as conftest:
            self.testdir.makeconftest(conftest.read())

    def inline_run(self, *args):
        """
        Override inline_run to use our conftest
        """
        with override_env({"DD_API_KEY": "foobar.baz"}):
            self.makeconftest()
            return self.testdir.inline_run(*args)

    def test_subprocess_fail(self):
        """
        Test a failing test with subprocess decorator
        """
        py_file = self.testdir.makepyfile(
            """
            import pytest

            @pytest.mark.subprocess()
            def test_fail():
                assert False
            """
        )
        file_name = os.path.basename(py_file.strpath)
        rec = self.inline_run(file_name)
        rec.assertoutcome(passed=0, failed=1, skipped=0)

    def test_subprocess_pass(self):
        """
        Test a passing test with subprocess decorator
        """
        py_file = self.testdir.makepyfile(
            """
            import pytest

            @pytest.mark.subprocess()
            def test_pass():
                assert True
            """
        )
        file_name = os.path.basename(py_file.strpath)
        rec = self.inline_run(file_name)
        rec.assertoutcome(passed=1, failed=0, skipped=0)

    def test_subprocess_skip(self):
        """
        Test a skipping test with subprocess decorator
        """
        py_file = self.testdir.makepyfile(
            """
            import pytest

            @pytest.mark.skip
            @pytest.mark.subprocess()
            def test_pass():
                assert True
            """
        )
        file_name = os.path.basename(py_file.strpath)
        rec = self.inline_run(file_name)
        rec.assertoutcome(passed=0, failed=0, skipped=1)

    def test_process_fixture_is_unskippable(self):
        py_file = self.testdir.makepyfile(
            """
            def test_selection(request, python_process):
                reasons = [m.kwargs.get("reason") for m in request.node.iter_markers("skipif")]
                assert "datadog_itr_unskippable" in reasons
            """
        )
        self.inline_run(os.path.basename(py_file.strpath)).assertoutcome(passed=1)

    def test_child_skip_is_reported(self):
        py_file = self.testdir.makepyfile(
            """
            import pytest
            @pytest.mark.subprocess()
            def test_skip():
                import unittest
                raise unittest.SkipTest("child platform")
            """
        )
        self.inline_run(os.path.basename(py_file.strpath)).assertoutcome(skipped=1)


@pytest.mark.parametrize("optimization", ["0", "1", "2"])
def test_subprocess_assertions_with_optimization(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch, optimization: str
) -> None:
    root = Path(__file__).resolve().parents[2]
    pytester.makeconftest((root / "tests/conftest.py").read_text())
    pytester.makepyfile(application="def optimized():\n    return not __debug__\n")
    pytester.makepyfile(
        test_assertions="""
        import pytest

        @pytest.mark.subprocess(timeout=10)
        def test_failing_assertion():
            assert False, "subprocess assertion must execute"

        @pytest.mark.subprocess(timeout=10)
        def test_application_optimization():
            import os
            import sys
            import application

            expected = int(os.environ["PYTHONOPTIMIZE"])
            assert sys.flags.optimize == expected
            assert application.optimized() is bool(expected)
        """
    )
    monkeypatch.setenv("PYTHONOPTIMIZE", optimization)
    monkeypatch.setenv("DD_API_KEY", "foobar.baz")
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([str(pytester.path), str(root), os.getenv("PYTHONPATH", "")]))
    result = pytester.runpytest_subprocess("--no-cov", "-o", "addopts=", "test_assertions.py", timeout=30)
    result.assert_outcomes(passed=1, failed=1)
    result.stdout.fnmatch_lines(["*subprocess assertion must execute*"])


def test_class_subprocess(pytester, monkeypatch):
    root = Path(__file__).resolve().parents[2]
    pytester.makeconftest(
        (root / "tests/conftest.py").read_text() + "\n@pytest.fixture(autouse=True)\ndef unrelated_fixture():\n"
        "    raise AssertionError('isolated method loaded a parent fixture')\n"
    )
    pytester.makepyfile(
        test_cases="""
        import asyncio
        import os
        from pathlib import Path
        import unittest
        import pytest

        MODE = os.getenv("CHILD_MODE", "parent")

        class TestCase(unittest.TestCase):
            def setUp(self):
                assert MODE == "child"
                assert os.getpid() != int(os.environ["PARENT_PID"])
                self.value = 42
                self.addCleanup(self.record, "cleanup")

            def record(self, event):
                with Path(os.environ["EVENTS"]).open("a") as stream:
                    stream.write(self._testMethodName + ":" + event + "\\n")

            def tearDown(self):
                self.record("teardown")

            @pytest.mark.subprocess(env={"CHILD_MODE": "child"}, parametrize={"CASE": ["one", "two"]})
            async def test_async(self):
                await asyncio.sleep(0)
                assert self.value == 42
                assert os.environ["CASE"] in ("one", "two")
                self.record("awaited")

            @pytest.mark.subprocess(env={"CHILD_MODE": "child", "PYTHONOPTIMIZE": "1"})
            def test_failure(self):
                assert False, "class assertion must execute"
        """
    )
    monkeypatch.setenv("PARENT_PID", str(os.getpid()))
    monkeypatch.setenv("EVENTS", str(pytester.path / "events"))
    monkeypatch.setenv("DD_API_KEY", "foobar.baz")
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([str(pytester.path), str(root), os.getenv("PYTHONPATH", "")]))
    result = pytester.runpytest_subprocess("--no-cov", "-o", "addopts=", "-v", "test_cases.py", timeout=30)
    result.assert_outcomes(passed=2, failed=1)
    result.stdout.fnmatch_lines(["*class assertion must execute*"])
    result.stdout.re_match_lines(
        [r".*TestCase::test_async\[one\].*PASSED.*", r".*TestCase::test_async\[two\].*PASSED.*"]
    )
    events = (pytester.path / "events").read_text().splitlines()
    assert events.count("test_async:awaited") == 2
    assert events.count("test_async:teardown") == 2
    assert events.count("test_async:cleanup") == 2
    assert events[-2:] == ["test_failure:teardown", "test_failure:cleanup"]
