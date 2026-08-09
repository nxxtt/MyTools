import argparse
import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import mytools.core.batch as batch_mod
from mytools.core.batch import (
    TargetResult,
    _build_base_ns,
    _detect_target_type,
    _find_project_root,
    _get_all_module_names,
    _get_parser_defaults,
    _get_registry,
    _is_compatible,
    _make_args,
    _print_report,
    _resolve_module,
    _sanitize_target,
    _suppress_stdout,
    main,
    process_target,
    read_targets,
    run_batch,
    run_once,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# read_targets
# ---------------------------------------------------------------------------


class TestReadTargets:
    def test_basic(self, tmp_path: Path) -> None:
        f = tmp_path / "targets.txt"
        f.write_text("example.com\nhttps://test.com\n192.168.1.1\n")
        assert read_targets(str(f)) == [
            "example.com",
            "https://test.com",
            "192.168.1.1",
        ]

    def test_skips_comments(self, tmp_path: Path) -> None:
        f = tmp_path / "targets.txt"
        f.write_text("# comment\nexample.com\n\n  \n# another\nhttps://test.com\n")
        assert read_targets(str(f)) == ["example.com", "https://test.com"]

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError, match="arquivo nao encontrado"):
            read_targets("/nonexistent/path.txt")

    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "targets.txt"
        f.write_text("# only comments\n\n")
        with pytest.raises(ValueError, match="nenhum target valido"):
            read_targets(str(f))


# ---------------------------------------------------------------------------
# _discover_modules
# ---------------------------------------------------------------------------


class TestDiscoverModules:
    def test_returns_dict(self) -> None:
        registry = _get_registry()
        assert isinstance(registry, dict)
        assert len(registry) > 0

    def test_all_modules_present(self) -> None:
        names = _get_all_module_names()
        assert "recon" in names
        assert "port" in names
        assert len(names) > 50

    def test_empty_pyproject_returns_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
        monkeypatch.setattr(batch_mod, "_find_project_root", lambda: tmp_path)
        assert batch_mod._discover_modules() == {}


# ---------------------------------------------------------------------------
# _resolve_module
# ---------------------------------------------------------------------------


class TestResolveModule:
    def test_valid(self) -> None:
        mod = _resolve_module("recon")
        assert hasattr(mod, "run_once")
        assert hasattr(mod, "build_parser")

    def test_invalid(self) -> None:
        with pytest.raises(ValueError, match="nao encontrado"):
            _resolve_module("nonexistent_module_xyz")


# ---------------------------------------------------------------------------
# _sanitize_target
# ---------------------------------------------------------------------------


class TestSanitizeTarget:
    def test_basic(self) -> None:
        assert _sanitize_target("example.com") == "example.com"

    def test_with_slashes(self) -> None:
        assert (
            _sanitize_target("https://example.com/path") == "https___example.com_path"
        )

    def test_long(self) -> None:
        long_target = "a" * 200
        assert len(_sanitize_target(long_target)) == 100


# ---------------------------------------------------------------------------
# _detect_target_type
# ---------------------------------------------------------------------------


class TestTargetTypeDetection:
    def test_http(self) -> None:
        assert _detect_target_type("http://example.com") == "url"

    def test_https(self) -> None:
        assert _detect_target_type("https://example.com") == "url"

    def test_domain(self) -> None:
        assert _detect_target_type("example.com") == "domain"

    def test_ip(self) -> None:
        assert _detect_target_type("192.168.1.1") == "domain"


# ---------------------------------------------------------------------------
# _is_compatible
# ---------------------------------------------------------------------------


class TestIsCompatible:
    def test_url_module_with_url(self) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("url")
        assert _is_compatible("https://example.com", parser) is True

    def test_domain_module_with_domain(self) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("domain")
        assert _is_compatible("example.com", parser) is True

    def test_url_module_with_domain(self) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("url")
        assert _is_compatible("example.com", parser) is False

    def test_module_with_target(self) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("target")
        assert _is_compatible("example.com", parser) is True
        assert _is_compatible("https://example.com", parser) is True


# ---------------------------------------------------------------------------
# _make_args
# ---------------------------------------------------------------------------


class TestMakeArgs:
    def test_combines(self) -> None:
        base = argparse.Namespace(timeout=5.0, verbose=False)
        extra = {"url": "https://example.com", "timeout": 10.0}
        result = _make_args(extra, base)
        assert result.url == "https://example.com"
        assert result.timeout == 10.0
        assert result.verbose is False


# ---------------------------------------------------------------------------
# dry_run
# ---------------------------------------------------------------------------


class TestDryRun:
    def test_dry_run(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        f = tmp_path / "targets.txt"
        f.write_text("example.com\nhttps://test.com\n")
        monkeypatch.setattr(
            "sys.argv",
            ["mytools-batch", str(f), "recon", "--dry-run"],
        )
        assert main() == 0


# ---------------------------------------------------------------------------
# process_target
# ---------------------------------------------------------------------------


class TestProcessTarget:
    def test_runs_modules(self) -> None:
        mock_run = MagicMock(return_value=0)
        mock_parser = argparse.ArgumentParser()
        mock_parser.add_argument("target")
        mock_parser.add_argument("--timeout", type=float, default=5.0)
        mock_build = MagicMock(return_value=mock_parser)

        base_ns = argparse.Namespace(timeout=5.0, verbose=False)
        module_list = [("webrecon", mock_run, mock_build)]

        result = process_target("example.com", module_list, base_ns, None, 5.0)
        assert result.target == "example.com"
        assert result.success == 1
        assert result.errors == 0
        mock_run.assert_called_once()

    def test_handles_exception(self) -> None:
        mock_run = MagicMock(side_effect=RuntimeError("boom"))
        mock_parser = argparse.ArgumentParser()
        mock_parser.add_argument("target")
        mock_parser.add_argument("--timeout", type=float, default=5.0)
        mock_build = MagicMock(return_value=mock_parser)

        base_ns = argparse.Namespace(timeout=5.0, verbose=False)
        module_list = [("webrecon", mock_run, mock_build)]

        result = process_target("example.com", module_list, base_ns, None, 5.0)
        assert result.errors == 1
        assert result.details["webrecon"] == -1


# ---------------------------------------------------------------------------
# _print_report
# ---------------------------------------------------------------------------


class TestPrintReport:
    def test_text_format(self) -> None:
        results = [
            TargetResult(
                target="example.com",
                sanitized="example.com",
                success=1,
                vulns=0,
                errors=0,
                details={"webrecon": 0},
                duration=1.2,
            ),
        ]
        code = _print_report(results, strict=False, fmt="text")
        assert code == 0

    def test_json_format(self, capsys: pytest.CaptureFixture[str]) -> None:
        results = [
            TargetResult(
                target="example.com",
                sanitized="example.com",
                success=1,
                vulns=1,
                errors=0,
                details={"attackaudit": 1},
                duration=2.5,
            ),
        ]
        code = _print_report(results, strict=False, fmt="json")
        assert code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["summary"]["vulnerabilities"] == 1

    def test_strict_with_vulns(self) -> None:
        results = [
            TargetResult(
                target="example.com",
                sanitized="example.com",
                success=0,
                vulns=1,
                errors=0,
                details={"attackaudit": 1},
                duration=1.0,
            ),
        ]
        code = _print_report(results, strict=True, fmt="text")
        assert code == 2

    def test_errors_returns_1(self) -> None:
        results = [
            TargetResult(
                target="example.com",
                sanitized="example.com",
                success=0,
                vulns=0,
                errors=1,
                details={"webrecon": -1},
                duration=0.5,
            ),
        ]
        code = _print_report(results, strict=False, fmt="text")
        assert code == 1


# ---------------------------------------------------------------------------
# _find_project_root
# ---------------------------------------------------------------------------


class TestFindProjectRoot:
    def test_raises_when_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class FakePath:
            def __init__(self, *args: object) -> None:
                pass

            def resolve(self) -> FakePath:
                return self

            @property
            def parent(self) -> FakePath:
                return FakePath()

            def __truediv__(self, other: object) -> FakePath:
                return FakePath()

            def exists(self) -> bool:
                return False

        monkeypatch.setattr(batch_mod, "Path", FakePath)
        with pytest.raises(FileNotFoundError, match=r"pyproject\.toml"):
            _find_project_root()


# ---------------------------------------------------------------------------
# _get_parser_defaults
# ---------------------------------------------------------------------------


class TestGetParserDefaults:
    def test_extracts_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("--timeout", type=float, default=7.5)
        parser.add_argument("--headless", action="store_true")

        class FakeMod:
            def build_parser(self) -> argparse.ArgumentParser:
                return parser

        monkeypatch.setattr(
            batch_mod,
            "_get_registry",
            lambda: {"webrecon": "mytools.web.webrecon"},
        )
        monkeypatch.setattr(
            batch_mod.importlib,
            "import_module",
            lambda name: FakeMod(),
        )
        defaults = _get_parser_defaults(["webrecon"])
        assert defaults["timeout"] == 7.5
        assert defaults["headless"] is False

    def test_ignores_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class BadMod:
            def build_parser(self) -> None:
                raise RuntimeError("boom")

        monkeypatch.setattr(
            batch_mod,
            "_get_registry",
            lambda: {"bad": "mytools.web.bad"},
        )
        monkeypatch.setattr(
            batch_mod.importlib,
            "import_module",
            lambda name: BadMod(),
        )
        assert _get_parser_defaults(["bad"]) == {}


# ---------------------------------------------------------------------------
# _build_base_ns
# ---------------------------------------------------------------------------


class TestBuildBaseNs:
    def test_combines_defaults(self) -> None:
        args = argparse.Namespace(
            output_dir="out",
            verbose=True,
            timeout=3.0,
            auth="u:p",
            bearer_token="tok",
            cookie="c",
            header=["X: 1"],
            dry_run=True,
        )
        ns = _build_base_ns(args, ["webrecon"])
        assert ns.output is None
        assert ns.output_dir == "out"
        assert ns.quiet is True
        assert ns.verbose is True
        assert ns.timeout == 3.0
        assert ns.user_agent.startswith("MyTools/")
        assert ns.verify is False
        assert ns.proxy is None
        assert ns.auth == "u:p"
        assert ns.dry_run is True


# ---------------------------------------------------------------------------
# _suppress_stdout
# ---------------------------------------------------------------------------


class TestSuppressStdout:
    def test_restores_stdout(self) -> None:
        old = sys.stdout
        with _suppress_stdout():
            assert sys.stdout is not old
            print("hidden")
        assert sys.stdout is old


# ---------------------------------------------------------------------------
# process_target — branches adicionais
# ---------------------------------------------------------------------------


class TestProcessTargetEdges:
    def _make_parser(self, dest: str = "target") -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser()
        parser.add_argument(dest)
        parser.add_argument("--timeout", type=float, default=5.0)
        return parser

    def test_incompatible_skips(self) -> None:
        mock_run = MagicMock(return_value=0)
        mock_parser = self._make_parser("url")
        mock_build = MagicMock(return_value=mock_parser)

        base_ns = argparse.Namespace(timeout=5.0, verbose=False)
        module_list = [("webrecon", mock_run, mock_build)]

        result = process_target("example.com", module_list, base_ns, None, 5.0)
        assert mock_run.call_count == 0
        assert result.success == 0

    def test_vuln_code_and_output_dir(self, tmp_path: Path) -> None:
        mock_run = MagicMock(return_value=2)
        mock_parser = self._make_parser("target")
        mock_build = MagicMock(return_value=mock_parser)

        base_ns = argparse.Namespace(timeout=5.0, verbose=False)
        module_list = [("webrecon", mock_run, mock_build)]
        outdir = tmp_path / "out"

        result = process_target(
            "https://example.com/p",
            module_list,
            base_ns,
            str(outdir),
            5.0,
        )
        assert result.vulns == 1
        assert result.success == 0
        target_dir = outdir / "https___example.com_p"
        assert target_dir.exists()
        assert mock_run.call_args.args[0].output == str(target_dir / "webrecon.json")


# ---------------------------------------------------------------------------
# run_batch
# ---------------------------------------------------------------------------


class TestRunBatch:
    def _make_module(
        self, code: int = 0, raise_exc: bool = False
    ) -> types.SimpleNamespace:
        mod = types.SimpleNamespace()
        if raise_exc:
            mod.run_once = MagicMock(side_effect=RuntimeError("boom"))
        else:
            mod.run_once = MagicMock(return_value=code)
        parser = argparse.ArgumentParser()
        parser.add_argument("target")
        mod.build_parser = MagicMock(return_value=parser)
        return mod

    def _make_args(
        self,
        tmp_path: Path,
        *,
        modules: list[str],
        skip: list[str] | None = None,
        parallel: int = 1,
        strict: bool = False,
        fail_fast: bool = False,
        fmt: str = "text",
    ) -> argparse.Namespace:
        f = tmp_path / "targets.txt"
        f.write_text("example.com\nhttps://test.com\n")
        return argparse.Namespace(
            targets=str(f),
            modules=modules,
            skip=skip or [],
            parallel=parallel,
            output_dir=None,
            timeout=5.0,
            strict=strict,
            fail_fast=fail_fast,
            format=fmt,
            dry_run=False,
        )

    def test_all_combined_errors(self, tmp_path: Path) -> None:
        args = self._make_args(tmp_path, modules=["all", "recon"])
        assert run_batch(args) == 1

    def test_all_with_skip(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            batch_mod,
            "_get_registry",
            lambda: {
                "webrecon": "mytools.web.webrecon",
                "recon": "mytools.recon.recon",
            },
        )
        monkeypatch.setattr(
            batch_mod,
            "_resolve_module",
            lambda name: self._make_module(0),
        )
        monkeypatch.setattr(batch_mod, "_get_parser_defaults", lambda names: {})
        args = self._make_args(tmp_path, modules=["all"], skip=["recon"])
        assert run_batch(args) == 0

    def test_fail_fast_breaks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            batch_mod,
            "_get_registry",
            lambda: {"webrecon": "mytools.web.webrecon"},
        )
        monkeypatch.setattr(
            batch_mod,
            "_resolve_module",
            lambda name: self._make_module(0, raise_exc=True),
        )
        monkeypatch.setattr(batch_mod, "_get_parser_defaults", lambda names: {})
        args = self._make_args(tmp_path, modules=["webrecon"], fail_fast=True)
        assert run_batch(args) == 1

    def test_parallel_execution(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            batch_mod,
            "_get_registry",
            lambda: {"webrecon": "mytools.web.webrecon"},
        )
        monkeypatch.setattr(
            batch_mod,
            "_resolve_module",
            lambda name: self._make_module(0),
        )
        monkeypatch.setattr(batch_mod, "_get_parser_defaults", lambda names: {})
        args = self._make_args(tmp_path, modules=["webrecon"], parallel=3)
        assert run_batch(args) == 0

    def test_parallel_exception_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            batch_mod,
            "_get_registry",
            lambda: {"webrecon": "mytools.web.webrecon"},
        )

        def _raise(*args: object, **kwargs: object) -> None:
            raise RuntimeError("worker crashed")

        monkeypatch.setattr(batch_mod, "process_target", _raise)
        args = self._make_args(tmp_path, modules=["webrecon"], parallel=3)
        assert run_batch(args) == 1

    def test_sequential_vuln_strict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            batch_mod,
            "_get_registry",
            lambda: {"webrecon": "mytools.web.webrecon"},
        )
        monkeypatch.setattr(
            batch_mod,
            "_resolve_module",
            lambda name: self._make_module(1),
        )
        monkeypatch.setattr(batch_mod, "_get_parser_defaults", lambda names: {})
        args = self._make_args(tmp_path, modules=["webrecon"], strict=True)
        assert run_batch(args) == 2

    def test_json_format(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            batch_mod,
            "_get_registry",
            lambda: {"webrecon": "mytools.web.webrecon"},
        )
        monkeypatch.setattr(
            batch_mod,
            "_resolve_module",
            lambda name: self._make_module(0),
        )
        monkeypatch.setattr(batch_mod, "_get_parser_defaults", lambda names: {})
        args = self._make_args(tmp_path, modules=["webrecon"], fmt="json")
        assert run_batch(args) == 0


# ---------------------------------------------------------------------------
# run_once
# ---------------------------------------------------------------------------


class TestRunOnce:
    def test_dry_run(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        f = tmp_path / "targets.txt"
        f.write_text("example.com\n")
        args = argparse.Namespace(
            targets=str(f),
            modules=["recon"],
            skip=[],
            parallel=2,
            verbose=False,
            dry_run=True,
        )
        assert run_once(args) == 0

    def test_dry_run_sequential(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        f = tmp_path / "targets.txt"
        f.write_text("example.com\n")
        args = argparse.Namespace(
            targets=str(f),
            modules=["recon"],
            skip=[],
            parallel=1,
            verbose=False,
            dry_run=True,
        )
        assert run_once(args) == 0

    def test_delegates_to_run_batch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        args = argparse.Namespace(
            targets=str(tmp_path / "targets.txt"),
            modules=["recon"],
            skip=[],
            parallel=1,
            verbose=False,
            dry_run=False,
        )
        with patch.object(batch_mod, "run_batch", return_value=0) as mock_run_batch:
            assert run_once(args) == 0
        mock_run_batch.assert_called_once()


# ---------------------------------------------------------------------------
# main — branches adicionais
# ---------------------------------------------------------------------------


class TestMainEdges:
    def test_no_args_shell(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "argv", ["mytools-batch"])
        with patch(
            "mytools.core.batch.run_interactive_shell",
            return_value=0,
        ) as mock_shell:
            assert main() == 0
        mock_shell.assert_called_once()

    def test_main_dry_run_parallel(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        f = tmp_path / "targets.txt"
        f.write_text("example.com\n")
        monkeypatch.setattr(
            sys,
            "argv",
            ["mytools-batch", str(f), "all", "--dry-run", "-p", "2"],
        )
        assert main() == 0

    def test_main_runs_batch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        f = tmp_path / "targets.txt"
        f.write_text("example.com\n")
        monkeypatch.setattr(sys, "argv", ["mytools-batch", str(f), "recon"])
        with patch.object(batch_mod, "run_batch", return_value=0) as mock_run_batch:
            assert main() == 0
        mock_run_batch.assert_called_once()


# ---------------------------------------------------------------------------
# guard
# ---------------------------------------------------------------------------


class TestMainGuard:
    def test_guard_runs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "argv", ["mytools-batch", "--version"])
        with pytest.raises(SystemExit):
            import runpy

            runpy.run_module("mytools.core.batch", run_name="__main__")
