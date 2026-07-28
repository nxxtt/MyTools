import argparse
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mytools.core.batch import (
    TargetResult,
    _detect_target_type,
    _get_all_module_names,
    _get_registry,
    _is_compatible,
    _make_args,
    _print_report,
    _resolve_module,
    _sanitize_target,
    main,
    process_target,
    read_targets,
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
