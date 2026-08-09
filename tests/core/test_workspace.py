import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from mytools.core.base import BaseScanner, ScanGroup
from mytools.core.utils import (
    run_main_loop,
    workspace_path,
    workspace_timestamp,
    write_output,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# workspace_timestamp
# ---------------------------------------------------------------------------


class TestWorkspaceTimestamp:
    def test_format(self):
        ts = workspace_timestamp()
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}", ts)

    def test_lexicographic_order(self):
        ts1 = workspace_timestamp()
        time.sleep(1.1)
        ts2 = workspace_timestamp()
        assert ts1 < ts2


# ---------------------------------------------------------------------------
# workspace_path
# ---------------------------------------------------------------------------


class TestWorkspacePath:
    def test_url_with_port(self):
        p = workspace_path("/tmp/out", "https://a.com:8443/x")
        assert p.name.endswith(".json")
        assert p.parent.name == "a.com_8443"

    def test_plain_host(self):
        p = workspace_path("/tmp/out", "example.com")
        assert p.name.endswith(".json")
        assert p.parent.name == "example.com"

    def test_plain_host_with_port(self):
        p = workspace_path("/tmp/out", "a.com:8080")
        assert p.name.endswith(".json")
        assert p.parent.name == "a.com_8080"

    def test_nested_output_dir(self):
        p = workspace_path("/tmp/a/b/c", "host.local")
        assert p.parent.name == "host.local"
        assert p.parts[1:4] == ("tmp", "a", "b")


# ---------------------------------------------------------------------------
# Fake scanners for BaseScanner integration
# ---------------------------------------------------------------------------


@dataclass
class _FakeResultB:
    overall_status: str = "ok"
    target: str = ""
    findings: list[str] = field(default_factory=list)


class _FakeScannerB(BaseScanner):
    """Group B fake scanner — returns a Result dataclass."""

    prog = "fake-b"
    description = "Fake Group B scanner"
    prompt = "fake-b> "
    module_name = "fake_b"
    banner_text = "Fake B"
    group = ScanGroup.B

    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("url", nargs="?", default=None)

    async def run_scan(self, **kwargs):  # type: ignore[override]
        return _FakeResultB(target=kwargs.get("url", ""))

    def print_results(self, result: object) -> None:
        pass

    def _example(self) -> str:
        return "fake-b https://example.com"

    def _help(self) -> str:
        return "Fake B help"


class _FakeScannerA(BaseScanner):
    """Group A fake scanner — run_scan returns int, manages output internally."""

    prog = "fake-a"
    description = "Fake Group A scanner"
    prompt = "fake-a> "
    module_name = "fake_a"
    banner_text = "Fake A"
    group = ScanGroup.A

    def __init__(self) -> None:
        super().__init__()
        self._last_output_file: str | None = None

    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("url", nargs="?", default=None)

    async def run_scan(self, **kwargs):  # type: ignore[override]
        self._last_output_file = kwargs.get("output_file")
        if self._last_output_file:
            write_output(self._last_output_file, {"target": kwargs.get("target", "")})
        return 0

    def print_results(self, result: object) -> None:
        pass

    def _example(self) -> str:
        return "fake-a https://example.com"

    def _help(self) -> str:
        return "Fake A help"


def _make_args(scanner: BaseScanner, extra: list[str]) -> argparse.Namespace:
    """Build args with all stealth defaults for testing."""
    parser = scanner.build_parser()
    args = parser.parse_args(extra)
    args.verbose = False
    args.log_file = None
    args.quiet = True
    args.color = None
    args.theme = "cyber"
    args.severity_override = None
    args.random_delay = False
    args.jitter = 0.0
    args.user_agent_rotate = False
    args.impersonate = None
    args.tor = False
    args.waf_evasion = False
    args.pad_headers = 0
    return args


# ---------------------------------------------------------------------------
# Group B integration
# ---------------------------------------------------------------------------


class TestGroupBWorkspace:
    def test_output_dir_only(self, tmp_path: Path):
        scanner = _FakeScannerB()
        args = _make_args(
            scanner,
            [
                "https://example.com",
                "--output-dir",
                str(tmp_path),
            ],
        )

        code = scanner.run_once(args)
        assert code == 0

        json_files = list(tmp_path.rglob("*.json"))
        assert len(json_files) == 1
        data = json.loads(json_files[0].read_text(encoding="utf-8"))
        assert data["target"] == "https://example.com"

    def test_both_flags_two_files(self, tmp_path: Path):
        scanner = _FakeScannerB()
        out_file = str(tmp_path / "explicit.json")
        args = _make_args(
            scanner,
            [
                "https://example.com",
                "-o",
                out_file,
                "--output-dir",
                str(tmp_path / "ws"),
            ],
        )

        code = scanner.run_once(args)
        assert code == 0

        assert Path(out_file).exists()
        ws_files = list((tmp_path / "ws").rglob("*.json"))
        assert len(ws_files) == 1


# ---------------------------------------------------------------------------
# Group A integration
# ---------------------------------------------------------------------------


class TestGroupAWorkspace:
    def test_output_dir_fallback(self, tmp_path: Path):
        scanner = _FakeScannerA()
        args = _make_args(
            scanner,
            [
                "https://target.com",
                "--output-dir",
                str(tmp_path),
            ],
        )

        scanner.run_once(args)
        assert scanner._last_output_file is not None
        assert "target.com" in scanner._last_output_file
        assert scanner._last_output_file.endswith(".json")

    def test_output_flag_takes_priority(self, tmp_path: Path):
        scanner = _FakeScannerA()
        explicit = str(tmp_path / "explicit.json")
        args = _make_args(
            scanner,
            [
                "https://target.com",
                "-o",
                explicit,
                "--output-dir",
                str(tmp_path / "ws"),
            ],
        )

        scanner.run_once(args)
        assert scanner._last_output_file == explicit


# ---------------------------------------------------------------------------
# BaseScanner edge cases (no target, main entry point)
# ---------------------------------------------------------------------------


class TestBaseScannerEdgeCases:
    def test_run_once_b_no_target(self, capsys):
        scanner = _FakeScannerB()
        args = _make_args(scanner, [])
        code = scanner.run_once(args)
        assert code == 1
        assert "Especifique um alvo." in capsys.readouterr().out

    def test_main_with_target(self, monkeypatch):
        scanner = _FakeScannerB()
        monkeypatch.setattr(sys, "argv", ["fake-b", "https://example.com"])
        assert scanner.main() == 0


# ---------------------------------------------------------------------------
# run_main_loop injection (legacy modules)
# ---------------------------------------------------------------------------


def _run_main_loop_with_args(
    argv: list[str], run_fn, parser: argparse.ArgumentParser
) -> int:
    old_argv = sys.argv
    sys.argv = argv
    try:
        return run_main_loop(
            parser=parser,
            banner_fn=lambda: None,
            run_fn=run_fn,
            has_target=lambda a: bool(getattr(a, "url", None)),
            prompt="fake> ",
            description="Fake",
            example="fake https://example.com",
            contextual_help="help",
        )
    finally:
        sys.argv = old_argv


class TestRunMainLoopWorkspace:
    def _make_writer(self, recorded: dict[str, object]):
        def run_fn(args: argparse.Namespace) -> int:
            recorded["output"] = args.output
            if args.output:
                write_output(args.output, {"target": getattr(args, "url", "")})
            return 0

        return run_fn

    def test_output_dir_injected(self, tmp_path: Path):
        scanner = _FakeScannerB()
        parser = scanner.build_parser()
        recorded: dict[str, object] = {}
        run_fn = self._make_writer(recorded)

        code = _run_main_loop_with_args(
            ["fake", "https://example.com", "--output-dir", str(tmp_path)],
            run_fn,
            parser,
        )

        assert code == 0
        out = recorded["output"]
        assert isinstance(out, str)
        assert "example.com" in out
        assert out.endswith(".json")
        assert Path(out).exists()

    def test_explicit_output_wins(self, tmp_path: Path):
        scanner = _FakeScannerB()
        parser = scanner.build_parser()
        explicit = str(tmp_path / "explicit.json")
        recorded: dict[str, object] = {}
        run_fn = self._make_writer(recorded)

        code = _run_main_loop_with_args(
            [
                "fake",
                "https://example.com",
                "-o",
                explicit,
                "--output-dir",
                str(tmp_path / "ws"),
            ],
            run_fn,
            parser,
        )

        assert code == 0
        assert recorded["output"] == explicit
        assert Path(explicit).exists()

    def test_quiet_with_output_dir(self, tmp_path: Path):
        scanner = _FakeScannerB()
        parser = scanner.build_parser()
        recorded: dict[str, object] = {}
        run_fn = self._make_writer(recorded)

        code = _run_main_loop_with_args(
            ["fake", "-q", "https://example.com", "--output-dir", str(tmp_path)],
            run_fn,
            parser,
        )

        assert code == 0
        assert isinstance(recorded["output"], str)
        assert Path(recorded["output"]).exists()
