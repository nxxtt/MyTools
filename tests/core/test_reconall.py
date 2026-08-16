import argparse
import runpy
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import pytest

from mytools.core.reconall import (
    ALL_MODULES,
    _build_base_ns,
    _extract_domain,
    _is_url,
    _make_args,
    banner,
    build_parser,
    main,
    run_all,
    run_once,
)
from mytools.network.portscanner import TOP_100_PORTS

pytestmark = pytest.mark.integration


def _domain_ns(domain: str = "example.com", **overrides: object) -> argparse.Namespace:
    """Constrói Namespace base para um dominio sem rodar run_all()."""
    parser = build_parser()
    args = parser.parse_args([domain])
    ns = _build_base_ns(args)
    for k, v in overrides.items():
        setattr(ns, k, v)
    return ns


def _url_ns(
    url: str = "https://example.com", **overrides: object
) -> argparse.Namespace:
    """Constrói Namespace base para uma URL sem rodar run_all()."""
    parser = build_parser()
    args = parser.parse_args([url])
    ns = _build_base_ns(args)
    for k, v in overrides.items():
        setattr(ns, k, v)
    return ns


class TestIsUrl:
    def test_http(self):
        assert _is_url("http://example.com") is True

    def test_https(self):
        assert _is_url("https://example.com") is True

    def test_domain(self):
        assert _is_url("example.com") is False

    def test_ip(self):
        assert _is_url("192.168.1.1") is False


class TestExtractDomain:
    def test_from_url(self):
        assert _extract_domain("https://example.com") == "example.com"

    def test_from_url_with_port(self):
        assert _extract_domain("https://example.com:8080") == "example.com"

    def test_from_domain(self):
        assert _extract_domain("example.com") == "example.com"

    def test_from_ip(self):
        assert _extract_domain("192.168.1.1") == "192.168.1.1"


class TestMakeArgs:
    def test_merges_base_and_extra(self):
        base = argparse.Namespace(timeout=5.0, verbose=False)
        result = _make_args({"url": "http://example.com", "deep": True}, base)
        assert result.url == "http://example.com"
        assert result.deep is True
        assert result.timeout == 5.0
        assert result.verbose is False


class TestBuildParser:
    def test_has_target(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.target == "example.com"

    def test_deep_flag(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--deep"])
        assert args.deep is True

    def test_test_vulns_flag(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--test-vulns"])
        assert args.test_vulns is True

    def test_skip_module(self):
        parser = build_parser()
        args = parser.parse_args(
            ["example.com", "--skip", "dnstransfer", "--skip", "subenum"]
        )
        assert "dnstransfer" in args.skip
        assert "subenum" in args.skip

    def test_skip_invalid_module_rejected(self):
        import pytest

        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["example.com", "--skip", "invalidmodule"])

    def test_dry_run(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--dry-run"])
        assert args.dry_run is True

    def test_output_dir(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--output-dir", "results/"])
        assert args.output_dir == "results/"

    def test_cve_flag(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--cve"])
        assert args.cve is True

    def test_dnshistory_in_all_modules(self):
        assert "dnshistory" in ALL_MODULES

    def test_skip_dnshistory(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "dnshistory"])
        assert "dnshistory" in args.skip


_ALL_MODULES_LIST = list(ALL_MODULES)


def _skip_all_except(*keep: str) -> list[str]:
    """Retorna lista de --skip para todos os modulos EXCETO os listados em keep."""
    keep_set = set(keep)
    result: list[str] = []
    for m in _ALL_MODULES_LIST:
        if m not in keep_set:
            result.extend(["--skip", m])
    return result


class TestRunAll:
    def test_runs_portscanner_for_domain(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", *_skip_all_except("portscanner")])
        with patch(
            "mytools.core.reconall.portscanner.run_once", return_value=0
        ) as mock_fn:
            result = run_all(args)
            assert result == 0
            mock_fn.assert_called_once()

    def test_runs_all_http_for_url(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "https://example.com",
                *_skip_all_except("dirscanner", "webrecon", "attackaudit"),
            ]
        )
        with (
            patch("mytools.core.reconall.dirscanner.run_once", return_value=0),
            patch("mytools.core.reconall.webrecon.run_once", return_value=0),
            patch("mytools.core.reconall.attackaudit.run_once", return_value=0),
        ):
            result = run_all(args)
            assert result == 0

    def test_skips_specified_modules(self):
        parser = build_parser()
        args = parser.parse_args(
            ["https://example.com", *_skip_all_except("attackaudit")]
        )
        with (
            patch("mytools.core.reconall.attackaudit.run_once", return_value=0),
            patch("mytools.core.reconall.dirscanner.run_once") as mock_dir,
            patch("mytools.core.reconall.webrecon.run_once") as mock_web,
        ):
            mock_dir.return_value = 0
            mock_web.return_value = 0
            result = run_all(args)
            assert result == 0
            mock_dir.assert_not_called()
            mock_web.assert_not_called()

    def test_counts_errors(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", *_skip_all_except("portscanner")])
        with patch("mytools.core.reconall.portscanner.run_once", return_value=1):
            result = run_all(args)
            assert result == 1

    def test_passes_deep_flag(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "https://example.com",
                *_skip_all_except("dirscanner", "webrecon", "attackaudit"),
                "--deep",
            ]
        )
        with (
            patch("mytools.core.reconall.dirscanner.run_once", return_value=0),
            patch(
                "mytools.core.reconall.webrecon.run_once", return_value=0
            ) as mock_web,
            patch("mytools.core.reconall.attackaudit.run_once", return_value=0),
        ):
            run_all(args)
            call_args = mock_web.call_args[0][0]
            assert call_args.deep is True


class TestNamespaceConstruction:
    def test_portscanner_has_threads(self):
        ns = _make_args(
            {"targets": ["example.com"], "ports": TOP_100_PORTS, "output": None},
            _domain_ns(),
        )
        assert hasattr(ns, "threads")
        assert ns.threads is None

    def test_portscanner_has_workers(self):
        ns = _make_args(
            {"targets": ["example.com"], "ports": TOP_100_PORTS, "output": None},
            _domain_ns(),
        )
        assert hasattr(ns, "workers")
        assert ns.workers == 100

    def test_dirscanner_has_required_attrs(self):
        ns = _make_args(
            {
                "url": "https://example.com",
                "extensions": ["php", "txt", "bak", "html"],
                "output": None,
            },
            _url_ns(),
        )
        for attr in (
            "user_agent",
            "proxy",
            "delay",
            "auth",
            "header",
            "cookie",
            "concurrency",
            "status",
            "method",
            "wordlist",
            "extensions",
            "filter_size",
            "filter_words",
            "retries",
        ):
            assert hasattr(ns, attr), f"dirscanner missing attribute: {attr}"

    def test_dirscanner_extensions_is_list(self):
        ns = _make_args(
            {
                "url": "https://example.com",
                "extensions": ["php", "txt", "bak", "html"],
                "output": None,
            },
            _url_ns(),
        )
        assert isinstance(ns.extensions, list)
        assert ns.extensions == ["php", "txt", "bak", "html"]

    def test_webrecon_has_required_attrs(self):
        ns = _make_args(
            {"url": "https://example.com", "cve": False, "deep": False, "output": None},
            _url_ns(),
        )
        for attr in (
            "user_agent",
            "proxy",
            "cve",
            "deep",
            "crawl_limit",
            "nvd_api_key",
        ):
            assert hasattr(ns, attr), f"webrecon missing attribute: {attr}"

    def test_attackaudit_has_required_attrs(self):
        ns = _make_args(
            {
                "url": "https://example.com",
                "deep": False,
                "test_vulns": False,
                "test_methods": False,
                "output": None,
            },
            _url_ns(),
        )
        for attr in (
            "user_agent",
            "proxy",
            "delay",
            "concurrency",
            "deep",
            "test_vulns",
            "test_methods",
            "paths_file",
            "params",
        ):
            assert hasattr(ns, attr), f"attackaudit missing attribute: {attr}"

    def test_subenum_has_threads(self):
        ns = _make_args({"domain": "example.com", "output": None}, _domain_ns())
        assert hasattr(ns, "threads")
        assert ns.threads is None or isinstance(ns.threads, int)

    def test_portscanner_ports_is_list(self):
        ns = _make_args(
            {"targets": ["example.com"], "ports": TOP_100_PORTS, "output": None},
            _domain_ns(),
        )
        assert isinstance(ns.ports, list)
        assert all(isinstance(p, int) for p in ns.ports)

    def test_portscanner_default_ports_count(self):
        ns = _make_args(
            {"targets": ["example.com"], "ports": TOP_100_PORTS, "output": None},
            _domain_ns(),
        )
        assert len(ns.ports) == len(TOP_100_PORTS)

    def test_portscanner_custom_ports(self):
        ns = _make_args(
            {"targets": ["example.com"], "ports": [22, 80, 443], "output": None},
            _domain_ns(),
        )
        assert ns.ports == [22, 80, 443]

    def test_http_modules_user_agent_not_none(self):
        ns = _make_args(
            {"url": "https://example.com", "cve": False, "deep": False, "output": None},
            _url_ns(),
        )
        assert ns.user_agent is not None
        assert "MyTools/" in ns.user_agent

    def test_portscanner_has_output(self):
        ns = _make_args(
            {
                "targets": ["example.com"],
                "ports": TOP_100_PORTS,
                "output": "results/portscanner.json",
            },
            _domain_ns(),
        )
        assert ns.output is not None
        assert "portscanner" in ns.output

    def test_dnshistory_runs_for_domain(self):
        ns = _make_args({"domain": "example.com", "output": None}, _domain_ns())
        assert ns.domain == "example.com"

    def test_dnshistory_runs_for_url(self):
        ns = _make_args({"domain": "example.com", "output": None}, _url_ns())
        assert ns.domain == "example.com"

    def test_dnshistory_has_required_attrs(self):
        ns = _make_args({"domain": "example.com", "output": None}, _domain_ns())
        for attr in (
            "source",
            "record_types",
            "dnslytics_key",
            "st_api_key",
            "viewdns_key",
        ):
            assert hasattr(ns, attr), f"dnshistory missing attribute: {attr}"

    def test_whoishistory_in_all_modules(self):
        assert "whoishistory" in ALL_MODULES

    def test_skip_whoishistory(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "whoishistory"])
        assert "whoishistory" in args.skip

    def test_whoishistory_runs_for_domain(self):
        ns = _make_args({"domain": "example.com", "output": None}, _domain_ns())
        assert ns.domain == "example.com"

    def test_whoishistory_runs_for_url(self):
        ns = _make_args({"domain": "example.com", "output": None}, _url_ns())
        assert ns.domain == "example.com"

    def test_whoishistory_has_required_attrs(self):
        ns = _make_args({"domain": "example.com", "output": None}, _domain_ns())
        for attr in ("st_api_key", "whoisxml_key", "source"):
            assert hasattr(ns, attr), f"whoishistory missing attribute: {attr}"

    def test_ipasninfo_in_all_modules(self):
        assert "ipasninfo" in ALL_MODULES

    def test_skip_ipasninfo(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "ipasninfo"])
        assert "ipasninfo" in args.skip

    def test_ipasninfo_runs_for_domain(self):
        ns = _make_args({"ips": ["example.com"], "output": None}, _domain_ns())
        assert hasattr(ns, "ips")

    def test_ipasninfo_runs_for_url(self):
        ns = _make_args({"ips": ["example.com"], "output": None}, _url_ns())
        assert hasattr(ns, "ips")

    def test_ipasninfo_has_required_attrs(self):
        ns = _make_args({"ips": ["example.com"], "output": None}, _domain_ns())
        for attr in ("ips", "output"):
            assert hasattr(ns, attr), f"ipasninfo missing attribute: {attr}"

    def test_techfingerprint_in_all_modules(self):
        assert "techfingerprint" in ALL_MODULES

    def test_skip_techfingerprint(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "techfingerprint"])
        assert "techfingerprint" in args.skip

    def test_techfingerprint_runs_for_url(self):
        ns = _make_args(
            {"urls": ["https://example.com"], "output": None},
            _url_ns(),
        )
        assert hasattr(ns, "urls")

    def test_techfingerprint_has_required_attrs(self):
        ns = _make_args(
            {"urls": ["https://example.com"], "output": None},
            _url_ns(),
        )
        assert hasattr(ns, "urls")
        assert hasattr(ns, "output")


class TestAuthArgs:
    """Testes para argumentos de auth no reconall."""

    def test_has_auth_argument(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--auth", "user:pass"])
        assert args.auth == {"Authorization": "Basic dXNlcjpwYXNz"}

    def test_has_bearer_token_argument(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--bearer-token", "tok123"])
        assert args.bearer_token == "tok123"

    def test_has_cookie_argument(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--cookie", "session=abc"])
        assert args.cookie == "session=abc"

    def test_has_header_argument(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--header", "X-Token: abc"])
        assert args.header == ["X-Token: abc"]

    def test_header_multiple(self):
        parser = build_parser()
        args = parser.parse_args(
            ["example.com", "--header", "X-A: 1", "--header", "X-B: 2"]
        )
        assert args.header == ["X-A: 1", "X-B: 2"]

    def test_auth_defaults_none(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.auth is None
        assert args.bearer_token is None
        assert args.cookie is None
        assert args.header == []


class TestAuthPropagated:
    """Testes para propagacao de auth via base_ns."""

    def test_bearer_token_propagated_to_http_modules(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "https://example.com",
                "--bearer-token",
                "tok_abc",
                *_skip_all_except("webrecon", "attackaudit"),
            ]
        )
        with (
            patch(
                "mytools.core.reconall.webrecon.run_once", return_value=0
            ) as mock_web,
            patch(
                "mytools.core.reconall.attackaudit.run_once", return_value=0
            ) as mock_audit,
        ):
            run_all(args)
            for mock_fn in (mock_web, mock_audit):
                ns = mock_fn.call_args[0][0]
                assert ns.bearer_token == "tok_abc"

    def test_auth_propagated_to_http_modules(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "https://example.com",
                "--auth",
                "admin:s3cret",
                *_skip_all_except("webrecon", "attackaudit"),
            ]
        )
        with (
            patch(
                "mytools.core.reconall.webrecon.run_once", return_value=0
            ) as mock_web,
            patch(
                "mytools.core.reconall.attackaudit.run_once", return_value=0
            ) as mock_audit,
        ):
            run_all(args)
            for mock_fn in (mock_web, mock_audit):
                ns = mock_fn.call_args[0][0]
                assert ns.auth is not None

    def test_cookie_propagated(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "https://example.com",
                "--cookie",
                "sid=xyz",
                *_skip_all_except("webrecon"),
            ]
        )
        with patch(
            "mytools.core.reconall.webrecon.run_once", return_value=0
        ) as mock_web:
            run_all(args)
            ns = mock_web.call_args[0][0]
            assert ns.cookie == "sid=xyz"

    def test_header_propagated(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "https://example.com",
                "--header",
                "X-Custom: val",
                *_skip_all_except("attackaudit"),
            ]
        )
        with patch(
            "mytools.core.reconall.attackaudit.run_once", return_value=0
        ) as mock_audit:
            run_all(args)
            ns = mock_audit.call_args[0][0]
            assert ns.header == ["X-Custom: val"]

    def test_auth_none_does_not_override_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", *_skip_all_except("webrecon")])
        with patch(
            "mytools.core.reconall.webrecon.run_once", return_value=0
        ) as mock_web:
            run_all(args)
            ns = mock_web.call_args[0][0]
            assert ns.auth is None
            assert ns.bearer_token is None


_MODULE_ATTRS = [
    "attackaudit",
    "backupfiledetect",
    "blindxss",
    "bominjection",
    "caacheck",
    "cachedeception",
    "cachepoisoning",
    "charsetbypass",
    "clickjacking",
    "cloudbucketenum",
    "cmdinject",
    "configfiledetect",
    "corsmisconfig",
    "crlfinjection",
    "csrfscan",
    "darkwebmonitor",
    "deserialinject",
    "dirscanner",
    "dnsamplification",
    "dnshistory",
    "dnsrebinding",
    "dnssecvalidation",
    "dnstransfer",
    "dnstunnel",
    "dnswatorture",
    "doubleurlencode",
    "emailaddressbypass",
    "emailattachmentbypass",
    "emailbreachcheck",
    "emaillinktracking",
    "emailsecurity",
    "emailspoof",
    "emailtemplateinject",
    "googledorking",
    "graphqlplayground",
    "headerinject",
    "hostheaderinject",
    "httpparampollution",
    "ipasninfo",
    "ldapiinject",
    "lfidetect",
    "log4shell",
    "loginbruteforce",
    "loginjection",
    "methodoverride",
    "nosqliinject",
    "nsecwalking",
    "nullbyteinject",
    "openapidiscovery",
    "openredirect",
    "overlongencoding",
    "pasteleak",
    "pathtraversal",
    "portscanner",
    "prototypepollution",
    "rtloverride",
    "smtpdowngrade",
    "smtpinjection",
    "socialengrecon",
    "sourcemapdiscovery",
    "sqliscan",
    "ssiinject",
    "ssrfdetect",
    "sstidetect",
    "subdomainenum",
    "subdomaintakeover",
    "techfingerprint",
    "vcsleak",
    "webrecon",
    "whoishistory",
    "xpathinject",
    "xxedetect",
]


def _patch_all_modules() -> ExitStack:
    """Patcha run_once de todos os modulos filhos para retornar 0.

    Retorna um ExitStack ativo; o caller deve fechar o stack (ou usar ``with``)
    para reverter os patches.
    """
    stack = ExitStack()
    for mod_name in _MODULE_ATTRS:
        stack.enter_context(
            patch(f"mytools.core.reconall.{mod_name}.run_once", return_value=0)
        )
    return stack


class TestRunAllFull:
    """Exercita o caminho completo de run_all() com TODOS os modulos ativos."""

    def test_all_domain_modules_run(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        with _patch_all_modules():
            result = run_all(args)
        assert result == 0

    def test_all_url_modules_run(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        with _patch_all_modules():
            result = run_all(args)
        assert result == 0

    def test_output_dir_creates_directory(self, tmp_path):
        parser = build_parser()
        args = parser.parse_args(
            ["https://example.com", "--output-dir", str(tmp_path / "res")]
        )
        with _patch_all_modules():
            result = run_all(args)
        assert result == 0
        assert (tmp_path / "res").is_dir()

    def test_output_paths_passed_to_modules(self, tmp_path):
        parser = build_parser()
        args = parser.parse_args(
            ["https://example.com", "--output-dir", str(tmp_path / "res")]
        )
        stack = _patch_all_modules()
        mock_web = stack.enter_context(
            patch("mytools.core.reconall.webrecon.run_once", return_value=0)
        )
        with stack:
            run_all(args)
            ns = mock_web.call_args[0][0]
            out = Path(ns.output)
            assert out.parent == tmp_path / "res" / "webrecon"
            assert out.suffix == ".json"
            assert out.stem.startswith("20")

    def test_empty_skipped_returns_zero(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", *_skip_all_except()])
        result = run_all(args)
        assert result == 0

    def test_non_url_without_url_only_modules(self):
        # Alvo sem esquema e ALL_MODULES sem modulos URL-only -> aviso vazio.
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        stack = _patch_all_modules()
        stack.enter_context(
            patch("mytools.core.reconall.ALL_MODULES", ["dnstransfer"])
        )
        with stack:
            result = run_all(args)
        assert result == 0


class TestRunAllErrorHandling:
    def test_exception_in_module_returns_one(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        stack = _patch_all_modules()
        stack.enter_context(
            patch(
                "mytools.core.reconall.portscanner.run_once",
                side_effect=RuntimeError("boom"),
            )
        )
        with stack:
            result = run_all(args)
        assert result == 1

    def test_partial_errors_summed(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        stack = _patch_all_modules()
        stack.enter_context(
            patch("mytools.core.reconall.portscanner.run_once", return_value=1)
        )
        stack.enter_context(
            patch("mytools.core.reconall.dnstransfer.run_once", return_value=2)
        )
        with stack:
            result = run_all(args)
        assert result == 3


class TestRunOnce:
    def test_dry_run_returns_zero(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--dry-run"])
        assert run_once(args) == 0

    def test_dry_run_logs_auth_bearer(self):
        parser = build_parser()
        args = parser.parse_args(
            ["example.com", "--dry-run", "--bearer-token", "tok123"]
        )
        assert run_once(args) == 0

    def test_dry_run_logs_auth_basic(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--dry-run", "--auth", "u:p"])
        assert run_once(args) == 0

    def test_dry_run_logs_auth_cookie(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--dry-run", "--cookie", "s=1"])
        assert run_once(args) == 0

    def test_dry_run_extra_flags(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "example.com",
                "--dry-run",
                "--deep",
                "--test-vulns",
                "--test-methods",
                "--cve",
            ]
        )
        assert run_once(args) == 0

    def test_runs_all_and_returns_zero(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        with patch("mytools.core.reconall.run_all", return_value=0):
            result = run_once(args)
        assert result == 0

    def test_runs_all_and_returns_error(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        with patch("mytools.core.reconall.run_all", return_value=2):
            result = run_once(args)
        assert result == 1


class TestMain:
    def test_no_args_enters_shell(self):
        with (
            patch.object(sys, "argv", ["mytools-reconall"]),
            patch(
                "mytools.core.reconall.run_interactive_shell", return_value=0
            ) as mock_shell,
        ):
            result = main()
        assert result == 0
        assert mock_shell.call_args.kwargs["prompt"] == "reconall> "

    def test_with_target_runs_once(self):
        with (
            patch.object(sys, "argv", ["mytools-reconall", "example.com"]),
            patch("mytools.core.reconall.run_once", return_value=0) as mock_run,
        ):
            result = main()
        assert result == 0
        mock_run.assert_called_once()

    def test_guard_runs(self):
        with (
            patch.object(sys, "argv", ["mytools-reconall", "--version"]),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.core.reconall", run_name="__main__")

    def test_banner_prints(self, capsys):
        banner()
        out = capsys.readouterr().out
        assert "recon all-in-one" in out


class TestRtlOverrideRegistered:
    def test_rtloverride_in_all_modules(self):
        assert "rtloverride" in ALL_MODULES

    def test_rtloverride_scheduled_for_url(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        with (
            _patch_all_modules(),
            patch("mytools.core.reconall.rtloverride.run_once", return_value=0) as mock,
        ):
            run_all(args)
        assert mock.call_count == 1
        ns = mock.call_args[0][0]
        assert ns.url == "https://example.com"

    def test_rtloverride_skipped_for_bare_domain(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        with (
            _patch_all_modules(),
            patch("mytools.core.reconall.rtloverride.run_once", return_value=0) as mock,
        ):
            run_all(args)
        assert mock.call_count == 0


class TestGetParserDefaults:
    def test_no_stderr_spam_on_required_positionals(self, capsys):
        import mytools.core.reconall as reconall_mod

        with patch.object(reconall_mod, "_PARSER_DEFAULTS", None):
            reconall_mod.get_parser_defaults()
        err = capsys.readouterr().err
        assert "the following arguments are required" not in err


class TestModuleTimeout:
    def test_timeout_counts_as_error(self):
        import time

        import mytools.core.reconall as reconall_mod

        original_timeout = reconall_mod._MODULE_TIMEOUT_SECONDS
        original_max = reconall_mod._MAX_CONCURRENT_MODULES
        reconall_mod._MODULE_TIMEOUT_SECONDS = 0.05
        reconall_mod._MAX_CONCURRENT_MODULES = 64
        try:
            parser = build_parser()
            args = parser.parse_args(["example.com", *_skip_all_except("dnstransfer")])
            args.target = "https://example.com"

            def _slow(*_a, **_k):
                time.sleep(5)
                return 0

            with patch("mytools.core.reconall.dnstransfer.run_once", side_effect=_slow):
                result = run_all(args)
        finally:
            reconall_mod._MODULE_TIMEOUT_SECONDS = original_timeout
            reconall_mod._MAX_CONCURRENT_MODULES = original_max
        assert result == 1

    def test_per_module_timeout_override(self):
        import time

        import mytools.core.reconall as reconall_mod

        original_timeouts = dict(reconall_mod._MODULE_TIMEOUTS)
        original_max = reconall_mod._MAX_CONCURRENT_MODULES
        reconall_mod._MODULE_TIMEOUTS = {"dnstransfer": 0.05}
        reconall_mod._MAX_CONCURRENT_MODULES = 64
        try:
            parser = build_parser()
            args = parser.parse_args(["example.com", *_skip_all_except("dnstransfer")])
            args.target = "https://example.com"

            def _slow(*_a, **_k):
                time.sleep(5)
                return 0

            with patch("mytools.core.reconall.dnstransfer.run_once", side_effect=_slow):
                result = run_all(args)
        finally:
            reconall_mod._MODULE_TIMEOUTS = original_timeouts
            reconall_mod._MAX_CONCURRENT_MODULES = original_max
        assert result == 1
