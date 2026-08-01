"""Testes do menu dinamico (mytools.core.main).

Cobre: descoberta via entry points (113 tools), categorias, paginacao,
navegacao de 2 niveis, dispatch por numero/nome/alias, --version,
importabilidade e unicidade de aliases.
"""

import importlib.metadata as im
import sys

import pytest

from mytools.core import main as main_mod
from mytools.core.main import (
    _ALIASES,
    _CATEGORY_ORDER,
    _DISPLAY_NAMES,
    PAGE_SIZE,
    _display_name,
    _load_tools,
    _resolve_tool,
    _tools_by_category,
    help_screen,
    main,
    menu_category,
    menu_root,
)


@pytest.fixture
def no_clear(monkeypatch):
    """Evita que os testes chamem os.system('cls')."""
    monkeypatch.setattr(main_mod, "clear_console", lambda: None)


@pytest.fixture
def no_banner(monkeypatch):
    """Evita banner ruidoso nos testes de fluxo."""
    monkeypatch.setattr(main_mod, "banner", lambda: None)


@pytest.fixture
def fake_run(monkeypatch):
    """Intercepta _run_tool e registra as chamadas."""
    calls = []

    def _spy(cat, mod):
        calls.append((cat, mod))

    monkeypatch.setattr(main_mod, "_run_tool", _spy)
    return calls


class TestLoadTools:
    def test_112_tools_from_entry_points(self):
        tools = _load_tools()
        assert len(tools) == 113

    def test_matches_pyproject_scripts(self):
        eps = im.entry_points(group="console_scripts")
        scripts = {
            e.name for e in eps if e.name.startswith("mytools-") and e.name != "mytools"
        }
        tools = {script for script, _, _ in _load_tools()}
        assert tools == scripts

    def test_categories_match_expected_order(self):
        by_cat = _tools_by_category()
        assert set(by_cat) == set(_CATEGORY_ORDER)
        assert len(by_cat["config"]) == 2
        assert len(by_cat["core"]) == 4
        assert len(by_cat["dns"]) == 12
        assert len(by_cat["email"]) == 8
        assert len(by_cat["mobile"]) == 1
        assert len(by_cat["network"]) == 2
        assert len(by_cat["osint"]) == 6
        assert len(by_cat["vcs"]) == 1
        assert len(by_cat["web"]) == 76
        assert len(by_cat["whois"]) == 1


class TestDisplayNames:
    def test_all_modules_have_display_name(self):
        tools = _load_tools()
        assert all(mod in _DISPLAY_NAMES for _, _, mod in tools)

    def test_display_name_fallback(self):
        assert _display_name("webrecon") == "Web Recon"
        assert _display_name("cmdinject") == "Command Injection"
        assert _display_name("mxss") == "Mutable XSS (mXSS)"
        assert _display_name("modulo_inexistente") == "Modulo Inexistente"

    def test_aliases_unique_keys(self):
        keys = list(_ALIASES)
        assert len(keys) == len(set(keys))

    def test_aliases_resolve_to_real_modules(self):
        tools = _load_tools()
        mods = {mod for _, _, mod in tools}
        assert all(target in mods for target in _ALIASES.values())


class TestResolve:
    def test_resolve_by_module_name(self):
        assert _resolve_tool("blindxss") == ("web", "blindxss")

    def test_resolve_by_script_name(self):
        assert _resolve_tool("sqli") == ("web", "sqliscan")

    def test_resolve_by_full_script(self):
        assert _resolve_tool("mytools-sqli") == ("web", "sqliscan")

    def test_resolve_by_alias(self):
        assert _resolve_tool("cmd") == ("web", "cmdinject")
        assert _resolve_tool("port") == ("network", "portscanner")
        assert _resolve_tool("dns") == ("dns", "dnstransfer")

    def test_resolve_unknown_returns_none(self):
        assert _resolve_tool("nao-existe-xyz") is None


class TestMenuRendering:
    def test_root_lists_categories(self, capsys):
        by_cat = _tools_by_category()
        menu_root(by_cat)
        out = capsys.readouterr().out
        for label in (
            "CONFIG",
            "CORE",
            "DNS",
            "EMAIL",
            "MOBILE",
            "NETWORK",
            "OSINT",
            "VCS",
            "WEB",
            "WHOIS",
        ):
            assert label in out
        assert "(76)" in out

    def test_category_pagination_web_8_pages(self, capsys):
        items = _tools_by_category()["web"]
        pages = (len(items) + PAGE_SIZE - 1) // PAGE_SIZE
        assert pages == 8
        menu_category("web", items, 0, pages)
        out = capsys.readouterr().out
        assert "Pagina 1/8" in out
        for _, mod in items[:PAGE_SIZE]:
            assert _display_name(mod) in out


class TestMainFlow:
    def test_version_flag(self, capsys, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["main.py", "--version"])
        assert main() == 0
        assert "mytools 3.2.0" in capsys.readouterr().out

    def test_version_short(self, capsys, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["main.py", "-V"])
        assert main() == 0
        assert "mytools 3.2.0" in capsys.readouterr().out

    def test_quit_from_root(self, monkeypatch, no_clear, no_banner):
        monkeypatch.setattr("builtins.input", lambda *_: "q")
        assert main() == 0

    def test_dispatch_by_category_and_number(
        self, monkeypatch, no_clear, no_banner, fake_run
    ):
        inputs = iter(["web", "1", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        assert fake_run == [("web", "accountabuse")]

    def test_dispatch_by_category_and_name(
        self, monkeypatch, no_clear, no_banner, fake_run
    ):
        inputs = iter(["web", "blindxss", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        assert fake_run == [("web", "blindxss")]

    def test_dispatch_direct_by_alias(self, monkeypatch, no_clear, no_banner, fake_run):
        inputs = iter(["cmd", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        assert fake_run == [("web", "cmdinject")]

    def test_dispatch_direct_by_script(
        self, monkeypatch, no_clear, no_banner, fake_run
    ):
        inputs = iter(["mytools-sqli", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        assert fake_run == [("web", "sqliscan")]

    def test_category_back_returns_root(
        self, monkeypatch, no_clear, no_banner, fake_run
    ):
        inputs = iter(["web", "0", "dns", "0", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        assert fake_run == []

    def test_pagination_next_prev(self, monkeypatch, no_clear, no_banner, fake_run):
        inputs = iter(["web", "n", "p", "2", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        assert fake_run == [("web", "attackanalysis")]

    def test_pagination_reaches_second_page(
        self, monkeypatch, no_clear, no_banner, fake_run
    ):
        inputs = iter(["web", "n", "1", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        assert fake_run == [("web", "clickjacking")]

    def test_invalid_choice_ignored(self, monkeypatch, no_clear, no_banner, fake_run):
        inputs = iter(["web", "zzz", "", "2", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        assert fake_run == [("web", "attackanalysis")]

    def test_exit_tool_returns_to_categories(
        self, monkeypatch, no_clear, no_banner, fake_run
    ):
        inputs = iter(["web", "1", "3", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        assert fake_run == [("web", "accountabuse")]

    def test_help_from_root(self, monkeypatch, no_clear, no_banner, capsys):
        inputs = iter(["h", "", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        out = capsys.readouterr().out
        assert "Exemplos:" in out


class TestHelpScreen:
    def test_help_lists_examples(self, capsys):
        by_cat = _tools_by_category()
        help_screen(by_cat)
        out = capsys.readouterr().out
        assert "Exemplos:" in out
        assert "mytools-port --help" in out
        assert "mytools-bak --help" in out


class TestImportability:
    def test_all_tools_importable_with_callable_main(self):
        tools = _load_tools()
        for cat, mod in ((cat, mod) for _, cat, mod in tools):
            module = __import__(f"mytools.{cat}.{mod}", fromlist=[mod])
            assert callable(getattr(module, "main", None)), mod
