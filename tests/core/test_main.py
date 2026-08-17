"""Testes do menu dinamico (mytools.core.main).

Cobre: descoberta via entry points (113 tools), categorias, paginacao,
navegacao de 2 niveis, dispatch por numero/nome/alias, --version,
importabilidade e unicidade de aliases.
"""

import importlib.metadata as im
import sys
import types
from unittest.mock import MagicMock

import pytest

from mytools.core import main as main_mod
from mytools.core.main import (
    _ALIASES,
    _CATEGORY_ORDER,
    _DISPLAY_NAMES,
    PAGE_SIZE,
    _display_name,
    _load_tools,
    _load_tools_from_pyproject,
    _resolve_tool,
    _tools_by_category,
    banner,
    help_screen,
    main,
    menu_category,
    menu_root,
)


def _load_tools_as_eps():
    """Retorna os entry points reais como lista."""
    return list(im.entry_points(group="console_scripts"))


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
    def test_114_tools_from_entry_points(self):
        tools = _load_tools()
        assert len(tools) == 114

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
        assert len(by_cat["osint"]) == 7
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

    def test_resolve_alias_without_tools_returns_none(self, monkeypatch):
        monkeypatch.setattr(main_mod, "_load_tools", lambda: [])
        assert _resolve_tool("cmd") is None

    def test_resolve_alias_unmatched_tool_returns_none(self, monkeypatch):
        monkeypatch.setattr(
            main_mod,
            "_load_tools",
            lambda: [
                ("mytools-bak", "config", "backupfiledetect"),
                ("mytools-sqli", "web", "sqliscan"),
            ],
        )
        assert _resolve_tool("port") is None


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
        inputs = iter(["9", "1", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        assert fake_run == [("web", "accountabuse")]

    def test_eoferror_in_category_menu(self, monkeypatch, no_clear, no_banner):
        calls = {"n": 0}

        def _input(*_):
            calls["n"] += 1
            if calls["n"] == 1:
                return "core"  # entra em uma categoria pelo rotulo
            raise EOFError

        monkeypatch.setattr("builtins.input", _input)
        assert main() == 0

    def test_dispatch_by_category_and_name(
        self, monkeypatch, no_clear, no_banner, fake_run
    ):
        inputs = iter(["9", "blindxss", "q"])
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
        inputs = iter(["9", "0", "3", "0", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        assert fake_run == []

    def test_pagination_next_prev(self, monkeypatch, no_clear, no_banner, fake_run):
        inputs = iter(["9", "n", "p", "2", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        assert fake_run == [("web", "attackanalysis")]

    def test_pagination_reaches_second_page(
        self, monkeypatch, no_clear, no_banner, fake_run
    ):
        inputs = iter(["9", "n", "1", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        assert fake_run == [("web", "clickjacking")]

    def test_invalid_choice_ignored(self, monkeypatch, no_clear, no_banner, fake_run):
        inputs = iter(["9", "zzz", "", "2", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        assert fake_run == [("web", "attackanalysis")]

    def test_out_of_range_number_from_root(
        self, monkeypatch, no_clear, no_banner, capsys, fake_run
    ):
        inputs = iter(["99", "", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        assert main() == 0
        out = capsys.readouterr().out
        assert "Categoria invalida." in out
        assert fake_run == []

    def test_exit_tool_returns_to_categories(
        self, monkeypatch, no_clear, no_banner, fake_run
    ):
        inputs = iter(["9", "1", "3", "q"])
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


class TestBanner:
    def test_prints_art(self, capsys):
        banner()
        out = capsys.readouterr().out
        assert "MyTools" in out or "by Default" in out
        assert "by Default" in out


class TestLoadToolsEdgeCases:
    def test_entry_points_raises_uses_pyproject(self, monkeypatch):
        from unittest.mock import patch

        main_mod._load_tools.cache_clear()
        with patch.object(
            main_mod.im, "entry_points", side_effect=RuntimeError("boom")
        ):
            tools = _load_tools()
        assert len(tools) > 50

    def test_entry_points_empty_uses_pyproject(self, monkeypatch):
        from unittest.mock import patch

        main_mod._load_tools.cache_clear()
        with patch.object(main_mod.im, "entry_points", return_value=[]):
            tools = _load_tools()
        assert len(tools) > 50

    def test_pyproject_read_error_returns_empty(self, monkeypatch):
        monkeypatch.setattr(
            main_mod.tomllib,
            "load",
            MagicMock(side_effect=main_mod.tomllib.TOMLDecodeError("bad", "", 0)),
        )
        assert _load_tools_from_pyproject() == []

    def test_find_pyproject_none(self, monkeypatch):
        class FakePath:
            def __init__(self, *args):
                pass

            def resolve(self):
                return self

            @property
            def parent(self):
                return FakePath()

            def __truediv__(self, other):
                return FakePath()

            def exists(self):
                return False

        monkeypatch.setattr(main_mod, "Path", FakePath)
        assert main_mod._find_pyproject() is None

    def test_find_pyproject_found(self, monkeypatch, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\n")

        class FakePath:
            def __init__(self, p=None):
                self._p = p or tmp_path

            def resolve(self):
                return self

            @property
            def parent(self):
                return FakePath(tmp_path)

            def __truediv__(self, other):
                return self._p / other

            def exists(self):
                return (self._p / "pyproject.toml").exists()

        monkeypatch.setattr(main_mod, "Path", FakePath)
        found = main_mod._find_pyproject()
        assert found == tmp_path / "pyproject.toml"


class TestLoadToolsFromPyprojectFallback:
    def test_fallback_used_when_no_tools(self, monkeypatch):
        from unittest.mock import patch

        main_mod._load_tools.cache_clear()
        with patch.object(main_mod.im, "entry_points", return_value=[]):
            tools = _load_tools()
        assert len(tools) > 50

    def test_short_module_path_skipped(self, monkeypatch):
        monkeypatch.setattr(
            main_mod.tomllib,
            "load",
            MagicMock(
                return_value={
                    "project": {
                        "scripts": {
                            "mytools-short": "a.b:main",
                            "mytools-ok": "mytools.web.xxedetect:main",
                            "notmytools": "x.y:main",
                            "mytools": "x:main",
                        }
                    }
                }
            ),
        )
        tools = _load_tools_from_pyproject()
        assert ("mytools-ok", "web", "xxedetect") in tools
        assert all(len(parts) >= 3 for _, _, parts in tools)

    def test_no_pyproject_returns_empty(self, monkeypatch):
        monkeypatch.setattr(
            main_mod,
            "_find_pyproject",
            lambda: None,
        )
        assert _load_tools_from_pyproject() == []


class TestToolsByCategory:
    def test_groups_ok(self, monkeypatch):
        tools = _load_tools()
        assert len(tools) > 0


class TestLoadToolsSkipsShortPaths:
    def test_entry_points_short_path_skipped(self):
        from unittest.mock import patch

        class FakeEP:
            def __init__(self, name, value):
                self.name = name
                self.value = value

        extra = [
            FakeEP("mytools-short", "a.b:main"),
            FakeEP("notmytools", "x.y:main"),
            FakeEP("mytools", "x:main"),
        ]
        main_mod._load_tools.cache_clear()
        with patch.object(
            main_mod.im,
            "entry_points",
            return_value=extra + list(_load_tools_as_eps()),
        ):
            tools = _load_tools()
        assert len(tools) > 50


class TestHelpScreenEdgeCases:
    def test_empty_categories_skipped(self, capsys):
        help_screen({})
        out = capsys.readouterr().out
        assert "Exemplos:" in out


class TestRunTool:
    def test_import_error(self, monkeypatch, capsys):
        from unittest.mock import patch

        monkeypatch.setattr("builtins.input", lambda *_: "")
        with patch.object(
            main_mod.importlib,
            "import_module",
            side_effect=ImportError("nope"),
        ):
            main_mod._run_tool("web", "nonexistent")
        out = capsys.readouterr().out
        assert "Erro ao carregar o modulo" in out

    def test_no_main_callable(self, monkeypatch, capsys):
        from unittest.mock import patch

        monkeypatch.setattr("builtins.input", lambda *_: "")
        with patch.object(
            main_mod.importlib,
            "import_module",
            return_value=types.SimpleNamespace(),
        ):
            main_mod._run_tool("web", "something")
        out = capsys.readouterr().out
        assert "nao possui main()" in out

    def test_system_exit_ignored(self, monkeypatch):
        from unittest.mock import patch

        def _main():
            raise SystemExit(0)

        with patch.object(
            main_mod.importlib,
            "import_module",
            return_value=types.SimpleNamespace(main=_main),
        ):
            main_mod._run_tool("web", "something")  # nao deve propagar

    def test_generic_exception(self, monkeypatch, capsys):
        from unittest.mock import patch

        monkeypatch.setattr("builtins.input", lambda *_: "")

        def _main():
            raise RuntimeError("fail")

        with patch.object(
            main_mod.importlib,
            "import_module",
            return_value=types.SimpleNamespace(main=_main),
        ):
            main_mod._run_tool("web", "something")
        out = capsys.readouterr().out
        assert "Erro: fail" in out

    def test_eof_error_in_module_main(self, monkeypatch, capsys):
        from unittest.mock import patch

        def _main():
            raise EOFError

        with patch.object(
            main_mod.importlib,
            "import_module",
            return_value=types.SimpleNamespace(main=_main),
        ):
            main_mod._run_tool("web", "something")  # nao deve propagar

        capsys.readouterr()  # print() vazio; sem excecao = sucesso


class TestMainEdgeCases:
    def test_no_tools_returns_1(self, monkeypatch, capsys):
        monkeypatch.setattr(main_mod, "_tools_by_category", lambda: {})
        assert main() == 1
        out = capsys.readouterr().out
        assert "Nenhuma ferramenta" in out

    def test_eof_at_root_returns_0(self, monkeypatch, no_clear, no_banner):
        def _input(*_):
            raise EOFError

        monkeypatch.setattr("builtins.input", _input)
        assert main() == 0

    def test_clear_at_root(self, monkeypatch, no_clear, no_banner, fake_run):
        inputs = iter(["clear", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        assert main() == 0

    def test_invalid_category_from_root(
        self, monkeypatch, no_clear, no_banner, capsys, fake_run
    ):
        inputs = iter(["nao-existe-xyz", "", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        assert main() == 0
        out = capsys.readouterr().out
        assert "Categoria invalida." in out

    def test_eof_at_category_returns_0(self, monkeypatch, no_clear, no_banner):
        def _input(*_):
            raise EOFError

        monkeypatch.setattr("builtins.input", _input)
        assert main() == 0

    def test_eof_in_category_input_returns_0(self, monkeypatch, no_clear, no_banner):
        calls = {"n": 0}

        def _input(*_):
            calls["n"] += 1
            if calls["n"] == 1:
                return "web"
            raise EOFError

        monkeypatch.setattr("builtins.input", _input)
        assert main() == 0

    def test_help_in_category(self, monkeypatch, no_clear, no_banner, capsys, fake_run):
        inputs = iter(["9", "h", "", "2", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        assert main() == 0
        assert ("web", "attackanalysis") in fake_run

    def test_clear_in_category(self, monkeypatch, no_clear, no_banner, fake_run):
        inputs = iter(["9", "clear", "1", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        assert main() == 0
        assert fake_run == [("web", "accountabuse")]

    def test_prev_page_in_category(
        self, monkeypatch, no_clear, no_banner, capsys, fake_run
    ):
        inputs = iter(["9", "p", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        assert main() == 0
        out = capsys.readouterr().out
        assert "Pagina 8/8" in out  # "p" na pagina 0 vai para a ultima
        assert fake_run == []

    def test_invalid_number_in_category(
        self, monkeypatch, no_clear, no_banner, capsys, fake_run
    ):
        inputs = iter(["9", "999", "", "1", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        assert main() == 0
        out = capsys.readouterr().out
        assert "Opcao invalida." in out
        assert fake_run == [("web", "accountabuse")]

    def test_guard_runs(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["mytools", "--version"])
        with pytest.raises(SystemExit):
            import runpy

            runpy.run_module("mytools.core.main", run_name="__main__")


class TestMainFixes:
    def test_load_tools_cached(self):
        assert _load_tools() is _load_tools()

    def test_load_tools_cache_clears(self):
        main_mod._load_tools.cache_clear()
        assert _load_tools() == _load_tools()
        main_mod._load_tools.cache_clear()

    def test_alias_at_root_runs_tool(self, monkeypatch, no_clear, no_banner, fake_run):
        inputs = iter(["dns", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        assert fake_run == [("dns", "dnstransfer")]

    def test_eof_on_pause_is_swallowed(self, monkeypatch, capsys):
        from unittest.mock import patch

        def _input(*_):
            raise EOFError

        monkeypatch.setattr("builtins.input", _input)
        with patch.object(
            main_mod.importlib,
            "import_module",
            side_effect=ImportError("nope"),
        ):
            main_mod._run_tool("web", "nonexistent")  # nao deve propagar EOFError
        out = capsys.readouterr().out
        assert "Erro ao carregar o modulo" in out

    def test_clear_after_tool_in_category(self, monkeypatch, no_banner, fake_run):
        cleared = []

        def _clear():
            cleared.append(1)

        monkeypatch.setattr(main_mod, "clear_console", _clear)
        inputs = iter(["9", "1", "q"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        main()
        assert fake_run == [("web", "accountabuse")]
        assert cleared  # clear_console chamado apos rodar a tool
