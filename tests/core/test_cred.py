import builtins
from argparse import Namespace
from unittest.mock import MagicMock, patch

import pytest

from mytools.core.cred import (
    _SERVICE_NAME,
    _get_keyring,
    _list_credentials,
    _update_registry,
    delete_credential,
    get_credential,
    list_credentials,
    run_once,
    set_credential,
)


class TestGetCredential:
    """Testes para get_credential()."""

    @patch("mytools.core.cred._get_keyring")
    def test_existing_credential(self, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = "secret_value"
        mock_kr.return_value = kr
        assert get_credential("my_token") == "secret_value"
        kr.get_password.assert_called_once_with(_SERVICE_NAME, "my_token")

    @patch("mytools.core.cred._get_keyring")
    def test_missing_credential(self, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = None
        mock_kr.return_value = kr
        assert get_credential("nonexistent") is None

    @patch("mytools.core.cred._get_keyring")
    def test_keyring_unavailable(self, mock_kr):
        mock_kr.return_value = None
        assert get_credential("my_token") is None


class TestSetCredential:
    """Testes para set_credential()."""

    @patch("mytools.core.cred._get_keyring")
    @patch("mytools.core.cred._update_registry")
    def test_set_with_value(self, mock_reg, mock_kr):
        kr = MagicMock()
        mock_kr.return_value = kr
        assert set_credential("my_token", "abc123") is True
        kr.set_password.assert_called_once_with(_SERVICE_NAME, "my_token", "abc123")
        mock_reg.assert_called_once_with("my_token", add=True)

    @patch("mytools.core.cred._get_keyring")
    def test_set_empty_value(self, mock_kr):
        mock_kr.return_value = MagicMock()
        assert set_credential("my_token", "") is False

    @patch("mytools.core.cred._get_keyring")
    def test_keyring_unavailable(self, mock_kr):
        mock_kr.return_value = None
        assert set_credential("my_token", "abc") is False


class TestDeleteCredential:
    """Testes para delete_credential()."""

    @patch("mytools.core.cred._get_keyring")
    @patch("mytools.core.cred._update_registry")
    def test_delete_existing(self, mock_reg, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = "old_value"
        mock_kr.return_value = kr
        assert delete_credential("my_token") is True
        kr.delete_password.assert_called_once_with(_SERVICE_NAME, "my_token")
        mock_reg.assert_called_once_with("my_token", add=False)

    @patch("mytools.core.cred._get_keyring")
    def test_delete_nonexistent(self, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = None
        mock_kr.return_value = kr
        assert delete_credential("nonexistent") is False

    @patch("mytools.core.cred._get_keyring")
    def test_keyring_unavailable(self, mock_kr):
        mock_kr.return_value = None
        assert delete_credential("my_token") is False


class TestListCredentials:
    """Testes para list_credentials()."""

    @patch("mytools.core.cred._list_credentials")
    def test_list_with_creds(self, mock_list):
        mock_list.return_value = ["bearer_token", "nvd_key"]
        result = list_credentials()
        assert result == ["bearer_token", "nvd_key"]

    @patch("mytools.core.cred._list_credentials")
    def test_list_empty(self, mock_list):
        mock_list.return_value = []
        result = list_credentials()
        assert result == []


class TestRegistry:
    """Testes para _update_registry()."""

    @patch("mytools.core.cred._get_keyring")
    def test_add_to_registry(self, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = None
        mock_kr.return_value = kr
        from mytools.core.cred import _update_registry

        _update_registry("new_cred", add=True)
        kr.set_password.assert_called_once_with(
            _SERVICE_NAME, "__registry__", "new_cred"
        )

    @patch("mytools.core.cred._get_keyring")
    def test_add_to_existing_registry(self, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = "token_a"
        mock_kr.return_value = kr
        from mytools.core.cred import _update_registry

        _update_registry("token_b", add=True)
        kr.set_password.assert_called_once_with(
            _SERVICE_NAME, "__registry__", "token_a\ntoken_b"
        )

    @patch("mytools.core.cred._get_keyring")
    def test_remove_from_registry(self, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = "token_a\ntoken_b"
        mock_kr.return_value = kr
        from mytools.core.cred import _update_registry

        _update_registry("token_a", add=False)
        kr.set_password.assert_called_once_with(
            _SERVICE_NAME, "__registry__", "token_b"
        )


class TestGetMaskedOutput:
    """Testes para mascaramento de output no comando get."""

    @patch("mytools.core.cred.get_credential")
    def test_long_value_masked(self, mock_get, capsys):
        mock_get.return_value = "secret_token_1234"
        from mytools.core.cred import main

        with patch("sys.argv", ["mytools-cred", "get", "my_token"]):
            result = main()
        assert result == 0
        captured = capsys.readouterr()
        assert captured.out.strip() == "*************1234"

    @patch("mytools.core.cred.get_credential")
    def test_short_value_fully_masked(self, mock_get, capsys):
        mock_get.return_value = "abc"
        from mytools.core.cred import main

        with patch("sys.argv", ["mytools-cred", "get", "my_token"]):
            result = main()
        assert result == 0
        captured = capsys.readouterr()
        assert captured.out.strip() == "****"

    @patch("mytools.core.cred.get_credential")
    def test_exact_four_chars_masked(self, mock_get, capsys):
        mock_get.return_value = "1234"
        from mytools.core.cred import main

        with patch("sys.argv", ["mytools-cred", "get", "my_token"]):
            result = main()
        assert result == 0
        captured = capsys.readouterr()
        assert captured.out.strip() == "****"

    @patch("mytools.core.cred.get_credential")
    def test_missing_cred_no_mask(self, mock_get, caplog):
        mock_get.return_value = None
        from mytools.core.cred import main

        with (
            caplog.at_level("ERROR", logger="mytools.cred"),
            patch("sys.argv", ["mytools-cred", "get", "missing"]),
        ):
            result = main()
        assert result == 1
        assert any("nao encontrada" in record.message for record in caplog.records)


class TestGetKeyringImportError:
    @patch("mytools.core.cred._get_keyring")
    def test_get_keyring_import_error(self, mock_kr, monkeypatch):
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "keyring":
                raise ImportError("no keyring")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        assert _get_keyring() is None
        assert _get_keyring() is None  # idempotent

    def test_get_keyring_returns_module(self):
        """Caminho de sucesso: keyring importa como modulo (ou None se ausente)."""
        kr = _get_keyring()
        assert kr is None or hasattr(kr, "get_password")


class TestListCredentialsEdgeCases:
    @patch("mytools.core.cred._get_keyring")
    def test_list_kr_none(self, mock_kr):
        mock_kr.return_value = None
        assert _list_credentials() == []

    @patch("mytools.core.cred._get_keyring")
    def test_list_empty_registry(self, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = None
        mock_kr.return_value = kr
        assert _list_credentials() == []

    @patch("mytools.core.cred._get_keyring")
    def test_list_sorted(self, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = "zeta\nalpha"
        mock_kr.return_value = kr
        assert _list_credentials() == ["alpha", "zeta"]


class TestUpdateRegistryEdgeCases:
    @patch("mytools.core.cred._get_keyring")
    def test_update_registry_kr_none(self, mock_kr):
        mock_kr.return_value = None
        _update_registry("x", add=True)

    @patch("mytools.core.cred._get_keyring")
    def test_update_registry_add_to_empty(self, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = None
        mock_kr.return_value = kr
        _update_registry("x", add=True)
        kr.set_password.assert_called_once_with(_SERVICE_NAME, "__registry__", "x")

    @patch("mytools.core.cred._get_keyring")
    def test_update_registry_discard(self, mock_kr):
        kr = MagicMock()
        kr.get_password.return_value = "x\ny"
        mock_kr.return_value = kr
        _update_registry("x", add=False)
        kr.set_password.assert_called_once_with(_SERVICE_NAME, "__registry__", "y")


class TestSetCredentialInteractive:
    @patch("mytools.core.cred._update_registry")
    @patch("mytools.core.cred.getpass.getpass")
    @patch("mytools.core.cred._get_keyring")
    def test_set_with_getpass(self, mock_kr, mock_getpass, mock_reg):
        kr = MagicMock()
        mock_kr.return_value = kr
        mock_getpass.return_value = "interactive_value"
        assert set_credential("token") is True
        kr.set_password.assert_called_once_with(
            _SERVICE_NAME, "token", "interactive_value"
        )
        mock_reg.assert_called_once_with("token", add=True)

    @patch("mytools.core.cred.getpass.getpass")
    @patch("mytools.core.cred._get_keyring")
    def test_set_getpass_empty(self, mock_kr, mock_getpass):
        mock_kr.return_value = MagicMock()
        mock_getpass.return_value = ""
        assert set_credential("token") is False


class TestRunOnceCommands:
    def test_run_once_unknown_command(self, capsys):
        result = run_once(Namespace(command="bogus", name="x"))
        assert result == 1
        assert "usage" in capsys.readouterr().out.lower()

    @patch("mytools.core.cred.set_credential")
    def test_run_once_set(self, mock_set):
        mock_set.return_value = True
        assert run_once(Namespace(command="set", name="token")) == 0

    @patch("mytools.core.cred.set_credential")
    def test_run_once_set_fail(self, mock_set):
        mock_set.return_value = False
        assert run_once(Namespace(command="set", name="token")) == 1

    @patch("mytools.core.cred.delete_credential")
    def test_run_once_delete(self, mock_del):
        mock_del.return_value = True
        assert run_once(Namespace(command="delete", name="token")) == 0

    @patch("mytools.core.cred.delete_credential")
    def test_run_once_delete_fail(self, mock_del):
        mock_del.return_value = False
        assert run_once(Namespace(command="delete", name="token")) == 1

    @patch("mytools.core.cred.list_credentials")
    def test_run_once_list(self, mock_list):
        assert run_once(Namespace(command="list")) == 0
        mock_list.assert_called_once()

    @patch("mytools.core.cred.get_credential")
    def test_run_once_get_missing(self, mock_get, caplog):
        mock_get.return_value = None
        with caplog.at_level("ERROR", logger="mytools.cred"):
            assert run_once(Namespace(command="get", name="missing")) == 1
        assert any("nao encontrada" in r.message for r in caplog.records)


class TestMainShell:
    def test_main_no_args_enters_shell(self):
        with (
            patch("sys.argv", ["mytools-cred"]),
            patch(
                "mytools.core.cred.run_interactive_shell",
                return_value=0,
            ) as mock_shell,
        ):
            from mytools.core.cred import main

            assert main() == 0
        mock_shell.assert_called_once()
        assert mock_shell.call_args.kwargs["prompt"] == "cred> "

    @patch("mytools.core.cred.set_credential")
    def test_main_set_command(self, mock_set):
        mock_set.return_value = True
        with patch("sys.argv", ["mytools-cred", "set", "token"]):
            from mytools.core.cred import main

            assert main() == 0


class TestMainGuard:
    def test_main_guard_runs(self, monkeypatch):
        import runpy

        import mytools.core.cred as cred_mod

        monkeypatch.setattr(
            cred_mod, "main", lambda: (_ for _ in ()).throw(SystemExit(0))
        )
        with patch("sys.argv", ["mytools-cred", "list"]), pytest.raises(SystemExit):
            runpy.run_module("mytools.core.cred", run_name="__main__")
