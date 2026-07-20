from unittest.mock import MagicMock, patch

from mytools.core.cred import (
    _SERVICE_NAME,
    delete_credential,
    get_credential,
    list_credentials,
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

        with caplog.at_level("ERROR", logger="mytools.cred"):
            with patch("sys.argv", ["mytools-cred", "get", "missing"]):
                result = main()
        assert result == 1
        assert any("nao encontrada" in record.message for record in caplog.records)
