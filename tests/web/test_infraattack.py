#!/usr/bin/env python3
"""Tests for infraattack.py."""

from __future__ import annotations

import argparse
import socket
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

import mytools.web.infraattack as infraattack_module
from mytools.web.infraattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    _CICD_PATHS_DEFAULT,
    InfraAttackAttempt,
    InfraAttackResult,
    _extract_secrets,
    _load_infra_paths,
    _make_attempt,
    _parse_url,
    _test_cicd_pipeline_leak,
    _test_cicd_secret_detection,
    _test_debug_endpoints,
    _test_debug_mode_detection,
    _test_elastic_exposed,
    _test_infrastructure,
    _test_redis_mongo_unauth,
    _test_terraform_state_leak,
    _test_vault_exposed,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)


class _FakeSocket:
    def __init__(self) -> None:
        self._sent: list[bytes] = []

    def settimeout(self, timeout: float) -> None:
        pass

    def connect_ex(self, address: object) -> int:
        return 1

    def send(self, data: bytes) -> int:
        return len(data)

    def recv(self, bufsize: int) -> bytes:
        return b""

    def close(self) -> None:
        pass


class _FakeSocketModule:
    AF_INET = socket.AF_INET
    SOCK_STREAM = socket.SOCK_STREAM

    @staticmethod
    def socket(*args: object, **kwargs: object) -> _FakeSocket:
        return _FakeSocket()


def _patch_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(infraattack_module, "socket", _FakeSocketModule)


class TestInfraAttackAttempt:
    def test_creation(self) -> None:
        a = InfraAttackAttempt(
            technique="terraform_state_leak",
            category="infrastructure",
            description="desc",
            vulnerable=False,
            details="test",
            error="",
            endpoint="https://target.com",
            service_type="terraform",
            response_code=200,
        )
        assert a.technique == "terraform_state_leak"
        assert a.service_type == "terraform"

    def test_frozen(self) -> None:
        a = InfraAttackAttempt(
            technique="t",
            category="c",
            description="d",
            vulnerable=False,
            details="",
            error="",
            endpoint="e",
            service_type="s",
            response_code=200,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestInfraAttackResult:
    def test_creation(self) -> None:
        r = InfraAttackResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            service_detected="unknown",
            techniques_count=8,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.techniques_count == 8

    def test_frozen(self) -> None:
        r = InfraAttackResult(
            target="t",
            host="h",
            port=443,
            tls=True,
            endpoint="e",
            service_detected="s",
            techniques_count=0,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.host = "changed"  # type: ignore[misc]


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        assert set(_CATEGORY_MAP.keys()) == {"infrastructure"}

    def test_infrastructure_techniques(self) -> None:
        expected = {
            "terraform_state_leak",
            "vault_exposed",
            "cicd_pipeline_leak",
            "cicd_secret_detection",
            "elastic_exposed",
            "redis_mongo_unauth",
            "debug_endpoints",
            "debug_mode_detection",
        }
        assert set(_CATEGORY_MAP["infrastructure"]) == expected

    def test_total_techniques(self) -> None:
        total = sum(len(v) for v in _CATEGORY_MAP.values())
        assert total == 8

    def test_dispatch_matches_map(self) -> None:
        for cat in _CATEGORY_MAP:
            assert cat in _CATEGORY_DISPATCH

    def test_all_dispatches_are_coroutines(self) -> None:
        import inspect

        for cat, fn in _CATEGORY_DISPATCH.items():
            assert inspect.iscoroutinefunction(fn), f"{cat} is not a coroutine"


class TestExtractSecrets:
    def test_finds_password(self) -> None:
        body = "password=secret123"
        found = _extract_secrets(body)
        assert len(found) > 0

    def test_finds_api_key(self) -> None:
        body = 'api_key="abc123def456"'
        found = _extract_secrets(body)
        assert len(found) > 0

    def test_no_secrets(self) -> None:
        body = "Hello world"
        found = _extract_secrets(body)
        assert found == []

    def test_filters_short_values(self) -> None:
        body = "password=x"
        found = _extract_secrets(body)
        assert found == []


class TestParseUrl:
    def test_https(self) -> None:
        host, _path, _port, tls = _parse_url("https://target.com/api")
        assert host == "target.com"
        assert tls is True

    def test_http(self) -> None:
        host, _path, _port, tls = _parse_url("http://target.com")
        assert host == "target.com"
        assert tls is False

    def test_custom_port(self) -> None:
        _, _, port, _ = _parse_url("https://target.com:8080")
        assert port == 8080


class TestMakeAttempt:
    def test_creation(self) -> None:
        a = _make_attempt(
            "terraform_state_leak",
            "infrastructure",
            "desc",
            True,
            "details",
            "",
            "url",
            "terraform",
            200,
        )
        assert a.vulnerable is True
        assert a.service_type == "terraform"

    def test_no_service(self) -> None:
        a = _make_attempt(
            "debug_endpoints",
            "infrastructure",
            "desc",
            False,
            "details",
            "",
            "url",
            "unknown",
            200,
        )
        assert a.service_type == "unknown"


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = InfraAttackResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            service_detected="unknown",
            techniques_count=8,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Infrastructure Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = InfraAttackAttempt(
            technique="terraform_state_leak",
            category="infrastructure",
            description="desc",
            vulnerable=True,
            details="state file found",
            error="",
            endpoint="https://target.com",
            service_type="terraform",
            response_code=200,
        )
        r = InfraAttackResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            service_detected="terraform",
            techniques_count=8,
            attempts=[a],
            vulnerable_techniques=["terraform_state_leak"],
            issues=["Test issue"],
            overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output
        assert "Issues:" in output

    def test_secure_category(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = _make_attempt(
            "debug_endpoints",
            "infrastructure",
            "desc",
            False,
            "details",
            "",
            "https://target.com",
            "debug",
            200,
        )
        r = InfraAttackResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            service_detected="unknown",
            techniques_count=1,
            attempts=[a],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "infrastructure: secure" in output


class TestCLI:
    def test_build_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com"])
        assert args.url == "https://target.com"

    def test_build_parser_with_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com", "-c", "infrastructure"])
        assert args.categories == ["infrastructure"]


@pytest.mark.asyncio
@pytest.mark.network
@respx.mock
@patch("socket.socket")
async def test_category_dispatch_all_return_lists(_mock_sock_cls: MagicMock) -> None:
    """All category dispatchers should return a list."""
    mock_sock_inst = _mock_sock_cls.return_value
    mock_sock_inst.connect_ex.return_value = 1
    respx.route().mock(return_value=httpx.Response(404, text="Not Found"))
    for cat, fn in _CATEGORY_DISPATCH.items():
        result = await fn("target.com", 443, "", 0.1, True, "https://target.com")
        assert isinstance(result, list), f"{cat} did not return a list"
        assert len(result) > 0, f"{cat} returned empty list"
        for attempt in result:
            assert isinstance(attempt, InfraAttackAttempt)
            assert attempt.category == cat


class TestParseUrlNoScheme:
    def test_defaults_to_https(self) -> None:
        host, path, port, tls = _parse_url("target.com")
        assert host == "target.com"
        assert path == ""
        assert port == 443
        assert tls is True


class TestLoadInfraPaths:
    def test_returns_default_when_not_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            infraattack_module,
            "_load_infra_payloads",
            lambda: {"cicd_paths": "not-a-list"},
        )
        result = _load_infra_paths("cicd_paths", _CICD_PATHS_DEFAULT)
        assert result == _CICD_PATHS_DEFAULT

    def test_converts_list_of_lists(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            infraattack_module,
            "_load_infra_payloads",
            lambda: {
                "cicd_paths": [
                    ["/a.yml", "A"],
                    {"path": "/b.yml", "desc": "B"},
                ]
            },
        )
        result = _load_infra_paths("cicd_paths", _CICD_PATHS_DEFAULT)
        assert result == [
            {"path": "/a.yml", "desc": "A"},
            {"path": "/b.yml", "desc": "B"},
        ]


class TestTerraformStateLeak:
    @pytest.mark.asyncio
    @respx.mock
    async def test_json_state_with_secrets(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            infraattack_module, "_TERRAFORM_STATE_PATHS", ["/terraform.tfstate"]
        )
        respx.get("https://target.com/terraform.tfstate").mock(
            return_value=httpx.Response(
                200,
                json={
                    "terraform_version": "1.5.0",
                    "serial": 1,
                    "resources": [{"type": "aws_instance", "name": "web"}],
                    "password": "hunter2",
                },
            )
        )
        async with httpx.AsyncClient() as client:
            result = await _test_terraform_state_leak("https://target.com", 5.0, client)
        assert result.vulnerable is True
        assert "Files: 1" in result.details
        assert "Secrets:" in result.details

    @pytest.mark.asyncio
    @respx.mock
    async def test_text_state_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            infraattack_module, "_TERRAFORM_STATE_PATHS", ["/terraform.tfstate"]
        )
        respx.get("https://target.com/terraform.tfstate").mock(
            return_value=httpx.Response(200, text="terraform state file content here")
        )
        async with httpx.AsyncClient() as client:
            result = await _test_terraform_state_leak("https://target.com", 5.0, client)
        assert result.vulnerable is True
        assert "Files: 1" in result.details

    @pytest.mark.asyncio
    @respx.mock
    async def test_json_state_without_keys(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            infraattack_module, "_TERRAFORM_STATE_PATHS", ["/terraform.tfstate"]
        )
        respx.get("https://target.com/terraform.tfstate").mock(
            return_value=httpx.Response(200, json={"foo": "bar"})
        )
        async with httpx.AsyncClient() as client:
            result = await _test_terraform_state_leak("https://target.com", 5.0, client)
        assert result.vulnerable is False
        assert "Files: 0" in result.details

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_json_without_terraform_text(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            infraattack_module, "_TERRAFORM_STATE_PATHS", ["/terraform.tfstate"]
        )
        respx.get("https://target.com/terraform.tfstate").mock(
            return_value=httpx.Response(200, text="just some plain content")
        )
        async with httpx.AsyncClient() as client:
            result = await _test_terraform_state_leak("https://target.com", 5.0, client)
        assert result.vulnerable is False
        assert "Files: 0" in result.details

    @pytest.mark.asyncio
    @respx.mock
    async def test_connection_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            infraattack_module, "_TERRAFORM_STATE_PATHS", ["/terraform.tfstate"]
        )
        respx.get("https://target.com/terraform.tfstate").mock(
            side_effect=httpx.ConnectError("boom")
        )
        async with httpx.AsyncClient() as client:
            result = await _test_terraform_state_leak("https://target.com", 5.0, client)
        assert result.vulnerable is False
        assert result.response_code == 0


class TestVaultExposed:
    @pytest.mark.asyncio
    @respx.mock
    async def test_vault_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            infraattack_module,
            "_VAULT_PATHS",
            [
                {"path": "/v1/sys/health", "desc": "Vault health"},
                {"path": "/v1/sys/auth", "desc": "Auth methods"},
                {"path": "/v1/sys/mounts", "desc": "Secret engines"},
            ],
        )
        respx.get("https://target.com/v1/sys/health").mock(
            return_value=httpx.Response(200, text="vault is sealed")
        )
        respx.get("https://target.com/v1/sys/auth").mock(
            return_value=httpx.Response(400, text="bad request")
        )
        respx.get("https://target.com/v1/sys/mounts").mock(
            side_effect=httpx.ConnectError("boom")
        )
        async with httpx.AsyncClient() as client:
            result = await _test_vault_exposed("https://target.com", 5.0, client)
        assert result.vulnerable is True
        assert "1 accessible" in result.details

    @pytest.mark.asyncio
    @respx.mock
    async def test_status_not_in_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            infraattack_module,
            "_VAULT_PATHS",
            [
                {"path": "/v1/sys/health", "desc": "Vault health"},
            ],
        )
        respx.get("https://target.com/v1/sys/health").mock(
            return_value=httpx.Response(500, text="internal error")
        )
        async with httpx.AsyncClient() as client:
            result = await _test_vault_exposed("https://target.com", 5.0, client)
        assert result.vulnerable is False
        assert "Vault: not found" in result.details


class TestCicdPipelineLeak:
    @pytest.mark.asyncio
    @respx.mock
    async def test_detects_pipeline_keywords(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            infraattack_module,
            "_CICD_PATHS",
            [
                {"path": "/.gitlab-ci.yml", "desc": "GitLab CI"},
                {"path": "/Jenkinsfile", "desc": "Jenkins"},
                {"path": "/.travis.yml", "desc": "Travis CI"},
            ],
        )
        respx.get("https://target.com/.gitlab-ci.yml").mock(
            return_value=httpx.Response(
                200,
                text="stages:\n  - build\nscript:\n  - echo hi",
            )
        )
        respx.get("https://target.com/Jenkinsfile").mock(
            return_value=httpx.Response(
                200, text="some plain text without any pipeline keywords"
            )
        )
        respx.get("https://target.com/.travis.yml").mock(
            side_effect=httpx.ConnectError("boom")
        )
        async with httpx.AsyncClient() as client:
            result = await _test_cicd_pipeline_leak("https://target.com", 5.0, client)
        assert result.vulnerable is True
        assert "GitLab CI" in result.details

    @pytest.mark.asyncio
    @respx.mock
    async def test_no_keywords_no_pipeline(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            infraattack_module,
            "_CICD_PATHS",
            [
                {"path": "/Jenkinsfile", "desc": "Jenkins"},
            ],
        )
        respx.get("https://target.com/Jenkinsfile").mock(
            return_value=httpx.Response(200, text="hello world, nothing here")
        )
        async with httpx.AsyncClient() as client:
            result = await _test_cicd_pipeline_leak("https://target.com", 5.0, client)
        assert result.vulnerable is False
        assert "No exposed pipelines" in result.details


class TestCicdSecretDetection:
    @pytest.mark.asyncio
    @respx.mock
    async def test_detects_secrets(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            infraattack_module,
            "_CICD_PATHS",
            [
                {"path": "/.gitlab-ci.yml", "desc": "GitLab CI"},
                {"path": "/Jenkinsfile", "desc": "Jenkins"},
            ],
        )
        respx.get("https://target.com/.gitlab-ci.yml").mock(
            return_value=httpx.Response(200, text="password=supersecret1")
        )
        respx.get("https://target.com/Jenkinsfile").mock(
            side_effect=httpx.ConnectError("boom")
        )
        async with httpx.AsyncClient() as client:
            result = await _test_cicd_secret_detection(
                "https://target.com", 5.0, client
            )
        assert result.vulnerable is True
        assert "Secrets: 1 found" in result.details

    @pytest.mark.asyncio
    @respx.mock
    async def test_no_secrets_in_pipeline(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            infraattack_module,
            "_CICD_PATHS",
            [
                {"path": "/Jenkinsfile", "desc": "Jenkins"},
            ],
        )
        respx.get("https://target.com/Jenkinsfile").mock(
            return_value=httpx.Response(200, text="hello world, nothing here")
        )
        async with httpx.AsyncClient() as client:
            result = await _test_cicd_secret_detection(
                "https://target.com", 5.0, client
            )
        assert result.vulnerable is False
        assert "No secrets in pipelines" in result.details


class TestElasticExposed:
    @pytest.mark.asyncio
    @respx.mock
    async def test_detects_elastic_and_kibana(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            infraattack_module,
            "_ELASTIC_PATHS",
            [
                {"path": "/_cluster/health", "desc": "Cluster health"},
                {"path": "/_cat/indices", "desc": "Index listing"},
            ],
        )
        monkeypatch.setattr(
            infraattack_module,
            "_KIBANA_PATHS",
            [
                {"path": "/status", "desc": "Kibana status"},
                {"path": "/api/status", "desc": "Kibana API status"},
            ],
        )
        respx.get("https://target.com/_cluster/health").mock(
            return_value=httpx.Response(200, text="green")
        )
        respx.get("https://target.com/_cat/indices").mock(
            side_effect=httpx.ConnectError("boom")
        )
        respx.get("https://target.com/status").mock(
            return_value=httpx.Response(200, text="Kibana")
        )
        respx.get("https://target.com/api/status").mock(
            side_effect=httpx.ConnectError("boom")
        )
        async with httpx.AsyncClient() as client:
            result = await _test_elastic_exposed("https://target.com", 5.0, client)
        assert result.vulnerable is True
        assert "2 accessible" in result.details
        assert "Kibana: Kibana status" in result.details


class TestRedisMongoUnauth:
    @pytest.mark.asyncio
    @patch("socket.socket")
    async def test_services_detected(self, mock_sock_cls: MagicMock) -> None:
        inst = mock_sock_cls.return_value
        inst.connect_ex.return_value = 0
        inst.recv.side_effect = [
            b"redis_version:6.0.16\r\n",
            b'{"ismaster":1,"ok":1}\r\n',
        ]
        async with httpx.AsyncClient() as client:
            result = await _test_redis_mongo_unauth("https://target.com", 2.0, client)
        assert result.vulnerable is True
        assert "Redis:6379" in result.details
        assert "MongoDB:27017" in result.details

    @pytest.mark.asyncio
    @patch("socket.socket")
    async def test_recv_raises(self, mock_sock_cls: MagicMock) -> None:
        inst = mock_sock_cls.return_value
        inst.connect_ex.return_value = 0
        inst.recv.side_effect = OSError("reset")
        async with httpx.AsyncClient() as client:
            result = await _test_redis_mongo_unauth("https://target.com", 2.0, client)
        assert result.vulnerable is False

    @pytest.mark.asyncio
    @patch("socket.socket")
    async def test_connect_ex_raises(self, mock_sock_cls: MagicMock) -> None:
        inst = mock_sock_cls.return_value
        inst.connect_ex.side_effect = OSError("boom")
        async with httpx.AsyncClient() as client:
            result = await _test_redis_mongo_unauth("https://target.com", 2.0, client)
        assert result.vulnerable is False
        assert result.response_code == 0

    @pytest.mark.asyncio
    @patch("socket.socket")
    async def test_response_without_markers(self, mock_sock_cls: MagicMock) -> None:
        inst = mock_sock_cls.return_value
        inst.connect_ex.return_value = 0
        inst.recv.side_effect = [
            b"ERR unknown command\r\n",
            b"ERR unknown command\r\n",
        ]
        async with httpx.AsyncClient() as client:
            result = await _test_redis_mongo_unauth("https://target.com", 2.0, client)
        assert result.vulnerable is False
        assert "No unauth Redis/MongoDB found" in result.details


class TestDebugEndpoints:
    @pytest.mark.asyncio
    @respx.mock
    async def test_detects_debug_endpoint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            infraattack_module,
            "_DEBUG_PATHS",
            [
                {"path": "/actuator", "desc": "Actuator"},
                {"path": "/console", "desc": "Console"},
                {"path": "/debug/", "desc": "Debug root"},
            ],
        )
        respx.get("https://target.com/actuator").mock(
            return_value=httpx.Response(200, text="actuator" + "x" * 60)
        )
        respx.get("https://target.com/console").mock(
            return_value=httpx.Response(200, text="hello" + "x" * 60)
        )
        respx.get("https://target.com/debug/").mock(
            side_effect=httpx.ConnectError("boom")
        )
        async with httpx.AsyncClient() as client:
            result = await _test_debug_endpoints("https://target.com", 5.0, client)
        assert result.vulnerable is True
        assert "Actuator" in result.details


class TestDebugModeDetection:
    @pytest.mark.asyncio
    @respx.mock
    async def test_debug_path_signature_detected(self) -> None:
        respx.get(url__regex=r"^https://target\.com/?$").mock(
            side_effect=httpx.ConnectError("boom")
        )
        respx.get("https://target.com/actuator").mock(
            side_effect=httpx.ConnectError("boom")
        )
        respx.get(url__regex=r"^https://target\.com/.*").mock(
            return_value=httpx.Response(200, text="settings DEBUG = True")
        )
        async with httpx.AsyncClient() as client:
            result = await _test_debug_mode_detection("https://target.com", 5.0, client)
        assert result.vulnerable is True
        assert "Django DEBUG=True" in result.details


class TestInfrastructureErrorHandling:
    @pytest.mark.asyncio
    @respx.mock
    @patch("socket.socket")
    async def test_tester_exception_captured(
        self, mock_sock_cls: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_sock_cls.return_value.connect_ex.return_value = 1

        async def boom(_url: str, _timeout: float, _client: httpx.AsyncClient) -> list:
            raise RuntimeError("kaboom")

        monkeypatch.setattr(infraattack_module, "_test_terraform_state_leak", boom)
        respx.route().mock(return_value=httpx.Response(404, text="Not Found"))
        results = await _test_infrastructure(
            "target.com", 443, "", 0.1, True, "https://target.com"
        )
        error_attempt = next(
            a for a in results if a.technique == "terraform_state_leak"
        )
        assert error_attempt.error == "kaboom"
        assert error_attempt.vulnerable is False


class TestRunScan:
    @pytest.mark.asyncio
    @respx.mock
    @patch("socket.socket")
    async def test_vulnerable_with_output(
        self, mock_sock_cls: MagicMock, tmp_path
    ) -> None:
        mock_sock_cls.return_value.connect_ex.return_value = 1
        respx.get(url__regex=r".*terraform\.tfstate").mock(
            return_value=httpx.Response(
                200, json={"resources": [], "terraform_version": "1.5.0"}
            )
        )
        respx.route().mock(return_value=httpx.Response(404, text="Not Found"))
        out = str(tmp_path / "out.json")
        result = await run_scan("target.com:8080/path", ["infrastructure"], 0.1, out)
        assert result.overall_status == "vulnerable"
        assert result.port == 8080
        assert result.tls is True
        assert result.endpoint == "https://target.com:8080/path"
        assert result.service_detected != "unknown"
        assert result.techniques_count == 8
        assert (tmp_path / "out.json").exists()

    @pytest.mark.asyncio
    @respx.mock
    @patch("socket.socket")
    async def test_http_default_port_secure(self, mock_sock_cls: MagicMock) -> None:
        mock_sock_cls.return_value.connect_ex.return_value = 1
        respx.route().mock(return_value=httpx.Response(404, text="Not Found"))
        result = await run_scan("http://target.com", None, 0.1, None)
        assert result.overall_status == "secure"
        assert result.port == 80
        assert result.tls is False
        assert result.endpoint == "http://target.com"
        assert result.techniques_count == 8
        assert result.issues == []

    @pytest.mark.asyncio
    async def test_unknown_category_and_dispatch_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def boom(*_args: object, **_kwargs: object) -> list:
            raise RuntimeError("scan failed")

        monkeypatch.setattr(
            infraattack_module,
            "_CATEGORY_DISPATCH",
            {"infrastructure": boom},
        )
        result = await run_scan(
            "https://target.com", ["bogus", "infrastructure"], 0.1, None
        )
        assert result.overall_status == "secure"
        assert result.techniques_count == 1
        assert result.issues == ["Errors: infrastructure_error"]

    @pytest.mark.asyncio
    async def test_tester_returns_empty_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def empty(*_args: object, **_kwargs: object) -> list:
            return []

        monkeypatch.setattr(
            infraattack_module,
            "_CATEGORY_DISPATCH",
            {"infrastructure": empty},
        )
        result = await run_scan("https://target.com", ["infrastructure"], 0.1, None)
        assert result.overall_status == "secure"
        assert result.techniques_count == 0
        assert result.service_detected == "unknown"


class TestRunOnce:
    @respx.mock
    def test_vulnerable_returns_1(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_socket(monkeypatch)
        respx.get(url__regex=r".*terraform\.tfstate").mock(
            return_value=httpx.Response(
                200, json={"resources": [], "terraform_version": "1.5.0"}
            )
        )
        respx.route().mock(return_value=httpx.Response(404, text="Not Found"))
        args = argparse.Namespace(
            url="https://target.com",
            categories=["infrastructure"],
            timeout=0.1,
            output=str(tmp_path / "out.json"),
        )
        assert run_once(args) == 1

    @respx.mock
    def test_secure_returns_0(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_socket(monkeypatch)
        respx.route().mock(return_value=httpx.Response(404, text="Not Found"))
        args = argparse.Namespace(
            url="https://target.com",
            categories=None,
            timeout=0.1,
            output=None,
        )
        assert run_once(args) == 0


class TestMain:
    @patch("mytools.web.infraattack.run_main_loop", return_value=0)
    def test_main(self, mock_run_main_loop: MagicMock) -> None:
        assert main() == 0
        mock_run_main_loop.assert_called_once()

    def test_main_guard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import runpy

        def _raise() -> int:
            raise SystemExit(0)

        monkeypatch.setattr(infraattack_module, "main", _raise)
        with pytest.raises(SystemExit):
            runpy.run_module("mytools.web.infraattack", run_name="__main__")
