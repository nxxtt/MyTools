import argparse
import asyncio
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from mytools.config.configfiledetect import (
    ALL_CATEGORIES,
    ALL_PATHS,
    CONFIG_PATHS,
    CREDENTIALS_PATHS,
    DATABASE_PATHS,
    DOCKER_PATHS,
    ENV_PATHS,
    FRAMEWORK_PATHS,
    ConfigLeak,
    _async_run_once,
    _classify_path,
    _is_sensitive,
    _load_paths_from_args,
    _validate_content,
    build_parser,
    main,
    print_results,
    run_once,
    scan_configs,
)


class TestConfigLeak:
    def test_frozen(self):
        leak = ConfigLeak(category="env", url="http://x.com/.env", path=".env")
        with pytest.raises(AttributeError):
            leak.category = "config"  # type: ignore[reportAttributeAccessIssue]

    def test_defaults(self):
        leak = ConfigLeak(category="env", url="http://x.com/.env", path=".env")
        assert leak.status == 0
        assert leak.detail == ""
        assert leak.raw_size == 0

    def test_all_fields(self):
        leak = ConfigLeak(
            category="env",
            url="http://x.com/.env",
            path=".env",
            status=200,
            detail="DB_HOST=localhost",
            raw_size=50,
        )
        assert leak.category == "env"
        assert leak.detail == "DB_HOST=localhost"
        assert leak.raw_size == 50


class TestClassifyPath:
    def test_env(self):
        assert _classify_path(".env") == "env"
        assert _classify_path(".env.local") == "env"
        assert _classify_path(".env.production") == "env"

    def test_config(self):
        assert _classify_path("config.json") == "config"
        assert _classify_path("settings.py") == "config"
        assert _classify_path("config.yaml") == "config"

    def test_framework(self):
        assert _classify_path("wp-config.php") == "framework"
        assert _classify_path("web.config") == "framework"
        assert _classify_path(".htaccess") == "framework"

    def test_database(self):
        assert _classify_path("database.yml") == "database"
        assert _classify_path("my.cnf") == "database"
        assert _classify_path("redis.conf") == "database"

    def test_docker(self):
        assert _classify_path("docker-compose.yml") == "docker"
        assert _classify_path("Dockerfile") == "docker"
        assert _classify_path("k8s/deployment.yaml") == "docker"

    def test_credentials(self):
        assert _classify_path("credentials.json") == "credentials"
        assert _classify_path("id_rsa") == "credentials"
        assert _classify_path(".htpasswd") == "credentials"

    def test_unknown_falls_back(self):
        assert _classify_path("robots.txt") == "config"


class TestIsSensitive:
    def test_env_file(self):
        assert _is_sensitive(".env") is True
        assert _is_sensitive(".env.bak") is True

    def test_credentials(self):
        assert _is_sensitive("credentials.json") is True
        assert _is_sensitive("id_rsa") is True
        assert _is_sensitive(".htpasswd") is True

    def test_wp_config(self):
        assert _is_sensitive("wp-config.php") is True

    def test_full_path_credentials(self):
        assert _is_sensitive("aws/credentials") is True
        assert _is_sensitive(".aws/credentials") is True

    def test_full_path_config_yaml(self):
        assert _is_sensitive("config/database.yml") is True
        assert _is_sensitive("config/secrets.yml") is True

    def test_not_sensitive(self):
        assert _is_sensitive("config.json") is False
        assert _is_sensitive("robots.txt") is False
        assert _is_sensitive("index.html") is False

    def test_save_and_tilde_sensitive(self):
        assert _is_sensitive("config.php.save") is True
        assert _is_sensitive("index.php~") is True

    def test_backup_extension_sensitive(self):
        assert _is_sensitive("config.php.bak") is True


class TestValidateContent:
    def test_env_valid(self):
        content = b"DB_HOST=localhost\nDB_PORT=3306\n"
        ok, detail = _validate_content(".env", content)
        assert ok is True
        assert "DB_HOST" in detail

    def test_env_with_comments(self):
        content = b"# Database config\nDB_HOST=localhost\n# PORT\nDB_PORT=3306\n"
        ok, _detail = _validate_content(".env", content)
        assert ok is True

    def test_env_empty(self):
        ok, _ = _validate_content(".env", b"")
        assert ok is False

    def test_env_no_assignment(self):
        ok, _ = _validate_content(".env", b"just some text\nno equals here")
        assert ok is False

    def test_config_json_valid(self):
        data = {"host": "localhost", "port": 3306}
        content = json.dumps(data).encode()
        ok, detail = _validate_content("config.json", content)
        assert ok is True
        assert "2 keys" in detail

    def test_config_json_empty_obj(self):
        ok, detail = _validate_content("config.json", b"{}")
        assert ok is True
        assert "JSON config" in detail

    def test_config_json_invalid(self):
        ok, _ = _validate_content("config.json", b"not json")
        assert ok is False

    def test_config_yaml_like(self):
        content = b"host: localhost\nport: 3306\ndatabase: mydb\n"
        ok, _detail = _validate_content("config.yaml", content)
        assert ok is True

    def test_framework_wp_config(self):
        content = (
            b"<?php\ndefine('DB_NAME', 'wordpress');\ndefine('DB_USER', 'root');\n"
        )
        ok, detail = _validate_content("wp-config.php", content)
        assert ok is True
        assert "DB_NAME" in detail

    def test_framework_web_config(self):
        content = b"<configuration>\n<system.web>\n<compilation debug='true' />\n</system.web>\n</configuration>"
        ok, _detail = _validate_content("web.config", content)
        assert ok is True

    def test_database_mysql(self):
        content = b"[mysqld]\nbind-address = 0.0.0.0\nport = 3306\n"
        ok, detail = _validate_content("my.cnf", content)
        assert ok is True
        assert "mysqld" in detail

    def test_database_postgres(self):
        content = b"host = 0.0.0.0\nport = 5432\ndbname = mydb\n"
        ok, _detail = _validate_content("postgresql.conf", content)
        assert ok is True

    def test_docker_compose(self):
        content = b"version: '3'\nservices:\n  web:\n    image: nginx\n"
        ok, detail = _validate_content("docker-compose.yml", content)
        assert ok is True
        assert "services" in detail

    def test_dockerfile(self):
        content = b"FROM python:3.12\nCOPY . /app\n"
        ok, _detail = _validate_content("Dockerfile", content)
        assert ok is True

    def test_credentials_json(self):
        data = {
            "private_key": "-----BEGIN RSA PRIVATE KEY-----",
            "client_email": "x@y.iam.gserviceaccount.com",
        }
        content = json.dumps(data).encode()
        ok, detail = _validate_content("credentials.json", content)
        assert ok is True
        assert "private_key" in detail

    def test_htpasswd(self):
        content = b"admin:$apr1$xyz$hash\nuser:$apr1$abc$hash\n"
        ok, detail = _validate_content(".htpasswd", content)
        assert ok is True
        assert "$apr1$" in detail

    def test_unknown_path_fallback(self):
        content = b"some content here"
        ok, _ = _validate_content("robots.txt", content)
        assert ok is False

    def test_empty_content(self):
        ok, _ = _validate_content("config.json", b"")
        assert ok is False

    def test_empty_text(self):
        ok, _ = _validate_content(".env", b"   \n  \n  ")
        assert ok is False

    def test_config_json_list(self):
        ok, _ = _validate_content("config.json", b'["a", "b"]')
        assert ok is False

    def test_framework_no_match(self):
        ok, _ = _validate_content("web.config", b"hello world")
        assert ok is False

    def test_database_no_match(self):
        ok, _ = _validate_content("my.cnf", b"nothing here")
        assert ok is False

    def test_docker_no_match(self):
        ok, _ = _validate_content("Dockerfile", b"random stuff")
        assert ok is False

    def test_credentials_no_match(self):
        ok, _ = _validate_content("credentials.json", b"hello world")
        assert ok is False


class TestPathConstants:
    def test_all_paths_are_strings(self):
        assert all(isinstance(p, str) for p in ALL_PATHS)

    def test_env_paths_have_dotenv(self):
        assert any(p.startswith(".env") for p in ENV_PATHS)

    def test_config_paths_have_common(self):
        assert "config.json" in CONFIG_PATHS
        assert "settings.py" in CONFIG_PATHS

    def test_framework_paths_have_wp(self):
        assert "wp-config.php" in FRAMEWORK_PATHS

    def test_database_paths_have_mycnf(self):
        assert "my.cnf" in DATABASE_PATHS

    def test_docker_paths_have_compose(self):
        assert "docker-compose.yml" in DOCKER_PATHS

    def test_credentials_paths_have_id_rsa(self):
        assert "id_rsa" in CREDENTIALS_PATHS

    def test_minimum_count(self):
        assert len(ALL_PATHS) >= 40

    def test_all_categories_populated(self):
        for cat, paths in ALL_CATEGORIES.items():
            assert len(paths) >= 3, f"Categoria {cat} tem menos de 3 paths"

    def test_no_duplicates_in_all_paths(self):
        assert len(ALL_PATHS) == len(set(ALL_PATHS))


class TestLoadPaths:
    def test_default_returns_none(self):
        args = argparse.Namespace(category="all")
        result = _load_paths_from_args(args)
        assert result is None

    def test_env_category(self):
        args = argparse.Namespace(category="env")
        result = _load_paths_from_args(args)
        assert result == ENV_PATHS

    def test_config_category(self):
        args = argparse.Namespace(category="config")
        result = _load_paths_from_args(args)
        assert result == CONFIG_PATHS

    def test_framework_category(self):
        args = argparse.Namespace(category="framework")
        result = _load_paths_from_args(args)
        assert result == FRAMEWORK_PATHS

    def test_database_category(self):
        args = argparse.Namespace(category="database")
        result = _load_paths_from_args(args)
        assert result == DATABASE_PATHS

    def test_docker_category(self):
        args = argparse.Namespace(category="docker")
        result = _load_paths_from_args(args)
        assert result == DOCKER_PATHS

    def test_credentials_category(self):
        args = argparse.Namespace(category="credentials")
        result = _load_paths_from_args(args)
        assert result == CREDENTIALS_PATHS


@pytest.mark.smoke
class TestBuildParser:
    def test_has_url(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.url == "http://example.com"

    def test_has_list(self):
        parser = build_parser()
        args = parser.parse_args(["-l", "urls.txt"])
        assert args.target_list == "urls.txt"

    def test_has_concurrency(self):
        parser = build_parser()
        args = parser.parse_args(["--concurrency", "50", "http://x.com"])
        assert args.concurrency == 50

    def test_default_concurrency(self):
        parser = build_parser()
        args = parser.parse_args(["http://x.com"])
        assert args.concurrency == 30

    def test_category_default(self):
        parser = build_parser()
        args = parser.parse_args(["http://x.com"])
        assert args.category == "all"

    def test_category_env(self):
        parser = build_parser()
        args = parser.parse_args(["--category", "env", "http://x.com"])
        assert args.category == "env"

    def test_category_credentials(self):
        parser = build_parser()
        args = parser.parse_args(["--category", "credentials", "http://x.com"])
        assert args.category == "credentials"

    def test_sensitive_only(self):
        parser = build_parser()
        args = parser.parse_args(["--sensitive-only", "http://x.com"])
        assert args.sensitive_only is True

    def test_has_timeout(self):
        parser = build_parser()
        args = parser.parse_args(["-t", "15", "http://x.com"])
        assert args.timeout == 15

    def test_has_output(self):
        parser = build_parser()
        args = parser.parse_args(["-o", "out.json", "http://x.com"])
        assert args.output == "out.json"

    def test_has_proxy(self):
        parser = build_parser()
        args = parser.parse_args(["--proxy", "http://p:8080", "http://x.com"])
        assert args.proxy == "http://p:8080"

    def test_has_user_agent(self):
        parser = build_parser()
        args = parser.parse_args(["-A", "Bot/1.0", "http://x.com"])
        assert args.user_agent == "Bot/1.0"

    def test_has_dry_run(self):
        parser = build_parser()
        args = parser.parse_args(["--dry-run", "http://x.com"])
        assert args.dry_run is True

    def test_has_retries(self):
        parser = build_parser()
        args = parser.parse_args(["--retries", "5", "http://x.com"])
        assert args.retries == 5

    def test_has_delay(self):
        parser = build_parser()
        args = parser.parse_args(["--delay", "2", "http://x.com"])
        assert args.delay == 2

    def test_has_cookie(self):
        parser = build_parser()
        args = parser.parse_args(["--cookie", "session=abc", "http://x.com"])
        assert args.cookie == "session=abc"

    def test_has_header(self):
        parser = build_parser()
        args = parser.parse_args(["--header", "X-Custom: yes", "http://x.com"])
        assert args.header == ["X-Custom: yes"]


@pytest.mark.smoke
class TestCommonFlags:
    def test_has_json(self):
        args = build_parser().parse_args(["--json", "http://x.com"])
        assert args.json_output is True

    def test_has_quiet(self):
        args = build_parser().parse_args(["--quiet", "http://x.com"])
        assert args.quiet is True

    def test_has_theme(self):
        args = build_parser().parse_args(["--theme", "solarized", "http://x.com"])
        assert args.theme == "solarized"

    def test_has_random_delay(self):
        args = build_parser().parse_args(["--random-delay", "http://x.com"])
        assert args.random_delay is True


class TestJsonOutput:
    def test_json_output_is_valid(self, capsys):
        leak = ConfigLeak(category="env", url="http://x.com/.env", path=".env")
        args = build_parser().parse_args(["--json", "-q", "http://x.com"])
        with patch(
            "mytools.config.configfiledetect.scan_configs",
            new=AsyncMock(return_value=[leak]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        captured = capsys.readouterr().out
        decoder = json.JSONDecoder()
        data, _ = decoder.raw_decode(captured)
        assert isinstance(data, list)
        assert data[0]["path"] == ".env"
        assert json.loads(captured) == data

    def test_json_with_output_writes_file(self, tmp_path, capsys):
        leak = ConfigLeak(category="env", url="http://x.com/.env", path=".env")
        out = tmp_path / "out.json"
        args = build_parser().parse_args(
            ["--json", "-q", "-o", str(out), "http://x.com"]
        )
        with patch(
            "mytools.config.configfiledetect.scan_configs",
            new=AsyncMock(return_value=[leak]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        assert out.exists()
        assert json.loads(out.read_text()) == [
            {
                "category": "env",
                "url": "http://x.com/.env",
                "path": ".env",
                "status": 0,
                "detail": "",
                "raw_size": 0,
                "exploit": "",
                "tool": "",
            }
        ]
        captured = capsys.readouterr().out
        assert json.loads(captured) == json.loads(out.read_text())


# ── scan_configs (mock HTTP) ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_configs_no_results():
    with respx.mock:
        respx.route(method="HEAD", url__startswith="http://x.com/").mock(
            return_value=httpx.Response(404),
        )
        respx.route(method="GET", url__startswith="http://x.com/").mock(
            return_value=httpx.Response(404),
        )
        leaks = await scan_configs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert leaks == []


@pytest.mark.asyncio
async def test_scan_configs_finds_env():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/.env").mock(
            return_value=httpx.Response(200, headers={"content-length": "50"}),
        )
        respx.route(method="GET", url="http://x.com/.env").mock(
            return_value=httpx.Response(200, content=b"DB_HOST=localhost\n"),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_configs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert any(leak.path == ".env" for leak in leaks)


@pytest.mark.asyncio
async def test_scan_configs_skips_large():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/.env").mock(
            return_value=httpx.Response(200, headers={"content-length": "6000000"}),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_configs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert leaks == []


@pytest.mark.asyncio
async def test_scan_configs_head_bad_length():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/.env").mock(
            return_value=httpx.Response(200, headers={"content-length": "abc"}),
        )
        respx.route(method="GET", url="http://x.com/.env").mock(
            return_value=httpx.Response(200, content=b"DB_HOST=localhost\n"),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_configs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert any(leak.path == ".env" for leak in leaks)


@pytest.mark.asyncio
async def test_scan_configs_head_405_followed_by_get():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/.env").mock(
            return_value=httpx.Response(405),
        )
        respx.route(method="GET", url="http://x.com/.env").mock(
            return_value=httpx.Response(200, content=b"DB_HOST=localhost\n"),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_configs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert any(leak.path == ".env" for leak in leaks)


@pytest.mark.asyncio
async def test_scan_configs_head_fetch_error():
    with respx.mock:
        respx.route(method="HEAD", url__startswith="http://x.com/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        respx.route(method="GET", url__startswith="http://x.com/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        leaks = await scan_configs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert leaks == []


@pytest.mark.asyncio
async def test_scan_configs_get_fetch_error():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/.env").mock(
            return_value=httpx.Response(200),
        )
        respx.route(method="GET", url="http://x.com/.env").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_configs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert leaks == []


@pytest.mark.asyncio
async def test_scan_configs_get_non_200():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/.env").mock(
            return_value=httpx.Response(200),
        )
        respx.route(method="GET", url="http://x.com/.env").mock(
            return_value=httpx.Response(500),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_configs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert leaks == []


@pytest.mark.asyncio
async def test_scan_configs_invalid_content():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/config.json").mock(
            return_value=httpx.Response(200),
        )
        respx.route(method="GET", url="http://x.com/config.json").mock(
            return_value=httpx.Response(200, content=b"not json"),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_configs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
            custom_paths=["config.json"],
        )
        assert leaks == []


@pytest.mark.asyncio
async def test_scan_configs_sensitive_only():
    with respx.mock:
        respx.route(method="HEAD", url__startswith="http://x.com/").mock(
            return_value=httpx.Response(404),
        )
        respx.route(method="GET", url__startswith="http://x.com/").mock(
            return_value=httpx.Response(404),
        )
        leaks = await scan_configs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
            custom_paths=["credentials.json", "robots.txt"],
            sensitive_only=True,
        )
        assert leaks == []


# ── print_results ─────────────────────────────────────────────────────────────


class TestPrintResults:
    def test_empty(self, capsys):
        print_results([])
        out = capsys.readouterr().out
        assert "Nenhum" in out

    def test_with_results(self, capsys):
        leaks = [
            ConfigLeak(
                category="env",
                url="http://x.com/.env",
                path=".env",
                status=200,
                detail="DB_HOST=localhost",
                raw_size=50,
            ),
        ]
        print_results(leaks)
        out = capsys.readouterr().out
        assert ".env" in out

    def test_with_exploit(self, capsys):
        leak = ConfigLeak(
            category="env",
            url="http://x.com/.env",
            path=".env",
            status=200,
            detail="DB_HOST=localhost",
            raw_size=50,
            exploit="curl http://x.com/.env",
            tool="curl",
        )
        print_results([leak])
        out = capsys.readouterr().out
        assert "Exploits" in out


class TestAsyncRunOnce:
    def _args(self):
        args = build_parser().parse_args(["http://x.com"])
        args.dry_run = False
        args.json_output = False
        args.output = None
        args.output_dir = None
        return args

    def test_dry_run(self):
        args = self._args()
        args.dry_run = True
        with (
            patch(
                "mytools.config.configfiledetect.init_scanner",
                return_value=False,
            ),
            patch(
                "mytools.config.configfiledetect.resolve_target_urls",
                return_value=["http://x.com/"],
            ),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_prints_results_when_not_quiet(self, capsys):
        args = self._args()
        with (
            patch(
                "mytools.config.configfiledetect.init_scanner",
                return_value=False,
            ),
            patch(
                "mytools.config.configfiledetect.resolve_target_urls",
                return_value=["http://x.com/"],
            ),
            patch(
                "mytools.config.configfiledetect.scan_configs",
                new=AsyncMock(return_value=[]),
            ),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_output_dir(self, tmp_path):
        args = self._args()
        args.output_dir = str(tmp_path)
        with (
            patch(
                "mytools.config.configfiledetect.init_scanner",
                return_value=True,
            ),
            patch(
                "mytools.config.configfiledetect.resolve_target_urls",
                return_value=["http://x.com/"],
            ),
            patch(
                "mytools.config.configfiledetect.scan_configs",
                new=AsyncMock(return_value=[]),
            ),
            patch("mytools.config.configfiledetect.write_output") as mock_write,
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        mock_write.assert_called_once()

    def test_output_file(self, tmp_path):
        args = self._args()
        args.output = str(tmp_path / "out.json")
        with (
            patch(
                "mytools.config.configfiledetect.init_scanner",
                return_value=True,
            ),
            patch(
                "mytools.config.configfiledetect.resolve_target_urls",
                return_value=["http://x.com/"],
            ),
            patch(
                "mytools.config.configfiledetect.scan_configs",
                new=AsyncMock(return_value=[]),
            ),
            patch("mytools.config.configfiledetect.write_output") as mock_write,
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        mock_write.assert_called_once()


# ── run_once / main / __main__ guard ─────────────────────────────────────────


class TestRunOnceAndMain:
    def test_run_once(self):
        args = argparse.Namespace()
        with patch(
            "mytools.config.configfiledetect._async_run_once",
            new_callable=AsyncMock,
            return_value=0,
        ):
            assert run_once(args) == 0

    def test_main(self):
        with patch(
            "mytools.config.configfiledetect.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()

    def test_main_guard(self):
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-configfiledetect"]),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.config.configfiledetect", run_name="__main__")
