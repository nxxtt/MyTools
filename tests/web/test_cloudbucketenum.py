"""Testes do modulo cloudbucketenum."""

from dataclasses import asdict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.cloudbucketenum import (
    BucketAttempt,
    BucketResult,
    _check_azure_response,
    _check_gcp_response,
    _check_s3_response,
    _generate_bucket_names,
    _get_azure_indicators,
    _get_gcp_indicators,
    _get_prefixes,
    _get_s3_indicators,
    _get_suffixes,
    banner_art,
    build_parser,
    main,
    print_results,
    run_scan,
)

# ---------------------------------------------------------------------------
# _get_suffixes / _get_prefixes
# ---------------------------------------------------------------------------


class TestPayloads:
    def test_suffixes_loaded(self) -> None:
        suffixes = _get_suffixes()
        assert isinstance(suffixes, list)
        assert len(suffixes) > 0
        assert "" in suffixes

    def test_prefixes_loaded(self) -> None:
        prefixes = _get_prefixes()
        assert isinstance(prefixes, list)
        assert len(prefixes) > 0
        assert "" in prefixes

    def test_s3_indicators(self) -> None:
        ind = _get_s3_indicators()
        assert "open" in ind
        assert "exists" in ind
        assert "access_denied" in ind

    def test_gcp_indicators(self) -> None:
        ind = _get_gcp_indicators()
        assert "open" in ind
        assert "not_found" in ind

    def test_azure_indicators(self) -> None:
        ind = _get_azure_indicators()
        assert "open" in ind
        assert "not_found" in ind


# ---------------------------------------------------------------------------
# _generate_bucket_names
# ---------------------------------------------------------------------------


class TestGenerateBucketNames:
    def test_basic_generation(self) -> None:
        names = _generate_bucket_names("example.com")
        assert isinstance(names, list)
        assert "example" in names
        assert len(names) > 1

    def test_has_backup(self) -> None:
        names = _generate_bucket_names("mycompany.com")
        assert "mycompany-backup" in names

    def test_has_logs(self) -> None:
        names = _generate_bucket_names("mycompany.com")
        assert "mycompany-logs" in names

    def test_no_duplicates(self) -> None:
        names = _generate_bucket_names("test.com")
        assert len(names) == len(set(names))

    def test_single_word_domain(self) -> None:
        names = _generate_bucket_names("localhost")
        assert "localhost" in names


# ---------------------------------------------------------------------------
# _check_s3_response
# ---------------------------------------------------------------------------


class TestCheckS3Response:
    def test_open_bucket(self) -> None:
        indicators = {"open": ["ListBucketResult", "<Key>"], "exists": ["NoSuchBucket"], "access_denied": ["AccessDenied"]}
        open_b, exists, detail = _check_s3_response(200, "<ListBucketResult><Key>file.txt</Key></ListBucketResult>", indicators)
        assert open_b is True
        assert exists is True
        assert "ABERTO" in detail

    def test_not_exists(self) -> None:
        indicators = {"open": ["ListBucketResult"], "exists": ["NoSuchBucket"], "access_denied": ["AccessDenied"]}
        open_b, exists, detail = _check_s3_response(404, "<NoSuchBucket>The bucket does not exist</NoSuchBucket>", indicators)
        assert open_b is False
        assert exists is False
        assert "nao existe" in detail

    def test_access_denied(self) -> None:
        indicators = {"open": ["ListBucketResult"], "exists": ["NoSuchBucket"], "access_denied": ["AccessDenied"]}
        open_b, exists, detail = _check_s3_response(403, "<AccessDenied>Access Denied</AccessDenied>", indicators)
        assert open_b is False
        assert exists is True
        assert "fechado" in detail or "negado" in detail

    def test_unknown_status(self) -> None:
        indicators = {"open": ["ListBucketResult"], "exists": ["NoSuchBucket"], "access_denied": ["AccessDenied"]}
        open_b, exists, detail = _check_s3_response(500, "error", indicators)
        assert open_b is False
        assert exists is False
        assert "500" in detail


# ---------------------------------------------------------------------------
# _check_gcp_response
# ---------------------------------------------------------------------------


class TestCheckGCPResponse:
    def test_open_bucket(self) -> None:
        indicators = {"open": ["items", "kind"], "not_found": ["NoSuchBucket"]}
        open_b, exists, _detail = _check_gcp_response(200, '{"kind": "storage#objects", "items": []}', indicators)
        assert open_b is True
        assert exists is True

    def test_not_exists(self) -> None:
        indicators = {"open": ["items"], "not_found": ["NoSuchBucket"]}
        open_b, exists, _detail = _check_gcp_response(404, "NoSuchBucket", indicators)
        assert open_b is False
        assert exists is False

    def test_access_denied(self) -> None:
        indicators = {"open": ["items"], "not_found": ["NoSuchBucket"]}
        open_b, exists, _detail = _check_gcp_response(403, "Forbidden", indicators)
        assert open_b is False
        assert exists is True


# ---------------------------------------------------------------------------
# _check_azure_response
# ---------------------------------------------------------------------------


class TestCheckAzureResponse:
    def test_open_container(self) -> None:
        indicators = {"open": ["EnumerationResults", "<Blobs>"], "not_found": ["BlobNotFound"]}
        open_b, exists, _detail = _check_azure_response(
            200, "<EnumerationResults><Blobs><Blob><Name>file.txt</Name></Blob></Blobs></EnumerationResults>", indicators
        )
        assert open_b is True
        assert exists is True

    def test_not_exists(self) -> None:
        indicators = {"open": ["EnumerationResults"], "not_found": ["BlobNotFound"]}
        open_b, exists, _detail = _check_azure_response(404, "BlobNotFound", indicators)
        assert open_b is False
        assert exists is False

    def test_access_denied(self) -> None:
        indicators = {"open": ["EnumerationResults"], "not_found": ["BlobNotFound"]}
        open_b, exists, _detail = _check_azure_response(403, "Forbidden", indicators)
        assert open_b is False
        assert exists is True


# ---------------------------------------------------------------------------
# BucketAttempt / BucketResult dataclasses
# ---------------------------------------------------------------------------


class TestBucketAttempt:
    def test_frozen(self) -> None:
        attempt = BucketAttempt(
            provider="s3",
            bucket_name="test",
            url="http://x",
            status_code=200,
            response_size=100,
            response_time=0.1,
            open_bucket=True,
            exists=True,
            details="open",
        )
        with pytest.raises(AttributeError):
            attempt.provider = "gcp"  # type: ignore[misc]

    def test_slots(self) -> None:
        attempt = BucketAttempt(
            provider="s3",
            bucket_name="test",
            url="http://x",
            status_code=200,
            response_size=100,
            response_time=0.1,
            open_bucket=True,
            exists=True,
            details="open",
        )
        assert not hasattr(attempt, "__dict__")

    def test_asdict(self) -> None:
        attempt = BucketAttempt(
            provider="s3",
            bucket_name="test",
            url="http://x",
            status_code=200,
            response_size=100,
            response_time=0.1,
            open_bucket=True,
            exists=True,
            details="open",
        )
        d = asdict(attempt)
        assert d["provider"] == "s3"
        assert d["open_bucket"] is True


class TestBucketResult:
    def test_frozen(self) -> None:
        result = BucketResult(
            domain="example.com",
            attempts=[],
            open_buckets=[],
            existing_buckets=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            result.domain = "other.com"  # type: ignore[misc]

    def test_asdict(self) -> None:
        result = BucketResult(
            domain="example.com",
            attempts=[],
            open_buckets=["s3:test"],
            existing_buckets=[],
            issues=[],
            overall_status="vulnerable",
        )
        d = asdict(result)
        assert d["open_buckets"] == ["s3:test"]
        assert d["overall_status"] == "vulnerable"


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


class TestBuildParser:
    def test_domain_arg(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_providers_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.providers == "all"

    def test_providers_s3(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "-p", "s3"])
        assert args.providers == "s3"

    def test_providers_gcp(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "-p", "gcp"])
        assert args.providers == "gcp"

    def test_providers_azure(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "-p", "azure"])
        assert args.providers == "azure"

    def test_concurrency_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.concurrency == 5


# ---------------------------------------------------------------------------
# print_results
# ---------------------------------------------------------------------------


class TestPrintResults:
    def test_secure_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = BucketResult(
            domain="example.com",
            attempts=[],
            open_buckets=[],
            existing_buckets=[],
            issues=["Nenhum bucket aberto"],
            overall_status="secure",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "CLOUD BUCKET" in captured.out
        assert "SECURE" in captured.out

    def test_vulnerable_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = BucketResult(
            domain="example.com",
            attempts=[],
            open_buckets=["s3:example"],
            existing_buckets=[],
            issues=["Buckets ABERTOS"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "VULNERABLE" in captured.out
        assert "s3:example" in captured.out


# ---------------------------------------------------------------------------
# banner_art
# ---------------------------------------------------------------------------


class TestBanner:
    def test_callable(self) -> None:
        assert callable(banner_art)

    def test_runs(self, capsys: pytest.CaptureFixture[str]) -> None:
        banner_art()
        captured = capsys.readouterr()
        assert "Cloud Bucket" in captured.out


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


class TestMain:
    def test_no_args(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.argv", ["mytools-bucket"])
        monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(EOFError))
        result = main()
        assert result == 0


# ---------------------------------------------------------------------------
# run_scan (mocked)
# ---------------------------------------------------------------------------


class TestRunScan:
    @pytest.mark.asyncio()
    async def test_invalid_provider(self) -> None:
        result = await run_scan("example.com", providers="invalid")
        assert result.overall_status == "error"
        assert any("desconhecido" in i for i in result.issues)

    @pytest.mark.asyncio()
    async def test_s3_open_bucket(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<ListBucketResult><Key>file.txt</Key></ListBucketResult>"
        mock_resp.content = b"<ListBucketResult>"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("mytools.web.cloudbucketenum.create_async_client") as mock_factory:
            mock_factory.return_value = mock_client
            result = await run_scan(
                "example.com",
                providers="s3",
                concurrency=50,
            )
            assert result.overall_status == "vulnerable"
            assert any("s3:" in b for b in result.open_buckets)

    @pytest.mark.asyncio()
    async def test_s3_not_exists(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "<NoSuchBucket>The bucket does not exist</NoSuchBucket>"
        mock_resp.content = b"<NoSuchBucket>"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("mytools.web.cloudbucketenum.create_async_client") as mock_factory:
            mock_factory.return_value = mock_client
            result = await run_scan(
                "example.com",
                providers="s3",
                concurrency=50,
            )
            assert result.overall_status == "secure"
            assert len(result.open_buckets) == 0
