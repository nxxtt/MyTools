from __future__ import annotations

from utils import (
    Cyber,
    NoRedirectHandler,
    color,
    extract_title,
    header_get,
    status_color,
)


class TestCyberConstants:
    def test_all_colors_are_ansi_strings(self):
        for attr in ("RESET", "BOLD", "DIM", "RED", "GREEN", "CYAN", "BLUE", "MAGENTA", "YELLOW", "WHITE", "GRAY"):
            value = getattr(Cyber, attr)
            assert isinstance(value, str)
            assert value.startswith("\033[")

    def test_reset_ends_with_zero(self):
        assert Cyber.RESET == "\033[0m"


class TestColor:
    def test_returns_plain_text_when_no_color(self, monkeypatch):
        monkeypatch.setattr("utils.USE_COLOR", False)
        assert color("hello", Cyber.RED) == "hello"

    def test_wraps_with_ansi_when_color(self, monkeypatch):
        monkeypatch.setattr("utils.USE_COLOR", True)
        result = color("hello", Cyber.RED)
        assert result == f"{Cyber.RED}hello{Cyber.RESET}"

    def test_multiple_styles(self, monkeypatch):
        monkeypatch.setattr("utils.USE_COLOR", True)
        result = color("hello", Cyber.RED, Cyber.BOLD)
        assert result == f"{Cyber.RED}{Cyber.BOLD}hello{Cyber.RESET}"

    def test_no_styles(self, monkeypatch):
        monkeypatch.setattr("utils.USE_COLOR", True)
        result = color("hello")
        assert result == f"hello{Cyber.RESET}"


class TestStatusColor:
    def test_200_is_green(self):
        assert status_color(200) == Cyber.GREEN

    def test_301_is_yellow(self):
        assert status_color(301) == Cyber.YELLOW

    def test_401_is_magenta(self):
        assert status_color(401) == Cyber.MAGENTA

    def test_403_is_magenta(self):
        assert status_color(403) == Cyber.MAGENTA

    def test_500_is_gray(self):
        assert status_color(500) == Cyber.GRAY

    def test_503_is_gray(self):
        assert status_color(503) == Cyber.GRAY

    def test_unknown_is_gray(self):
        assert status_color(999) == Cyber.GRAY


class TestHeaderGet:
    def test_exact_match(self):
        assert header_get({"Content-Type": "text/html"}, "Content-Type") == "text/html"

    def test_case_insensitive(self):
        assert header_get({"CONTENT-TYPE": "text/html"}, "content-type") == "text/html"

    def test_missing_returns_empty(self):
        assert header_get({"Content-Type": "text/html"}, "X-Custom") == ""

    def test_empty_headers(self):
        assert header_get({}, "anything") == ""


class TestExtractTitle:
    def test_simple_title(self):
        assert extract_title("<html><title>Hello</title></html>") == "Hello"

    def test_no_title(self):
        assert extract_title("<html><body>No title here</body></html>") == ""

    def test_case_insensitive(self):
        assert extract_title("<TITLE>Mixed</TITLE>") == "Mixed"

    def test_extra_whitespace(self):
        assert extract_title("<title>  Hello   World  </title>") == "Hello World"

    def test_truncation_at_100(self):
        long_title = "A" * 150
        result = extract_title(f"<title>{long_title}</title>")
        assert len(result) == 100

    def test_empty_title(self):
        assert extract_title("<title></title>") == ""


class TestNoRedirectHandler:
    def test_redirect_returns_none(self):
        handler = NoRedirectHandler()
        result = handler.redirect_request(None, None, 301, None, None, "http://new")
        assert result is None
