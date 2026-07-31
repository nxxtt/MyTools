"""API endpoint extraction from APK DEX bytecode."""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

__all__ = ["extract_endpoints"]

logger = logging.getLogger("mytools.mobile.apk_endpoints")

# URL patterns to extract
_URL_PATTERNS = [
    re.compile(rb"https?://[a-zA-Z0-9._/\-?&=%#@:~]+"),
    re.compile(rb"ws://[a-zA-Z0-9._/\-?&=%#@:~]+"),
    re.compile(rb"wss://[a-zA-Z0-9._/\-?&=%#@:~]+"),
]

# API path patterns
_API_PATH_PATTERNS = [
    re.compile(
        rb"/(?:api|v[0-9]+|graphql|rest|oauth|auth|token|login|register|signup|user|users|profile|admin|dashboard|webhook)[a-zA-Z0-9/_\-]*"
    ),
]

# Deep link / scheme patterns
_SCHEME_PATTERNS = [
    re.compile(rb"[a-zA-Z][a-zA-Z0-9+.\-]+://[^\s\x00-\x1f]+"),
]

# Firebase patterns
_FIREBASE_PATTERNS = [
    re.compile(rb"https://[a-z0-9-]+\.firebaseio\.com[^\s\x00-\x1f]*"),
    re.compile(rb"https://[a-z0-9-]+\.firebaseapp\.com[^\s\x00-\x1f]*"),
    re.compile(rb"https://[a-z0-9-]+\.web\.app[^\s\x00-\x1f]*"),
]


def extract_endpoints(file_path: str) -> dict[str, Any]:
    """Extrai endpoints de API de um APK via scan de strings DEX.

    Returns:
        Dict com keys: urls, api_paths, firebase_urls, schemes,
        total_endpoints, domains.
    """
    try:
        import zipfile

        all_urls: set[str] = set()
        api_paths: set[str] = set()
        firebase_urls: set[str] = set()
        schemes: set[str] = set()
        domains: set[str] = set()

        with zipfile.ZipFile(file_path, "r") as apk:
            dex_files = [n for n in apk.namelist() if n.endswith(".dex")]

            for dex_name in dex_files:
                try:
                    data = apk.read(dex_name)
                except Exception:
                    continue

                # Extract URLs
                for pattern in _URL_PATTERNS:
                    for match in pattern.finditer(data):
                        url = match.group().decode("utf-8", errors="replace")
                        all_urls.add(url)
                        # Extract domain
                        try:
                            parsed = urlparse(url)
                            if parsed.hostname:
                                domains.add(parsed.hostname)
                        except Exception:
                            pass

                # Extract API paths
                for pattern in _API_PATH_PATTERNS:
                    for match in pattern.finditer(data):
                        path = match.group().decode("utf-8", errors="replace")
                        api_paths.add(path)

                # Extract Firebase URLs
                for pattern in _FIREBASE_PATTERNS:
                    for match in pattern.finditer(data):
                        url = match.group().decode("utf-8", errors="replace")
                        firebase_urls.add(url)

                # Extract deep link schemes
                for pattern in _SCHEME_PATTERNS:
                    for match in pattern.finditer(data):
                        scheme = match.group().decode("utf-8", errors="replace")
                        # Filter out common non-API schemes
                        lower = scheme.lower()
                        if not any(
                            lower.startswith(x)
                            for x in [
                                "http://",
                                "https://",
                                "file://",
                                "content://",
                                "android.",
                                "java.",
                                "javax.",
                            ]
                        ):
                            schemes.add(scheme)

        # Filter and sort
        sorted_urls = sorted(all_urls)[:200]  # cap at 200
        sorted_api_paths = sorted(api_paths)[:200]
        sorted_firebase = sorted(firebase_urls)[:50]
        sorted_schemes = sorted(schemes)[:50]
        sorted_domains = sorted(domains)[:100]

        return {
            "urls": sorted_urls,
            "api_paths": sorted_api_paths,
            "firebase_urls": sorted_firebase,
            "schemes": sorted_schemes,
            "domains": sorted_domains,
            "total_endpoints": len(sorted_urls)
            + len(sorted_api_paths)
            + len(sorted_firebase),
        }

    except Exception as e:
        logger.error("Failed to extract endpoints from %s: %s", file_path, e)
        return {
            "error": str(e)[:200],
            "urls": [],
            "api_paths": [],
            "total_endpoints": 0,
        }
