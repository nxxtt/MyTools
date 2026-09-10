#!/usr/bin/env python3
"""Stealth & Anti-Detection — Utilitarios para evasao e ofuscação.

Modulo compartilhado por todos os scanners do MyTools. Fornece:

- ProxyPool: pool round-robin de proxies com health check
- UserAgentRotator: rotacao de User-Agents reais (100+)
- TorManager: gerencia conexao Tor via SOCKS5
- Jitter/delay: variacao aleatoria entre requests
- Fragmentation: divisao de payloads para evasao L4/L7
- WAF evasion: encoding para bypass de WAF
- Header padding: ofuscacao de fingerprint

Dependencias:
  - curl-cffi: TLS fingerprint impersonation (Chrome, Firefox, Safari, Edge)
  - httpx-socks[asyncio]: Tor SOCKS5 proxy
"""

from __future__ import annotations

import asyncio
import binascii
import contextlib
import logging
import random
import secrets
from collections.abc import AsyncIterable
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import quote, urlparse, urlunparse

import httpx

logger = logging.getLogger("mytools")

__all__ = [
    "ProxyPool",
    "TorManager",
    "UserAgentRotator",
    "apply_jitter",
    "fragment_http_headers",
    "fragment_tcp_request",
    "pad_headers",
    "random_user_agent",
    "randomize_source_port",
    "waf_encode_headers",
    "waf_encode_url",
]


class ProxyPool:
    """Pool round-robin de proxies com health check e remocao automatica.

    Uso:
        pool = ProxyPool(["http://p1:8080", "http://p2:8080"])
        proxy = await pool.get()  # proximo proxy saudavel
        pool.mark_dead(proxy)     # marca como morto
        pool.mark_ok(proxy)       # reseta erro count
    """

    def __init__(self, proxies: list[str], max_failures: int = 3) -> None:
        self._proxies = list(proxies)
        self._index = 0
        self._failures: dict[str, int] = {}
        self._dead: set[str] = set()
        self._max_failures = max_failures

    @property
    def alive(self) -> list[str]:
        """Retorna proxies ainda saudaveis."""
        return [p for p in self._proxies if p not in self._dead]

    def get_sync(self) -> str | None:
        """Retorna proximo proxy saudavel (round-robin). None se todos mortos."""
        alive = self.alive
        if not alive:
            return None
        proxy = alive[self._index % len(alive)]
        self._index += 1
        return proxy

    async def get(self) -> str | None:
        """Retorna proximo proxy saudavel (async wrapper)."""
        return self.get_sync()

    def mark_dead(self, proxy: str) -> None:
        """Marca proxy como morto apos falha."""
        self._failures[proxy] = self._failures.get(proxy, 0) + 1
        if self._failures[proxy] >= self._max_failures:
            self._dead.add(proxy)
            logger.debug(
                "proxy %s marcado como morto (falhas=%d)", proxy, self._failures[proxy]
            )

    def mark_ok(self, proxy: str) -> None:
        """Reseta contagem de falhas do proxy."""
        self._failures.pop(proxy, None)
        self._dead.discard(proxy)

    @property
    def stats(self) -> dict[str, str]:
        """Retorna estatisticas do pool."""
        return {
            "total": str(len(self._proxies)),
            "alive": str(len(self.alive)),
            "dead": str(len(self._dead)),
        }


_USER_AGENTS: list[str] = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0",
    # Firefox Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:152.0) Gecko/20100101 Firefox/152.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:151.0) Gecko/20100101 Firefox/151.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:150.0) Gecko/20100101 Firefox/150.0",
    # Firefox Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0",
    # Safari Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15",
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0",
    # Mobile Chrome Android
    "Mozilla/5.0 (Linux; Android 15; SM-S938B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-A556B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36",
    # Mobile Safari iOS (Apple froze OS version at 18_6 in Safari 26+)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.3 Mobile/15E148 Safari/604.1",
    # Mobile Firefox Android
    "Mozilla/5.0 (Android 15; Mobile; rv:152.0) Gecko/152.0 Firefox/152.0",
    "Mozilla/5.0 (Android 14; Mobile; rv:151.0) Gecko/151.0 Firefox/151.0",
    # Opera Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 OPR/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 OPR/119.0.0.0",
    # Bot / Crawler — Googlebot (desktop, mobile, legacy)
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/150.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    # Bot / Crawler — Bingbot (desktop, mobile, legacy)
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/136.0.7103.92 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.92 Mobile Safari/537.36 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]


class UserAgentRotator:
    """Rotacao de User-Agents reais com suporte a categorias.

    Uso:
        rotator = UserAgentRotator()
        ua = rotator.get()              # random
        ua = rotator.get(category="chrome")  # so chrome
    """

    CATEGORIES: ClassVar[dict[str, list[str]]] = {
        "chrome": [
            ua
            for ua in _USER_AGENTS
            if "Chrome" in ua and "Edg" not in ua and "OPR" not in ua
        ],
        "firefox": [ua for ua in _USER_AGENTS if "Firefox" in ua],
        "safari": [ua for ua in _USER_AGENTS if "Safari" in ua and "Chrome" not in ua],
        "edge": [ua for ua in _USER_AGENTS if "Edg" in ua],
        "mobile": [ua for ua in _USER_AGENTS if "Mobile" in ua],
        "bot": [ua for ua in _USER_AGENTS if "bot" in ua.lower() or "Bot" in ua],
    }

    def __init__(self, user_agents: list[str] | None = None) -> None:
        self._agents = user_agents or list(_USER_AGENTS)
        self._index = 0

    def get(self, category: str | None = None) -> str:
        """Retorna um User-Agent. category opcional: chrome, firefox, safari, edge, mobile, bot."""
        if category:
            pool = self.CATEGORIES.get(category, [])
            if not pool:
                pool = self._agents
            return secrets.choice(pool)
        ua = self._agents[self._index % len(self._agents)]
        self._index += 1
        return ua

    @property
    def count(self) -> int:
        """Numero total de User-Agents disponiveis."""
        return len(self._agents)


class TorManager:
    """Gerencia conexao Tor via SOCKS5 proxy.

    Requer:
      - Tor daemon rodando na porta 9050 (padrao)
      - httpx-socks[asyncio] instalado

    Uso:
        tor = TorManager()
        proxy = await tor.get_proxy()  # socks5://127.0.0.1:9050
        ip = await tor.get_ip()
        await tor.new_circuit()
    """

    def __init__(
        self,
        socks_port: int = 9050,
        control_port: int = 9051,
        control_auth_cookie: str | Path | None = None,
    ) -> None:
        self._socks_port = socks_port
        self._control_port = control_port
        self._proxy_url = f"socks5://127.0.0.1:{socks_port}"
        self._current_ip: str | None = None
        self._control_auth_cookie = control_auth_cookie
        self._tor_client: httpx.AsyncClient | None = None
        self._tor_transport: Any = None

    async def get_proxy(self) -> str:
        """Retorna URL do proxy SOCKS5 do Tor."""
        return str(self._proxy_url)

    async def get_ip(self, timeout: float = 15.0) -> str:
        """Obtem IP atual via Tor (faz request para API de IP).

        O client/transport HTTP sao reutilizados entre chamadas e so sao
        recriados quando o client foi fechado ou nunca foi criado.
        """
        try:
            from httpx_socks import AsyncProxyTransport

            if self._tor_client is None or getattr(self._tor_client, "is_closed", True):
                self._tor_transport = AsyncProxyTransport.from_url(self._proxy_url)
                self._tor_client = httpx.AsyncClient(
                    transport=self._tor_transport, timeout=timeout
                )
            resp = await self._tor_client.get("https://api.ipify.org?format=json")
            data = resp.json()
            self._current_ip = str(data.get("ip", "unknown"))
            return self._current_ip
        except ImportError:
            logger.debug("httpx-socks nao instalado, impossivel usar Tor")
            return "unknown"
        except Exception as error:
            logger.debug("falha ao obter IP via Tor: %s", error)
            with contextlib.suppress(Exception):
                assert self._tor_client is not None
                await self._tor_client.aclose()
            self._tor_client = None
            self._tor_transport = None
            return "unknown"

    def _find_auth_cookie(self) -> bytes | None:
        """Localiza o control auth cookie do Tor (retorna hex).

        Procura no caminho configurado e, em seguida, nas localizacoes
        padrao das distribuicoes. None se nenhum cookie for encontrado.
        """
        candidates: list[Path] = []
        if self._control_auth_cookie:
            candidates.append(Path(self._control_auth_cookie))
        candidates.extend(
            [
                Path("/run/tor/control.authcookie"),
                Path("/var/lib/tor/control_auth_cookie"),
                Path("/usr/local/var/run/tor/control.authcookie"),
                Path("/var/run/tor/control.authcookie"),
            ]
        )
        for path in candidates:
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if data:
                return binascii.hexlify(data)
        return None

    @staticmethod
    async def _read_status(reader: asyncio.StreamReader) -> bool:
        """Le uma linha de resposta do control port ate '\\r\\n'.

        Acumula leituras parciais do stream (o protocolo Tor entrega linhas
        terminadas em CRLF sobre fluxo TCP) e retorna True se o codigo 250
        aparecer no inicio da linha.
        """
        data = b""
        try:
            for _ in range(8):
                chunk = await reader.read(1024)
                if not chunk:
                    break
                data += chunk
                if b"\r\n" in data:
                    break
        except Exception:
            return False
        return data.lstrip().startswith(b"250")

    async def _tor_control_exchange(self) -> bool:
        """Executa a troca AUTHENTICATE + SIGNAL NEWNYM no control port (async)."""
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", self._control_port
            )
        except Exception as error:
            logger.debug("falha ao conectar no control port Tor: %s", error)
            return False
        try:
            cookie = self._find_auth_cookie()
            if cookie:
                writer.write(b"AUTHENTICATE " + cookie + b"\r\n")
            else:
                # Fallback: autenticacao sem credenciais (CookieAuthentication 0)
                writer.write(b"AUTHENTICATE\r\n")
            await writer.drain()
            if not await self._read_status(reader):
                return False
            writer.write(b"SIGNAL NEWNYM\r\n")
            await writer.drain()
            return await self._read_status(reader)
        except Exception as error:
            logger.debug("falha ao renovar circuito Tor: %s", error)
            return False
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def new_circuit(self, new_circuit_wait: float = 2.0) -> str | None:
        """Solicita novo circuito Tor (via control port).

        Usa o control port do Tor, autenticando com o control_auth_cookie
        quando disponivel (fallback para autenticacao vazia).
        Retorna novo IP ou None se falhar.
        """
        try:
            ok = await self._tor_control_exchange()
            if not ok:
                return None
            await asyncio.sleep(new_circuit_wait)
            return await self.get_ip()
        except Exception as error:
            logger.debug("falha ao renovar circuito Tor: %s", error)
            return None

    @property
    def proxy_url(self) -> str:
        """URL do proxy SOCKS5."""
        return self._proxy_url


def apply_jitter(delay: float, jitter_pct: float = 0.2) -> float:
    """Aplica variacao aleatoria (jitter) ao delay.

    Args:
        delay: Delay base em segundos.
        jitter_pct: Percentual de variacao (0.0 a 1.0). 0.2 = ±20%.

    Returns:
        Delay com jitter aplicado (minimo 0.0).
    """
    if delay <= 0 or jitter_pct <= 0:
        return max(delay, 0.0)
    variation = delay * jitter_pct
    jittered = delay + random.uniform(-variation, variation)
    return max(jittered, 0.0)


def fragment_http_headers(headers: dict[str, str], chunk_size: int = 10) -> list[bytes]:
    """Fragmenta headers HTTP em pedaços para evasao L7 (WAF/IDS).

    Divida cada header em chunks de bytes para bypass de inspecao
    baseada em assinatura de pacotes.

    Args:
        headers: Dict de headers HTTP.
        chunk_size: Tamanho maximo de cada fragmento em bytes.

    Returns:
        Lista de bytes representando os headers fragmentados.
    """
    lines: list[str] = []
    for name, value in headers.items():
        lines.append(f"{name}: {value}\r\n")
    full = "".join(lines).encode("utf-8")
    if chunk_size <= 0:
        chunk_size = max(len(full), 1)
    if len(full) <= chunk_size:
        return [full]
    return [full[i : i + chunk_size] for i in range(0, len(full), chunk_size)]


def fragment_tcp_request(data: bytes, fragment_size: int = 8) -> list[bytes]:
    """Fragmenta payload TCP em pedaços para evasao L4 (IDS/IPS).

    Args:
        data: Payload completo em bytes.
        fragment_size: Tamanho maximo de cada fragmento em bytes.

    Returns:
        Lista de bytes representando os fragmentos.
    """
    if fragment_size <= 0:
        fragment_size = max(len(data), 1)
    if len(data) <= fragment_size:
        return [data]
    return [data[i : i + fragment_size] for i in range(0, len(data), fragment_size)]


class FragmentedSocket:
    """Wrapper transparente que fragmenta sendall() conforme StealthContext.

    Substitui socket normal — todos os sendall() passam a ser fragmentados
    automaticamente quando --fragment ou --fragment-tcp estao ativos.
    """

    def __init__(
        self,
        sock: Any,
        fragment: int = 0,
        fragment_tcp: int = 0,
    ) -> None:
        self._sock = sock
        self._fragment = fragment
        self._fragment_tcp = fragment_tcp

    @classmethod
    def from_context(cls, sock: Any, ctx: Any = None) -> FragmentedSocket:
        """Cria wrapper lendo fragment/fragment_tcp do StealthContext."""
        frag = getattr(ctx, "fragment", 0) if ctx else 0
        frag_tcp = getattr(ctx, "fragment_tcp", 0) if ctx else 0
        return cls(sock, fragment=frag, fragment_tcp=frag_tcp)

    def sendall(self, data: bytes, *args: Any, **kwargs: Any) -> None:
        if self._fragment_tcp > 0:
            for chunk in fragment_tcp_request(data, self._fragment_tcp):
                self._sock.sendall(chunk, *args, **kwargs)
        elif self._fragment > 0:
            sep = data.find(b"\r\n\r\n")
            if sep > 0:
                header_bytes = data[: sep + 4]
                body = data[sep + 4 :]
                for chunk in fragment_tcp_request(header_bytes, self._fragment):
                    self._sock.sendall(chunk, *args, **kwargs)
                if body:
                    self._sock.sendall(body, *args, **kwargs)
            else:
                self._sock.sendall(data, *args, **kwargs)
        else:
            self._sock.sendall(data, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._sock, name)

    def __repr__(self) -> str:
        return f"FragmentedSocket({self._sock!r}, frag={self._fragment}, frag_tcp={self._fragment_tcp})"


class _FragmentedNetworkStream:
    """AsyncNetworkStream wrapper that fragments writes for httpcore integration.

    Intercepts write() calls from httpcore's HTTP/1.1 connection and fragments
    the bytes before forwarding to the real network stream.
    """

    def __init__(self, real_stream: Any, fragment: int, fragment_tcp: int) -> None:
        self._real = real_stream
        self._fragment = fragment
        self._fragment_tcp = fragment_tcp

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._real.read(max_bytes, timeout=timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        if self._fragment_tcp > 0:
            for chunk in fragment_tcp_request(buffer, self._fragment_tcp):
                await self._real.write(chunk, timeout=timeout)
        elif self._fragment > 0:
            sep = buffer.find(b"\r\n\r\n")
            if sep > 0:
                header_bytes = buffer[: sep + 4]
                body = buffer[sep + 4 :]
                for chunk in fragment_tcp_request(header_bytes, self._fragment):
                    await self._real.write(chunk, timeout=timeout)
                if body:
                    await self._real.write(body, timeout=timeout)
            else:
                await self._real.write(buffer, timeout=timeout)
        else:
            await self._real.write(buffer, timeout=timeout)

    async def aclose(self) -> None:
        await self._real.aclose()

    async def start_tls(
        self,
        ssl_context: Any,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> _FragmentedNetworkStream:
        inner = await self._real.start_tls(
            ssl_context, server_hostname=server_hostname, timeout=timeout
        )
        return _FragmentedNetworkStream(inner, self._fragment, self._fragment_tcp)

    def get_extra_info(self, info: str) -> Any:
        return self._real.get_extra_info(info)


class _FragmentedNetworkBackend:
    """AsyncNetworkBackend that wraps connections with FragmentedNetworkStream.

    Pass as ``network_backend=`` to httpx.AsyncHTTPTransport or
    httpcore.AsyncConnectionPool to enable fragmentation at the socket level.
    """

    def __init__(self, fragment: int, fragment_tcp: int) -> None:
        self._fragment = fragment
        self._fragment_tcp = fragment_tcp

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any | None = None,
    ) -> _FragmentedNetworkStream:
        import httpcore._backends.anyio as _anyio_backend

        backend = _anyio_backend.AnyIOBackend()
        real_stream = await backend.connect_tcp(
            host,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )
        return _FragmentedNetworkStream(real_stream, self._fragment, self._fragment_tcp)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Any | None = None,
    ) -> _FragmentedNetworkStream:
        import httpcore._backends.anyio as _anyio_backend

        backend = _anyio_backend.AnyIOBackend()
        real_stream = await backend.connect_unix_socket(
            path, timeout=timeout, socket_options=socket_options
        )
        return _FragmentedNetworkStream(real_stream, self._fragment, self._fragment_tcp)

    async def sleep(self, seconds: float) -> None:
        import httpcore._backends.anyio as _anyio_backend

        backend = _anyio_backend.AnyIOBackend()
        await backend.sleep(seconds)


class _FragmentedTransport(httpx.AsyncBaseTransport):
    """httpx transport that fragments HTTP traffic at the socket level.

    Wraps an httpcore connection pool configured with a custom network backend
    that splits writes into chunks before sending to the wire.  Transparent to
    callers — implements the standard ``handle_async_request`` interface.
    """

    def __init__(
        self,
        *,
        fragment: int = 0,
        fragment_tcp: int = 0,
        verify: bool = False,
        local_address: str | None = None,
        proxy: str | None = None,
    ) -> None:
        import ssl as _ssl

        import httpcore

        backend = _FragmentedNetworkBackend(fragment, fragment_tcp)
        ssl_context = _ssl.create_default_context() if verify else None

        if proxy is not None:
            from httpx import Proxy

            p = Proxy(url=proxy) if isinstance(proxy, str) else proxy
            self._pool: Any = httpcore.AsyncHTTPProxy(
                proxy_url=httpcore.URL(
                    scheme=p.url.raw_scheme,
                    host=p.url.raw_host,
                    port=p.url.port,
                    target=p.url.raw_path,
                ),
                proxy_auth=p.raw_auth,
                proxy_headers=p.headers.raw,
                proxy_ssl_context=p.ssl_context,
                ssl_context=ssl_context,
                local_address=local_address,
                network_backend=backend,  # type: ignore[reportArgumentType]
            )
        else:
            self._pool = httpcore.AsyncConnectionPool(
                ssl_context=ssl_context,
                local_address=local_address,
                network_backend=backend,  # type: ignore[reportArgumentType]
            )

    async def handle_async_request(
        self,
        request: httpx.Request,
    ) -> httpx.Response:
        from httpx._transports.default import (
            AsyncResponseStream,
            map_httpcore_exceptions,
        )

        assert isinstance(request.stream, httpx.AsyncByteStream)
        import httpcore

        req = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        with map_httpcore_exceptions():
            resp = await self._pool.handle_async_request(req)

        assert isinstance(resp.stream, AsyncIterable)

        return httpx.Response(
            status_code=resp.status,
            headers=resp.headers,
            stream=AsyncResponseStream(resp.stream),
            extensions=resp.extensions,
        )


def build_fragmented_transport(
    *,
    fragment: int = 0,
    fragment_tcp: int = 0,
    verify: bool = False,
    local_address: str | None = None,
    proxy: str | None = None,
) -> httpx.AsyncBaseTransport:
    """Build an httpx transport with fragmentation at the socket level.

    When *fragment* or *fragment_tcp* > 0, returns a ``_FragmentedTransport``
    that chunks outgoing data at the TCP level.  Otherwise returns a plain
    ``httpx.AsyncHTTPTransport``.
    """
    if fragment > 0 or fragment_tcp > 0:
        return _FragmentedTransport(
            fragment=fragment,
            fragment_tcp=fragment_tcp,
            verify=verify,
            local_address=local_address,
            proxy=proxy,
        )

    return httpx.AsyncHTTPTransport(
        verify=verify,
        local_address=local_address,  # type: ignore[arg-type]
        proxy=proxy,
    )


def waf_encode_url(url: str) -> str:
    """Aplica encoding anti-WAF em uma URL.

    Tecnicas:
      - Double encoding (%25xx para %xx)
      - Case variation em path
      - Espacos codificados como %20 ou +
      - Ponto codificado como %2e

    Args:
        url: URL original.

    Returns:
        URL com encoding anti-WAF.
    """
    parsed = urlparse(url)
    path = parsed.path

    # Double encoding de caracteres especiais no path
    encoded_parts: list[str] = []
    for char in path:
        if char in ("/", "."):
            if char == "." and secrets.randbelow(2) == 0:
                encoded_parts.append("%2e")
            else:
                encoded_parts.append(char)
        elif char.isascii() and char.isalpha() and secrets.randbelow(3) == 0:
            # Case variation
            encoded_parts.append(char.upper() if char.islower() else char.lower())
        elif char == " ":
            encoded_parts.append("%20" if secrets.randbelow(2) == 0 else "+")
        else:
            encoded_parts.append(quote(char, safe=""))

    encoded_path = "".join(encoded_parts)

    # Double encode percent signs
    if secrets.randbelow(2) == 0:
        encoded_path = encoded_path.replace("%", "%25")

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            encoded_path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def waf_encode_headers(headers: dict[str, str]) -> dict[str, str]:
    """Aplica encoding anti-WAF nos headers.

    Tecnicas:
      - Nomes de headers em mixed case (Content-Type vs content-type)
      - Espacos extras antes do ':' (tecnica HTTP smuggling)
      - Headers padding para confundir fingerprinting

    Args:
        headers: Dict de headers originais.

    Returns:
        Dict de headers com encoding anti-WAF.
    """
    encoded: dict[str, str] = {}
    for name, value in headers.items():
        # Mixed case no nome do header
        new_name = ""
        for i, char in enumerate(name):
            if char == "-":
                new_name += char
            elif i % 2 == 0:
                new_name += char.upper()
            else:
                new_name += char.lower()
        # Headers que diferem apenas em caixa podem colidir (muitos-para-um);
        # neste caso mantemos o nome original para nao perder dados.
        if new_name in encoded:
            encoded[name] = value
        else:
            encoded[new_name] = value
    return encoded


def pad_headers(headers: dict[str, str], target_count: int = 10) -> dict[str, str]:
    """Adiciona headers padding para confundir analise de fingerprint.

    Gera headers fake com nomes realistas para dificultar
    identificacao de ferramentas de scan.

    Args:
        headers: Dict de headers originais.
        target_count: Numero minimo total de headers (incluindo originais).

    Returns:
        Dict de headers com padding adicionado.
    """
    padded = dict(headers)
    fake_header_names = [
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Requested-With",
        "Accept-Language",
        "Accept-Encoding",
        "Cache-Control",
        "Pragma",
        "Connection",
        "Upgrade-Insecure-Requests",
        "Sec-Fetch-Dest",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Site",
        "Sec-Fetch-User",
        "Sec-Ch-Ua",
        "Sec-Ch-Ua-Mobile",
        "Sec-Ch-Ua-Platform",
        "DNT",
        "TE",
        "Trailers",
    ]
    fake_values = [
        "127.0.0.1",
        "Mozilla/5.0",
        "keep-alive",
        "no-cache",
        "1",
        "navigate",
        "cross-site",
        '"Chromium";v="131", "Not_A Brand";v="24"',
        "?0",
        "en-US,en;q=0.9",
        "gzip, deflate, br",
    ]
    available = [n for n in fake_header_names if n not in padded]
    if len(padded) + len(available) < target_count:
        target_count = len(padded) + len(available)
    while len(padded) < target_count:
        name = available.pop()
        padded[name] = secrets.choice(fake_values)
    return padded


def random_user_agent() -> str:
    """Retorna um User-Agent aleatorio da lista de agents conhecidos."""
    return secrets.choice(_USER_AGENTS)


def randomize_source_port() -> int:
    """Retorna porta de origem aleatoria (1024-65535).

    Util para ofuscar fingerprint de ferramentas de scan
    que usam portas padrao previsiveis.
    """
    return secrets.randbelow(65535 - 1024 + 1) + 1024
