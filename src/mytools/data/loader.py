"""Loader de payloads YAML/JSON com cache e fallback."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("mytools.data")

_DATA_DIR = Path(__file__).parent
_cache: dict[str, Any] = {}
_loaded_registry: dict[str, Any] = {}


def _resolve_value(v: Any, module: str) -> Any:
    """Resolve binary_path para bytes lendo arquivo .bin."""
    if isinstance(v, dict) and "binary_path" in v:
        bin_path = _DATA_DIR / v["binary_path"]
        if bin_path.exists():
            return bin_path.read_bytes()
        logger.debug("binary_path não encontrado: %s", bin_path)
    return v


def _resolve_recursive(data: Any, module: str) -> Any:
    """Resolve binary_path recursivamente em dicts e lists."""
    if isinstance(data, dict):
        return {k: _resolve_recursive(_resolve_value(v, module), module) for k, v in data.items()}
    if isinstance(data, list):
        return [_resolve_recursive(_resolve_value(item, module), module) for item in data]
    return _resolve_value(data, module)


def load_payloads(
    module: str,
    name: str,
    default: Any = None,
    *,
    post_process: Callable[[Any], Any] | None = None,
) -> Any:
    """Carrega payloads de data/{module}/{name}.yaml (ou .json).

    - Fallback: retorna 'default' se arquivo não existe ou falha
    - Cache em memória (pós-processado é cacheado, não re-executado)
    - Resolve binary_path → leitura de .bin
    - post_process: transforma dados ANTES de cachear
    - Registra em _loaded_registry para --dump-payloads
    """
    cache_key = f"{module}/{name}"
    if cache_key in _cache:
        return _cache[cache_key]

    data = default
    for ext in ("yaml", "yml", "json"):
        path = _DATA_DIR / module / f"{name}.{ext}"
        if path.exists():
            try:
                with path.open(encoding="utf-8") as f:
                    data = yaml.safe_load(f) if ext in ("yaml", "yml") else json.load(f)
                break
            except Exception as exc:
                logger.debug("falha ao carregar %s: %s", path, exc)
                data = default

    if data is not default:
        data = _resolve_recursive(data, module)

    if post_process and data is not default:
        try:
            data = post_process(data)
        except Exception as exc:
            logger.debug("falha no post_process para %s: %s", cache_key, exc)
            data = default

    _cache[cache_key] = data
    if data is not default:
        _loaded_registry[cache_key] = data
    return data


def dump_registry() -> dict[str, Any]:
    """Retorna cópia de todos os payloads carregados (para --dump-payloads)."""
    return dict(_loaded_registry)
