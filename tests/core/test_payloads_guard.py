"""Guard transversal: toda chave top-level dos YAMLs de payload deve ser lida pelo modulo consumidor.

Verifica que:
1. Todos os YAMLs em src/mytools/data sao consumidos por load_payloads (zero orfaos).
2. Cada chave top-level de cada YAML aparece como dado lido (get("chave")) em pelo
   menos um modulo consumidor — pega chaves mortas como o caso rest_api_fuzz.yaml.
"""

from __future__ import annotations

import pathlib
import re

import pytest
import yaml

SRC_DIR = pathlib.Path(__file__).resolve().parents[2] / "src" / "mytools"
DATA_DIR = SRC_DIR / "data"

_LOAD_PAYLOAD_RE = re.compile(r'load_payloads\(\s*["\'](?P<module>[^"\']+)["\']\s*,\s*["\'](?P<stem>[^"\']+)["\']')
_GET_KEY_RE = re.compile(r'(?:get|_get_str_list|_get_tuple_list)\(\s*["\'](?P<key>[^"\']+)["\']')
_SUBSCRIPT_KEY_RE = re.compile(r'\[["\'](?P<key>[^"\']+)["\']\]')
_LOADER_CALL_RE = re.compile(r'_(?:load|get)\w*\(\s*["\'](?P<key>[^"\']+)["\']')

# YAMLs cujo consumidor retorna o dict INTEIRO (acesso por subscrito com variavel,
# ex.: darkwebmonitor._load_severity_keywords() -> _SEVERITY_KEYWORDS[severity]).
_DICT_RETURN_YAMLS = {"darkweb_severity_keywords"}


def _yaml_files() -> list[pathlib.Path]:
    return sorted(DATA_DIR.rglob("*.yaml"))


def _consumers(stem: str) -> list[pathlib.Path]:
    consumers = []
    for py in SRC_DIR.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        if any(m.group("stem") == stem for m in _LOAD_PAYLOAD_RE.finditer(text)):
            consumers.append(py)
    return consumers


@pytest.mark.parametrize("yaml_path", _yaml_files(), ids=lambda p: p.relative_to(DATA_DIR).as_posix())
def test_yaml_has_consumer(yaml_path: pathlib.Path) -> None:
    consumers = _consumers(yaml_path.stem)
    assert consumers, f"YAML sem consumidor via load_payloads: {yaml_path.relative_to(DATA_DIR)}"


@pytest.mark.parametrize("yaml_path", _yaml_files(), ids=lambda p: p.relative_to(DATA_DIR).as_posix())
def test_every_key_is_read(yaml_path: pathlib.Path) -> None:
    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    consumers = _consumers(yaml_path.stem)
    assert consumers, f"YAML sem consumidor via load_payloads: {yaml_path.relative_to(DATA_DIR)}"
    consumer_text = "\n".join(p.read_text(encoding="utf-8") for p in consumers)
    read_keys = {m.group("key") for m in _GET_KEY_RE.finditer(consumer_text)}
    read_keys |= {m.group("key") for m in _SUBSCRIPT_KEY_RE.finditer(consumer_text)}
    read_keys |= {m.group("key") for m in _LOADER_CALL_RE.finditer(consumer_text)}
    if yaml_path.stem in _DICT_RETURN_YAMLS:
        return
    dead = sorted(set(data) - read_keys)
    assert not dead, (
        f"Chaves nao lidas por nenhum consumidor em {yaml_path.relative_to(DATA_DIR)}: "
        f"{dead}. Renomeie as chaves do YAML para bater com as lidas no modulo "
        "(ou remova as que estao mortas)."
    )
