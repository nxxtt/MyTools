#!/usr/bin/env python3
"""Gerenciador de credenciais no keyring do SO.

Permite armazenar, recuperar e gerenciar API keys e tokens de autenticacao
de forma segura usando o keyring do sistema operacional (Windows Credential
Manager, macOS Keychain, Linux SecretService).

Uso:
    mytools-cred set <nome>        — armazena uma credencial
    mytools-cred get <nome>        — recupera uma credencial
    mytools-cred delete <nome>     — remove uma credencial
    mytools-cred list              — lista credenciais salvas

Em scanners, use o prefixo @ para referenciar credenciais salvas:
    mytools attackaudit https://target.com --bearer-token @meu_token
"""

import argparse
import getpass
import logging
import re
import sys
from typing import Any

from mytools.core.utils import run_interactive_shell, setup_logging

logger = logging.getLogger("mytools.cred")

_SERVICE_NAME = "mytools"
_VALID_NAME_RE = re.compile(r"^[\w.-]+$")
_RESERVED_NAMES = {"__registry__"}


def _get_keyring() -> Any:
    """Retorna o modulo keyring ou None se nao disponivel."""
    try:
        import keyring

        return keyring
    except ImportError:
        return None


def _valid_name(name: str) -> bool:
    """Valida um nome de credencial (evita corromper o registro)."""
    return (
        bool(name)
        and name not in _RESERVED_NAMES
        and _VALID_NAME_RE.fullmatch(name) is not None
    )


def _list_credentials() -> list[str]:
    """Lista todas as credenciais salvas com prefixo mytools/.

    keyring nao fornece listagem nativa, entao usamos um registro
    auxiliar para rastrear nomes de credenciais.
    """
    kr = _get_keyring()
    if kr is None:
        return []
    registry = _keyring_get(kr, _SERVICE_NAME, "__registry__")
    if not registry:
        return []
    return sorted(registry.splitlines())


def _update_registry(name: str, add: bool = True) -> None:
    """Adiciona ou remove um nome do registro de credenciais."""
    kr = _get_keyring()
    if kr is None:
        return
    registry = _keyring_get(kr, _SERVICE_NAME, "__registry__")
    names = set(registry.splitlines()) if registry else set()
    if add:
        names.add(name)
    else:
        names.discard(name)
    _keyring_set(kr, _SERVICE_NAME, "__registry__", "\n".join(sorted(names)))


def _keyring_get(kr: Any, *args: str) -> str | None:
    """Wrapper de get_password que trata erros do backend sem traceback."""
    try:
        return kr.get_password(*args)
    except Exception as exc:  # keyring backend pode lancar erros variados
        logger.error("Erro no keyring ao ler: %s", exc)
        return None


def _keyring_set(kr: Any, *args: str) -> bool:
    """Wrapper de set_password que trata erros do backend sem traceback."""
    try:
        kr.set_password(*args)
        return True
    except Exception as exc:  # keyring backend pode lancar erros variados
        logger.error("Erro no keyring ao gravar: %s", exc)
        return False


def _keyring_delete(kr: Any, *args: str) -> bool:
    """Wrapper de delete_password que trata erros do backend sem traceback."""
    try:
        kr.delete_password(*args)
        return True
    except Exception as exc:  # keyring backend pode lancar erros variados
        logger.error("Erro no keyring ao remover: %s", exc)
        return False


def set_credential(name: str, value: str | None = None) -> bool:
    """Armazena uma credencial no keyring.

    Se value nao for fornecido, solicita interativamente (sem echo).
    Retorna True em caso de sucesso.
    """
    if not _valid_name(name):
        logger.error(
            "Erro: nome de credencial invalido (apos: letras, digitos, "
            "ponto, hifen e sublinhado; nao pode ser '%s').",
            name,
        )
        return False
    kr = _get_keyring()
    if kr is None:
        logger.error("Erro: keyring nao disponivel. Instale com: pip install keyring")
        return False
    if value is None:
        value = getpass.getpass(f"Valor para '{name}': ")
    if not value:
        logger.error("Erro: valor vazio nao pode ser armazenado.")
        return False
    if not _keyring_set(kr, _SERVICE_NAME, name, value):
        return False
    _update_registry(name, add=True)
    logger.info("Credencial '%s' armazenada com sucesso.", name)
    return True


def get_credential(name: str) -> str | None:
    """Recupera uma credencial do keyring. Retorna None se nao encontrada."""
    kr = _get_keyring()
    if kr is None:
        return None
    return _keyring_get(kr, _SERVICE_NAME, name)


def delete_credential(name: str) -> bool:
    """Remove uma credencial do keyring. Retorna True em caso de sucesso."""
    if not _valid_name(name):
        logger.error("Erro: nome de credencial invalido.")
        return False
    kr = _get_keyring()
    if kr is None:
        logger.error("Erro: keyring nao disponivel.")
        return False
    existing = _keyring_get(kr, _SERVICE_NAME, name)
    if existing is None:
        logger.warning("Credencial '%s' nao encontrada.", name)
        return False
    if not _keyring_delete(kr, _SERVICE_NAME, name):
        return False
    _update_registry(name, add=False)
    logger.info("Credencial '%s' removida com sucesso.", name)
    return True


def list_credentials() -> list[str]:
    """Lista nomes das credenciais salvas (sem exibir valores)."""
    names = _list_credentials()
    if not names:
        logger.info("Nenhuma credencial salva.")
    else:
        logger.info("Credenciais salvas:")
        for name in names:
            logger.info("  - %s", name)
    return names


def build_parser() -> argparse.ArgumentParser:
    """Cria o parser CLI para mytools-cred."""
    parser = argparse.ArgumentParser(
        prog="mytools-cred",
        description="Gerencia credenciais no keyring do SO.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_set = sub.add_parser("set", help="Armazena uma credencial.")
    p_set.add_argument("name", help="Nome da credencial (ex: bearer_token)")

    p_get = sub.add_parser("get", help="Recupera uma credencial.")
    p_get.add_argument("name", help="Nome da credencial")

    p_del = sub.add_parser("delete", help="Remove uma credencial.")
    p_del.add_argument("name", help="Nome da credencial")

    sub.add_parser("list", help="Lista credenciais salvas.")

    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um comando de credenciais a partir de argumentos parseados."""
    command = getattr(args, "command", None)
    if command == "set":
        return 0 if set_credential(args.name) else 1
    if command == "get":
        if _get_keyring() is None:
            logger.error(
                "Erro: keyring nao disponivel. Instale com: pip install keyring"
            )
            return 1
        value = get_credential(args.name)
        if value is None:
            logger.error("Credencial '%s' nao encontrada.", args.name)
            return 1
        if len(value) > 4:
            print(f"{'*' * (len(value) - 4)}{value[-4:]}")
        else:
            print("****")
        return 0
    if command == "delete":
        return 0 if delete_credential(args.name) else 1
    if command == "list":
        list_credentials()
        return 0
    build_parser().print_help()
    return 1


def main() -> int:
    """Ponto de entrada CLI para mytools-cred."""
    parser = build_parser()
    setup_logging()

    if len(sys.argv) <= 1:
        return run_interactive_shell(
            parser,
            prompt="cred> ",
            run_fn=run_once,
            description="Gerencia credenciais no keyring do SO (set/get/delete/list).",
            example="set meu_token",
            contextual_help=(
                "Comandos:\n"
                "  set <nome>          armazena/atualiza uma credencial\n"
                "  get <nome>          recupera e exibe mascarada\n"
                "  delete <nome>       remove uma credencial\n"
                "  list                lista credenciais salvas\n\n"
                "Exemplos:\n"
                "  cred> set google_api\n"
                "  cred> get google_api\n"
                "  cred> delete google_api\n"
                "  cred> list"
            ),
        )

    args = parser.parse_args()
    return run_once(args)


if __name__ == "__main__":
    raise SystemExit(main())
