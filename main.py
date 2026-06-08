#!/usr/bin/env python3
from __future__ import annotations

import attackaudit
import dirscanner
import portscanner
import webrecon
from utils import Cyber, clear_console, color


def banner() -> None:
    art = r"""
    __  ___        ______            __    
   /  |/  /_  __  /_  __/___  ____  / /____
  / /|_/ / / / /   / / / __ \/ __ \/ / ___/
 / /  / / /_/ /   / / / /_/ / /_/ / (__  ) 
/_/  /_/\__, /   /_/  \____/\____/_/____/  
       /____/                               
"""
    print(color(art.rstrip(), Cyber.CYAN, Cyber.BOLD))
    print(color("   port scanner + dir scanner + web recon + attack audit", Cyber.MAGENTA))
    print(color("   by Default\n", Cyber.GRAY))


def menu() -> None:
    print(color("Escolha uma tool:", Cyber.WHITE, Cyber.BOLD))
    print(f"  {color('1', Cyber.GREEN, Cyber.BOLD)} {color('PortScanner', Cyber.CYAN)}  TCP ports, CIDR, banners, JSON/CSV")
    print(f"  {color('2', Cyber.GREEN, Cyber.BOLD)} {color('DirScanner', Cyber.CYAN)}   HTTP dirs/files, status filters, wordlist")
    print(f"  {color('3', Cyber.GREEN, Cyber.BOLD)} {color('WebRecon', Cyber.CYAN)}     HTTP headers, robots, security checks")
    print(f"  {color('4', Cyber.GREEN, Cyber.BOLD)} {color('AttackAudit', Cyber.CYAN)}  red/blue web audit pesado, score, JSON/CSV")
    print(f"  {color('5', Cyber.GREEN, Cyber.BOLD)} {color('Ajuda', Cyber.CYAN)}        exemplos rapidos")
    print(f"  {color('6', Cyber.GREEN, Cyber.BOLD)} {color('Limpar', Cyber.CYAN)}       limpar terminal")
    print(f"  {color('0', Cyber.RED, Cyber.BOLD)} {color('Sair', Cyber.CYAN)}")


def help_screen() -> None:
    print(color("\nExemplos:", Cyber.WHITE, Cyber.BOLD))
    print(color("PortScanner:", Cyber.CYAN))
    print("  python3 portscanner.py 127.0.0.1 -p 22,80,443")
    print("  python3 portscanner.py 192.168.0.0/24 -p top100 -b")
    print(color("\nDirScanner:", Cyber.CYAN))
    print("  python3 dirscanner.py http://testphp.vulnweb.com -x php,txt,bak")
    print("  python3 dirscanner.py http://127.0.0.1:8000 -s 200,301,403")
    print(color("\nWebRecon:", Cyber.CYAN))
    print("  python3 webrecon.py https://example.com")
    print("  python3 webrecon.py https://example.com -o recon.json")
    print(color("\nAttackAudit:", Cyber.CYAN))
    print("  python3 attackaudit.py https://example.com --deep")
    print("  python3 attackaudit.py https://example.com --deep -o audit.json")
    print(color("\nDentro do menu:", Cyber.CYAN))
    print("  escolha uma tool e digite os argumentos como faria depois do nome do script.")
    print("  use 'exit' dentro de cada scanner para voltar ao menu.\n")


def launch_portscanner() -> None:
    parser = portscanner.build_parser()
    portscanner.interactive_shell(parser)


def launch_dirscanner() -> None:
    parser = dirscanner.build_parser()
    dirscanner.interactive_shell(parser)


def launch_webrecon() -> None:
    parser = webrecon.build_parser()
    webrecon.interactive_shell(parser)


def launch_attackaudit() -> None:
    parser = attackaudit.build_parser()
    attackaudit.interactive_shell(parser)


def main() -> int:
    while True:
        banner()
        menu()
        try:
            choice = input(color("\nuser-agent> ", Cyber.GREEN, Cyber.BOLD)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice in {"0", "q", "quit", "exit"}:
            print(color("bye bye user!", Cyber.MAGENTA))
            return 0
        if choice in {"1", "port", "ports", "portscanner"}:
            launch_portscanner()
        elif choice in {"2", "dir", "dirs", "dirscanner"}:
            launch_dirscanner()
        elif choice in {"3", "web", "recon", "webrecon"}:
            launch_webrecon()
        elif choice in {"4", "audit", "attack", "attackaudit", "redblue"}:
            launch_attackaudit()
        elif choice in {"5", "help", "ajuda", "h"}:
            help_screen()
            input(color("Enter para voltar...", Cyber.GRAY))
        elif choice in {"6", "clear", "limpar", "cls"}:
            clear_console()
            continue
        else:
            print(color("Opcao invalida.", Cyber.RED))
            input(color("Enter para continuar...", Cyber.GRAY))

        clear_console()


if __name__ == "__main__":
    raise SystemExit(main())
