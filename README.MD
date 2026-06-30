# MyTools v3.2.0

[![CI](https://github.com/nxxtt/ferramentas_osint/actions/workflows/ci.yml/badge.svg)](https://github.com/nxxtt/ferramentas_osint/actions/workflows/ci.yml)

Suite de ferramentas de auditoria e reconhecimento web/network para ambientes de laboratório e alvos autorizados.

> **AVISO:** Este projeto é destinado exclusivamente para fins educacionais e de teste em ambientes autorizados. O uso irresponsável pode ser ilegal. Use com responsabilidade.

---

## Instalação

### Pré-requisitos
- **Python 3.14+**

### Instalacao rapida (recomendado)
```bash
git clone https://github.com/nxxtt/ferramentas_osint.git
cd ferramentas_osint

# Windows
.\setup.ps1

# Linux/Mac
chmod +x setup.sh
./setup.sh
```

O script instala Poetry, dependencias e adiciona os comandos CLI ao PATH.

### Instalacao manual
```bash
git clone https://github.com/nxxtt/ferramentas_osint.git
cd ferramentas_osint
pip install poetry
poetry install --with dev
```

> **Nota:** Apos instalar manualmente, use `poetry run mytools` ou ative o venv com `poetry env activate`.

Isso instala os comandos CLI:

| Comando | Modulo |
|---------|--------|
| `mytools` | Painel interativo central |
| `mytools-audit` | Auditoria ofensiva/defensiva |
| `mytools-recon` | Reconhecimento passivo |
| `mytools-port` | Scanner de portas TCP |
| `mytools-dir` | Scanner de diretorios HTTP |
| `mytools-dnsxfer` | DNS Zone Transfer |
| `mytools-subenum` | Enumeracao de subdominios |
| `mytools-dnshistory` | Historico DNS (OSINT) |
| `mytools-whoishistory` | Historico WHOIS (OSINT) |
| `mytools-ipasn` | IP ASN/ISP enrichment |
| `mytools-techfp` | Technology Fingerprint |
| `mytools-oas` | OpenAPI/Swagger Discovery |
| `mytools-gql` | GraphQL Playground Exposure |
| `mytools-sm` | Source Map Discovery |
| `mytools-vcs` | VCS Leak Detection |
| `mytools-cfg` | Config File Detection |
| `mytools-bak` | Backup File Detection |
| `mytools-dork` | Google Dorking |
| `mytools-breach` | Email Breach Check |
| `mytools-soceng` | Social Engineering Recon |
| `mytools-leak` | Paste/Leak Monitoring |
| `mytools-dark` | Dark Web Monitoring |
| `mytools-rebind` | DNS Rebinding Detection |
| `mytools-dwt` | DNS Water Torture (stress test) |
| `mytools-amp` | DNS Amplification Detection |
| `mytools-tunnel` | DNS Tunnel Detection |
| `mytools-dnssec` | DNSSEC Validation |
| `mytools-nsec` | NSEC Walking |
| `mytools-caa` | CAA Record Check |
| `mytools-secemail` | Email Security (DMARC/SPF/DKIM) |
| `mytools-spoof` | Email Spoofing Analysis |
| `mytools-smtpinject` | SMTP Header Injection |
| `mytools-smtpdown` | SMTP Downgrade Attack |
| `mytools-templeti` | Email Template Injection |
| `mytools-cred` | Gerenciador de credenciais |
| `mytools-reconall` | Recon completo (todos os modulos) |

> **Nota:** Apos instalar, abra um novo terminal. Se o comando nao for encontrado, adicione o diretorio `Scripts` do Python ao PATH.

---

## Estrutura do Projeto

```
src/mytools/                    # Pacote principal
  __init__.py                   # __version__
  core/                         # Infraestrutura compartilhada
    utils.py                    # Cores, HTTP async, helpers, output
    cred.py                     # Gerenciador de credenciais (keyring)
    main.py                     # Menu interativo central
    reconall.py                 # Orquestrador: executa todos os modulos
  network/                      # Rede e portas
    portscanner.py              # Scanner de portas TCP
    dirscanner.py               # Scanner de diretorios HTTP
  web/                          # Web e HTTP
    webrecon.py                 # Reconhecimento passivo + CVE + WHOIS
    attackaudit.py              # Auditoria ofensiva/defensiva
    openapidiscovery.py         # OpenAPI/Swagger Discovery
    graphqlplayground.py        # GraphQL Playground Exposure
    sourcemapdiscovery.py       # Source Map Discovery
    techfingerprint.py          # Technology Fingerprint
  dns/                          # DNS e resolucao
    dnstransfer.py              # DNS Zone Transfer
    subdomainenum.py            # Enumeracao de subdominios
    dnshistory.py               # Historico DNS (OSINT)
    dnswatorture.py             # DNS Water Torture (stress test)
    dnsamplification.py         # DNS Amplification Detection
    dnstunnel.py                # DNS Tunnel Detection
    dnssecvalidation.py         # DNSSEC Validation
    nsecwalking.py              # NSEC Walking
    caacheck.py                 # CAA Record Check
    dnsrebinding.py             # DNS Rebinding Detection
  whois/                        # WHOIS
    whoishistory.py             # Historico WHOIS (OSINT)
  osint/                        # OSINT e reconhecimento
    emailbreachcheck.py         # Email Breach Check
    socialengrecon.py           # Social Engineering Recon
    pasteleak.py                # Paste/Leak Monitoring
    darkwebmonitor.py           # Dark Web Monitoring
    googledorking.py            # Google Dorking
    ipasninfo.py                # IP ASN/ISP Enrichment
  email/                        # Seguranca de email
    emailsecurity.py            # DMARC/SPF/DKIM
    emailspoof.py               # Email Spoofing Analysis
    smtpinjection.py            # SMTP Header Injection
    smtpdowngrade.py            # SMTP Downgrade Attack
    emailtemplateinject.py      # Email Template Injection
  vcs/                          # Controle de versao
    vcsleak.py                  # VCS Leak Detection
  config/                       # Arquivos de configuracao
    configfiledetect.py         # Config File Detection
    backupfiledetect.py         # Backup File Detection

tests/                          # Testes unitarios (1900 testes)
  core/                         # test_utils, test_cred, test_reconall
  network/                      # test_portscanner, test_dirscanner
  web/                          # test_webrecon, test_attackaudit, ...
  dns/                          # test_dnstransfer, test_subdomainenum, ...
  whois/                        # test_whoishistory
  osint/                        # test_emailbreachcheck, ...
  email/                        # test_emailsecurity, ...
  vcs/                          # test_vcsleak
  config/                       # test_configfiledetect, ...

pyproject.toml                  # Configuracao do projeto
```

---

## Modulos

### 1. Painel Central (`mytools`)
Orquestrador do ecossistema com menu interativo colorido para alternar entre todas as subferramentas.

```bash
mytools
mytools --version
```

### 2. Network PortScanner (`mytools-port`)
Scanner de portas TCP com suporte a CIDR, banner grabbing e exportacao JSON/CSV.

```bash
mytools-port 192.168.0.0/24 -p 22,80,443 -b
mytools-port scanme.nmap.org -p top100 -o resultado.json
mytools-port -l targets.txt -o results.json
mytools-port 10.0.0.0/30 -p 80 -w 100 --banner -o scan.csv
```

### 3. Web Directory Scanner (`mytools-dir`)
Fuzzing e descoberta de caminhos ocultos em servidores web com filtros de status code e extensoes.

```bash
mytools-dir http://target.local -x php,txt,bak -s 200,403
mytools-dir http://127.0.0.1:8000 -w wordlist.txt
mytools-dir http://target.local --proxy http://proxy:8080 --delay 10
mytools-dir -l urls.txt --output-dir results/
```

### 4. Web Passive Recon (`mytools-recon`)
Reconhecimento passivo: headers de seguranca, fingerprinting, robots.txt, sitemap.xml, WAF detection, email harvesting, WHOIS e lookup de CVEs.

```bash
mytools-recon https://example.com
mytools-recon https://example.com -o recon.json
mytools-recon https://example.com --cve                    # Lookup de CVEs
mytools-recon https://example.com --cve --nvd-api-key KEY  # Com API key
mytools-recon https://example.com --deep                   # Email harvesting + crawl
mytools-recon https://example.com --deep --crawl-limit 20  # Limite de paginas crawleadas
```

### 5. Deep Attack & Vulnerability Audit (`mytools-audit`)
Auditoria red/blue com verificacao de CORS, TLS, cookies, XSS, SQLi, CSRF, metodos HTTP perigosos e deep scan de arquivos sensiveis.

```bash
mytools-audit https://example.com --deep
mytools-audit https://example.com --deep -o audit.json
mytools-audit https://example.com --test-vulns                 # Testa XSS, SQLi e CSRF
mytools-audit https://example.com --test-methods               # Scan de metodos HTTP
```

### 6. DNS Zone Transfer (`mytools-dnsxfer`)
Tenta zone transfer (AXFR) em nameservers de um dominio para enumerar registros DNS.

```bash
mytools-dnsxfer example.com
mytools-dnsxfer example.com -o xfr.json
```

### 7. Subdomain Enumeration (`mytools-subenum`)
Brute-force DNS de subdominios com wordlist embutida ou customizada.

```bash
mytools-subenum example.com
mytools-subenum example.com -o subs.json
mytools-subenum example.com -w wordlist.txt
mytools-subenum example.com -T 50
```

### 8. DNS History (`mytools-dnshistory`)
Consulta historico DNS via fontes OSINT (DNSlytics, SecurityTrails, ViewDNS).

```bash
mytools-dnshistory example.com
mytools-dnshistory example.com -o dns-history.json
```

### 9. WHOIS History (`mytools-whoishistory`)
Consulta historico WHOIS via fontes OSINT (SecurityTrails, WhoisXML).

```bash
mytools-whoishistory example.com
mytools-whoishistory example.com -o whois-history.json
```

### 10. IP ASN/ISP Info (`mytools-ipasn`)
Enriquece IPs com dados BGP: ASN, organizacao, ISP, pais, cidade. Dual API (ipwho.is + ip-api.com), suporte batch.

```bash
mytools-ipasn 8.8.8.8
mytools-ipasn 8.8.8.8 1.1.1.1 1.0.0.1
mytools-ipasn -l ips.txt -o asn.json
```

### 11. Technology Fingerprint (`mytools-techfp`)
Fingerprinting tecnologico com 7 sinais: headers, meta tags, scripts, CSS, cookies, body HTML, headers de seguranca. 40+ tecnologias, confidence scoring.

```bash
mytools-techfp https://example.com
mytools-techfp https://example.com -o tech.json
```

### 12. OpenAPI/Swagger Discovery (`mytools-oas`)
Busca specs OpenAPI/Swagger expostas em paths comuns, faz parse JSON/YAML, extrai endpoints, metodos, tags e schemas.

```bash
mytools-oas http://target.com
mytools-oas http://target.com --endpoints
```

### 13. GraphQL Playground Exposure (`mytools-gql`)
Descobre GraphQL playgrounds expostos (GraphiQL, Playground, Altair, Voyager) e opcionalmente executa introspection query.

```bash
mytools-gql http://target.com
mytools-gql http://target.com --introspect
```

### 14. Source Map Discovery (`mytools-sm`)
Busca `.map` files de JavaScript expostos por scan de `<script src>` + probing de paths comuns.

```bash
mytools-sm http://target.com
mytools-sm http://target.com --sources
```

### 15. VCS Leak Detection (`mytools-vcs`)
Detecta repositorios versionados expostos (.git, .svn, .hg) com validacao de conteudo.

```bash
mytools-vcs http://target.com
mytools-vcs http://target.com --git-only
```

### 16. Config File Detection (`mytools-cfg`)
Detecta arquivos de configuracao sensiveis expostos (.env, config.json, settings.py, .htpasswd).

```bash
mytools-cfg http://target.com
mytools-cfg http://target.com --category env
```

### 17. Backup File Detection (`mytools-bak`)
Detecta arquivos de backup expostos (.bak, .old, .swp, .sql, .zip) com validacao de magic bytes.

```bash
mytools-bak http://target.com
mytools-bak http://target.com --type sql
```

### 18. Google Dorking (`mytools-dork`)
Gera dorks Google para o alvo e busca via DuckDuckGo. 6 categorias de dorks.

```bash
mytools-dork example.com
mytools-dork example.com --category sensitive --search
```

### 19. Email Breach Check (`mytools-breach`)
Verifica se emails apareceram em vazamentos de dados (XposedOrNot, LeakCheck, HIBP).

```bash
mytools-breach user@example.com
mytools-breach user@example.com --source hibp --hibp-api-key KEY
```

### 20. Social Engineering Recon (`mytools-soceng`)
Coleta emails, nomes e cargos de funcionarios via GitHub, Hunter.io e web scraping.

```bash
mytools-soceng example.com
mytools-soceng example.com --hunter-api-key KEY
```

### 21. Paste/Leak Monitoring (`mytools-leak`)
Monitora pastes e repos publicos por credenciais e dados sensiveis (GitHub Gists, Pastebin RSS).

```bash
mytools-leak example.com
mytools-leak example.com --github-token ghp_xxx
```

### 22. Dark Web Monitoring (`mytools-dark`)
Busca mencoes do dominio em sites .onion via Ahmia, DarkSearch e Intelligence X.

```bash
mytools-dark example.com
mytools-dark example.com --intelx-key KEY
```

### 23. DNS Rebinding (`mytools-rebind`)
Testa vulnerabilidade a DNS rebinding (TTL, IPs privados, wildcard, IP flip).

```bash
mytools-rebind example.com
mytools-rebind example.com -o rebind.json
```

### 24. DNS Water Torture (`mytools-dwt`)
Stress test DNS com subdominios aleatorios para testar resiliencia.

```bash
mytools-dwt example.com
mytools-dwt example.com --num-queries 1000
```

### 25. DNS Amplification (`mytools-amp`)
Detecta se servidor DNS pode ser usado para amplificacao DDoS.

```bash
mytools-amp example.com
mytools-amp example.com -o amp.json
```

### 26. DNS Tunnel Detection (`mytools-tunnel`)
Detecta DNS tunneling via analise de entropia, comprimento de labels e padroes.

```bash
mytools-tunnel example.com
mytools-tunnel example.com -o tunnel.json
```

### 27. DNSSEC Validation (`mytools-dnssec`)
Valida configuracao DNSSEC: cadeia de confianca, RRSIG, forca de algoritmo.

```bash
mytools-dnssec example.com
mytools-dnssec example.com -o dnssec.json
```

### 28. NSEC Walking (`mytools-nsec`)
Enumera zonas DNSSEC via NSEC records em cadeia.

```bash
mytools-nsec example.com
mytools-nsec example.com -o nsec.json
```

### 29. CAA Record Check (`mytools-caa`)
Verifica registros CAA (Certificate Authority Authorization) de certificados.

```bash
mytools-caa example.com
mytools-caa example.com -o caa.json
```

### 30. Email Security (`mytools-secemail`)
Verifica configuracao DMARC/SPF/DKIM de email.

```bash
mytools-secemail example.com
mytools-secemail example.com -o emailsec.json
```

### 31. Email Spoofing (`mytools-spoof`)
Analise de vulnerabilidade a spoofing via SPF/DKIM/DMARC.

```bash
mytools-spoof example.com
mytools-spoof example.com -o spoof.json
```

### 32. SMTP Injection (`mytools-smtpinject`)
Testa injecao CRLF em campos de email via SMTP.

```bash
mytools-smtpinject mail.example.com
mytools-smtpinject mail.example.com --port 25
```

### 33. SMTP Downgrade (`mytools-smtpdown`)
Testa se servidor SMTP pode ser forcado a operar em plaintext (STARTTLS stripping).

```bash
mytools-smtpdown mail.example.com
mytools-smtpdown mail.example.com --port 25
```

### 34. Email Template Injection (`mytools-templeti`)
Testa injecao de codigo em templates de email (Jinja2, Handlebars, Mako).

```bash
mytools-templeti mail.example.com
mytools-templeti mail.example.com --port 25
```

### 35. ReconAll (`mytools-reconall`)
Executa todos os modulos contra um alvo de uma vez.

```bash
mytools-reconall https://example.com --deep
mytools-reconall example.com --skip dnstransfer --skip subenum
```

---

## Uso

### Painel unificado
```bash
mytools
```

### Modo interativo
Cada modulo possui um shell interativo. Dentro dele, digite os argumentos normalmente:
```
scanner> 192.168.1.0/24 -p 80,443 -b -t 1
```
Use `help` para ver a ajuda, `exit` para voltar ao menu.

### Exemplos rapidos
| Comando | Descricao |
|---------|-----------|
| `mytools-port 127.0.0.1 -p 1-1024` | Scan TCP nas primeiras 1024 portas |
| `mytools-dir http://testphp.vulnweb.com -x php` | Busca por arquivos .php |
| `mytools-recon https://example.com` | Recon passivo rapido |
| `mytools-audit https://example.com --deep` | Auditoria completa |
| `mytools-dnsxfer example.com` | DNS Zone Transfer scan |
| `mytools-subenum example.com` | Enumeracao de subdominios |
| `mytools-dnshistory example.com` | Historico DNS via OSINT |
| `mytools-ipasn 8.8.8.8` | IP ASN/ISP enrichment |
| `mytools-techfp https://example.com` | Technology fingerprinting |
| `mytools-vcs http://target.com` | VCS leak detection |
| `mytools-dork example.com` | Google dorking |
| `mytools-breach user@example.com` | Email breach check |
| `mytools-secemail example.com` | Email security (DMARC/SPF/DKIM) |
| `mytools-rebind example.com` | DNS rebinding test |
| `mytools-dnssec example.com` | DNSSEC validation |
| `mytools-reconall https://example.com --deep` | Recon completo |

### Execucao direta (sem instalar)
```bash
python -m mytools.core.main                # Painel unificado
python -m mytools.web.attackaudit --help   # Ajuda individual
python -m mytools.dns.dnstransfer --help   # DNS Zone Transfer
```

---

## Features v3.2.0

### src/ Package Structure
Codigo organizado em `src/mytools/` com subpacotes por categoria: `core`, `network`, `web`, `dns`, `whois`, `osint`, `email`, `vcs`, `config`.

### Python 3.14+ Modernization
Codigo utiliza features modernas do Python 3.14+: `asyncio.TaskGroup`, `match/case`, `tomllib`, PEP 758 `except` sem parenteses, f-strings PEP 701.

### Multi-target
Execute qualquer ferramenta em multiplos alvos a partir de um arquivo:

```bash
mytools-recon -l targets.txt --output-dir results/
mytools-audit -l targets.txt --output-dir results/
mytools-port -l hosts.txt -p 80,443
```

### Quiet Mode
Sem banner, sem mensagens de progresso — apenas erros no stderr:

```bash
mytools-recon https://example.com -q -o recon.json
```

### Autenticacao
Suporte a Basic Auth, Bearer Token, Cookies e Headers customizados:

```bash
mytools-audit https://internal.app --auth admin:senha123
mytools-recon https://api.target.com --bearer-token eyJhbGc...
mytools-dir http://app.local --cookie "session=abc123"
```

### Async HTTP (httpx)
Todos os modulos HTTP utilizam `httpx.AsyncClient` com `asyncio.TaskGroup` e `Semaphore`.

### 1900 Testes
Suite completa de testes unitarios com mocks, organizados por categoria.

---

## Desenvolvimento

### Rodar testes
```bash
poetry run pytest tests/ -v
```

### Lint
```bash
poetry run ruff check src/mytools/ tests/
poetry run basedpyright src/mytools/
```

### Adicionar dependencias de dev
```bash
poetry install --with dev
```

---

## Dependencias

### Runtime
- `httpx>=0.28.1` — HTTP client async com sessions, proxy, retry
- `beautifulsoup4>=4.15.0` — Parser HTML avancado
- `python-whois>=0.9.6` — Consulta WHOIS
- `dnspython>=2.8.0` — Resolucao DNS, zone transfer e enumeracao
- `pyyaml>=6.0.3` — Parse de YAML (OpenAPI specs)

### Dev
- `pytest>=9.1.1` — Framework de testes
- `pytest-asyncio>=1.4.0` — Testes async
- `respx>=0.23.1` — Mock de httpx para testes
- `ruff>=0.15.20` — Linter/formatter
- `basedpyright>=1.39.8` — Type checker

---

## Aviso Legal

Este software e fornecido "como esta", sem garantia de qualquer tipo. O autor nao se responsabiliza pelo uso indevido destas ferramentas. Execute apenas em ambientes que voce tenha autorizacao expressa para testar.

---

*nxt*
