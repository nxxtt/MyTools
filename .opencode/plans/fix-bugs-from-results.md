# Plano: Corrigir bugs encontrados na análise dos resultados JSON

## Context
Análise dos 28 arquivos JSON na pasta `results/` revelou 3 bugs de código + 1 observação.

---

## Bug 1: `dnstransfer.py:121` — `serial=0` removido no dnspython
**Severidade:** HIGH
**Erro:** `"inbound_xfr() got an unexpected keyword argument 'serial'"`
**Causa:** `dns.query.inbound_xfr()` na versão atual do dnspython (2.8.0) não aceita mais o parâmetro `serial`.

### Fix
- **Arquivo:** `dnstransfer.py:116-122`
- **Ação:** Remover `serial=0,` da chamada `dns.query.inbound_xfr()`
- **Antes:**
  ```python
  zone = dns.query.inbound_xfr(
      ns_ip,
      domain,
      timeout=timeout,
      lifetime=timeout,
      serial=0,
  )
  ```
- **Depois:**
  ```python
  zone = dns.query.inbound_xfr(
      ns_ip,
      domain,
      timeout=timeout,
      lifetime=timeout,
  )
  ```

---

## Bug 2: `webrecon.py` — `cve_findings: None` em vez de `[]`
**Severidade:** MEDIUM
**Problema:** `ReconResult.cve_findings` tem default `None`, gerando `"cve_findings": null` no JSON quando `--cve` não é usado. Deveria ser `[]` para consistência (sempre array).

### Fix
- **Arquivo:** `webrecon.py:654-657`
- **Ação:** Mudar defaults de `None` para `list` vazio
- **Mudanças:**
  - `cve_findings: list[CVEFinding] | None = None` → `cve_findings: list[CVEFinding] = field(default_factory=list)`
  - `waf_detected: list[str] | None = None` → `waf_detected: list[str] = field(default_factory=list)`
  - `emails: list[str] | None = None` → `emails: list[str] = field(default_factory=list)`
- **Nota:** Verificar se `from dataclasses import field` já está importado. Se não, adicionar.
- **Nota:** Verificar se o print/display code que checa `is not None` para `cve_findings` (line 834) continua funcionando — mudar para `if result.cve_findings:`.

---

## Bug 3: `attackaudit.py` — `sqli_errors/method_results/tls_versions: None` em vez de `[]`
**Severidade:** MEDIUM
**Problema:** `AuditResult` tem defaults `None` para campos que deveriam ser sempre listas.

### Fix
- **Arquivo:** `attackaudit.py:243-247`
- **Ação:** Mudar defaults de `None` para `list` vazio
- **Mudanças:**
  - `tls_versions: list[TLSVersionResult] | None = None` → `tls_versions: list[TLSVersionResult] = field(default_factory=list)`
  - `sqli_errors: list[str] | None = None` → `sqli_errors: list[str] = field(default_factory=list)`
  - `method_results: list[MethodResult] | None = None` → `method_results: list[MethodResult] = field(default_factory=list)`
- **Nota:** Verificar imports e print/display code que checam `is not None`.

---

## Bug 4 (observação): `dnstransfer.py` — verbose log vazio
**Severidade:** LOW
**Problema:** `xfr_verbose.log` tem 0 bytes mesmo com `-v --log-file`.
**Decisão:** NÃO corrigir agora — requer investigação do setup_logging para DNS Xfer. Baixa prioridade.

---

## Tests Updates

### `tests/test_dnstransfer.py`
- Remover `serial=0` dos mocks de `inbound_xfr` se presentes

### `tests/test_webrecon.py`
- Atualizar asserts `is None` para `== []`:
  - `assert r.cve_findings is None` → `assert r.cve_findings == []`
  - `assert r.waf_detected is None` → `assert r.waf_detected == []`
  - `assert r.emails is None` → `assert r.emails == []`

### `tests/test_attackaudit.py`
- Atualizar asserts `is None` para `== []`:
  - `assert r.sqli_errors is None` → `assert r.sqli_errors == []`
  - `assert r.method_results is None` → `assert r.method_results == []`
  - `assert r.tls_versions is None` → `assert r.tls_versions == []`

---

## Execução
1. Fix Bug 1: `dnstransfer.py`
2. Fix Bug 2: `webrecon.py` ReconResult
3. Fix Bug 3: `attackaudit.py` AuditResult
4. Fix tests: `test_dnstransfer.py`, `test_webrecon.py`, `test_attackaudit.py`
5. `poetry run pytest tests/ -q`
6. `poetry run ruff check .`
7. Commit: `fix: DNS Xfer serial kwarg, JSON null→[] consistency`
8. Push

## Verificação
- Rodar `mytools-dnsxfer testfire.net` e confirmar que o JSON não contém mais o erro `serial`
- Rodar `mytools-recon` sem `--cve` e confirmar `cve_findings: []`
- Rodar `mytools-audit` sem `--test-methods` e confirmar `method_results: []`
