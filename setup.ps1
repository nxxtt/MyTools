# MyTools — Script de instalação (Windows)
# Executa: .\setup.ps1

$ErrorActionPreference = "Stop"

$version = (Get-Content pyproject.toml | Select-String '^version').Line -replace '.*"(.*)".*','$1'

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MyTools v$version — Instalador" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verificar Python
Write-Host "[1/4] Verificando Python..." -ForegroundColor Yellow
try {
    $pyVersion = python --version 2>&1
    Write-Host "  OK: $pyVersion" -ForegroundColor Green
    # Validate >= 3.14.2
    if ($pyVersion -match "Python (\d+)\.(\d+)\.(\d+)") {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
        $patch = [int]$Matches[3]
        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 14) -or ($major -eq 3 -and $minor -eq 14 -and $patch -lt 2)) {
            Write-Host "  ERRO: Python $major.$minor.$patch encontrado. MyTools requer Python 3.14.2+." -ForegroundColor Red
            exit 1
        }
    }
} catch {
    Write-Host "  ERRO: Python nao encontrado. Instale Python 3.14.2+ e adicione ao PATH." -ForegroundColor Red
    exit 1
}

# Verificar/Instalar uv
Write-Host "[2/4] Verificando uv..." -ForegroundColor Yellow
try {
    $uvVersion = uv --version 2>&1
    if ($uvVersion -match "uv (\d+)\.(\d+)\.") {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
        if ($major -lt 0 -or ($major -eq 0 -and $minor -lt 12)) {
            Write-Host "  ERRO: uv $uvVersion encontrado. MyTools requer uv 0.12.1+." -ForegroundColor Red
            Write-Host "  Atualize com: pip install --upgrade uv" -ForegroundColor Yellow
            exit 1
        }
    }
    Write-Host "  OK: $uvVersion" -ForegroundColor Green
} catch {
    Write-Host "  uv nao encontrado. Instalando..." -ForegroundColor Yellow
    pip install uv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERRO: Falha ao instalar uv." -ForegroundColor Red
        exit 1
    }
    Write-Host "  uv instalado com sucesso." -ForegroundColor Green
}

# Instalar dependencias
Write-Host "[3/4] Instalando dependencias..." -ForegroundColor Yellow
uv sync
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERRO: Falha ao instalar dependencias." -ForegroundColor Red
    exit 1
}
Write-Host "  OK: Dependencias instaladas." -ForegroundColor Green

# Adicionar ao PATH
Write-Host "[4/4] Configurando PATH..." -ForegroundColor Yellow
$venvScripts = Join-Path $PSScriptRoot ".venv\Scripts"
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentPath -notlike "*$venvScripts*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$venvScripts", "User")
    Write-Host "  OK: PATH atualizado." -ForegroundColor Green
} else {
    Write-Host "  OK: PATH ja configurado." -ForegroundColor Green
}

# Resultado
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Instalacao concluida!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Abra um NOVO terminal e execute:" -ForegroundColor Cyan
Write-Host "    mytools --version" -ForegroundColor White
Write-Host "    mytools" -ForegroundColor White
Write-Host ""
Write-Host "  Ou use 'uv run mytools' neste terminal." -ForegroundColor DarkGray
Write-Host ""
