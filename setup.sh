#!/usr/bin/env bash
# MyTools — Script de instalacao (Linux/Mac)
# Executa: chmod +x setup.sh && ./setup.sh

set -euo pipefail

VERSION=$(grep '^version' pyproject.toml | head -1 | cut -d'"' -f2)

echo ""
echo "========================================"
echo "  MyTools v${VERSION} — Instalador"
echo "========================================"
echo ""

# Verificar Python
echo "[1/4] Verificando Python..."
if command -v python3 &>/dev/null; then
    PY="python3"
elif command -v python &>/dev/null; then
    PY="python"
else
    echo "  ERRO: Python nao encontrado. Instale Python 3.14.2+."
    exit 1
fi
echo "  OK: $($PY --version)"

# Validate Python version >= 3.14.2
PY_VER=$($PY -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")
PY_MAJOR=$($PY -c "import sys; print(sys.version_info.major)")
PY_MINOR=$($PY -c "import sys; print(sys.version_info.minor)")
PY_PATCH=$($PY -c "import sys; print(sys.version_info.micro)")
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 14 ]; } || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -eq 14 ] && [ "$PY_PATCH" -lt 2 ]; }; then
    echo "  ERRO: Python $PY_VER encontrado. MyTools requer Python 3.14.2+."
    exit 1
fi

# Verificar/Instalar Poetry
echo "[2/4] Verificando Poetry..."
if command -v poetry &>/dev/null; then
    echo "  OK: $(poetry --version)"
else
    echo "  Poetry nao encontrado. Instalando..."
    $PY -m pip install poetry
    echo "  Poetry instalado com sucesso."
fi

# Instalar dependencias
echo "[3/4] Instalando dependencias..."
poetry install --with dev
echo "  OK: Dependencias instaladas."

# Adicionar ao PATH
echo "[4/4] Configurando PATH..."
VENV_PATH=$(poetry env info --path 2>/dev/null)
if [ -z "$VENV_PATH" ]; then
    echo "  AVISO: Nao foi possivel detectar o venv. Use 'poetry run mytools' para executar."
else
    VENV_BIN="$VENV_PATH/bin"
    SHELL_RC=""
    if [ -f "$HOME/.bashrc" ]; then
        SHELL_RC="$HOME/.bashrc"
    elif [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    fi

    if [ -n "$SHELL_RC" ]; then
        if ! grep -q "$VENV_BIN" "$SHELL_RC" 2>/dev/null; then
            echo "" >> "$SHELL_RC"
            echo "# MyTools" >> "$SHELL_RC"
            echo "export PATH=\"$VENV_BIN:\$PATH\"" >> "$SHELL_RC"
            echo "  OK: PATH atualizado em $SHELL_RC"
        else
            echo "  OK: PATH ja configurado."
        fi
    else
        echo "  AVISO: Shell RC nao encontrado. Adicione manualmente: export PATH=\"$VENV_BIN:\$PATH\""
    fi
fi

# Resultado
echo ""
echo "========================================"
echo "  Instalacao concluida!"
echo "========================================"
echo ""
echo "  Abra um NOVO terminal e execute:"
echo "    mytools --version"
echo "    mytools"
echo ""
echo "  Ou use 'poetry run mytools' neste terminal."
echo ""
