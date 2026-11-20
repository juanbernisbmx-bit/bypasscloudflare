#!/usr/bin/env bash
# Lanzador de la herramienta: la primera vez crea el entorno e instala las
# dependencias solo; despues arranca directo. No hace falta activar nada.
#
# Uso:
#   ./run.sh DOMINIO [opciones de cli.py]
#
# Ejemplos:
#   ./run.sh ejemplo.com --yes
#   ./run.sh bataedu.lab --subdomains-file lab/subdomains.txt --yes
set -e

# Ubicarse siempre en la carpeta del repo, se invoque desde donde se invoque.
cd "$(dirname "$0")"

# Primera ejecucion: montar el entorno virtual e instalar dependencias.
if [ ! -d venv ]; then
    echo "[*] Primera vez: creando entorno virtual e instalando dependencias..."
    python3 -m venv venv
    ./venv/bin/pip install -q -r requirements.txt
    echo "[+] Listo."
fi

# Correr la herramienta con el python del venv, pasando todos los argumentos.
exec ./venv/bin/python cli.py "$@"
