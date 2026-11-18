# -*- coding: utf-8 -*-
"""
app.py - Backend web (Flask) estilo Shodan para recon de IP de origen.

   USO EXCLUSIVO PARA AUDITORIA / PENTESTING AUTORIZADO POR ESCRITO.

Levanta:
  GET  /                      -> interfaz web
  GET  /api/scan?domain=...   -> JSON con todo el recon
                                 (&validate=0 para omitir la fase activa)

Ejecutar:
    pip install -r requirements.txt
    python3 app.py
    -> http://127.0.0.1:5000
"""

from flask import Flask, jsonify, render_template, request

import scanner

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan")
def api_scan():
    domain = (request.args.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "Falta el parametro 'domain'."}), 400

    # La fase de validacion (Host header directo a la IP) es la parte ACTIVA.
    # El frontend puede desactivarla con validate=0 para un recon solo pasivo.
    validate = request.args.get("validate", "1") != "0"

    try:
        result = scanner.scan(domain, validate=validate)
        return jsonify(result)
    except Exception as e:  # noqa: BLE001 - devolvemos el error al cliente
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500


if __name__ == "__main__":
    # host 0.0.0.0 para que sea accesible desde el panel de vista previa.
    app.run(host="0.0.0.0", port=5000, debug=False)
