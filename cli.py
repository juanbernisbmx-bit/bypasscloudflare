#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cli.py - Uso desde terminal del mismo motor de recon (scanner.py).

   USO EXCLUSIVO PARA AUDITORIA / PENTESTING AUTORIZADO POR ESCRITO.

Ejemplos:
    python3 cli.py objetivo.com
    python3 cli.py objetivo.com --no-validate          # solo recon pasivo
    python3 cli.py objetivo.com -o reporte.json         # guarda JSON
    python3 cli.py objetivo.com -o reporte.csv --format csv
    python3 cli.py objetivo.com --no-color              # sin colores ANSI
"""

import argparse
import csv
import json
import sys

import scanner


# Colores ANSI (se desactivan con --no-color o si la salida no es un TTY).
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    GREEN = "\033[92m"; CYAN = "\033[96m"; YELLOW = "\033[93m"; RED = "\033[91m"

    @classmethod
    def off(cls):
        for a in ("RESET", "BOLD", "DIM", "GREEN", "CYAN", "YELLOW", "RED"):
            setattr(cls, a, "")


VERDICT_COLOR = {
    "origin-confirmado": ("GREEN", "[CONFIRMADO]"),
    "origin-probable":   ("CYAN",  "[PROBABLE] "),
    "responde-distinto": ("YELLOW", "[responde] "),
    "no-origin":         ("DIM",   "[   -     ]"),
}


def hr(title):
    print(f"\n{C.BOLD}{C.CYAN}== {title} =={C.RESET}")


def print_report(d):
    cf = f"{C.YELLOW}SI{C.RESET}" if d["behind_cloudflare"] else f"{C.GREEN}NO{C.RESET}"
    print(f"\n{C.BOLD}Dominio:{C.RESET} {d['domain']}   "
          f"{C.BOLD}Tras Cloudflare:{C.RESET} {cf}   "
          f"{C.DIM}({d['elapsed']}s){C.RESET}")
    print(f"{C.DIM}Subdominios: {d['subdomain_count']}  |  "
          f"IPs candidatas: {d['candidate_count']}{C.RESET}")

    # DNS
    hr("Registros DNS")
    any_rec = False
    for k in ("A", "AAAA", "MX", "NS", "SPF", "TXT"):
        for v in d["dns"].get(k, []):
            print(f"  {C.BOLD}{k:<5}{C.RESET} {v}")
            any_rec = True
    if not any_rec:
        print(f"  {C.DIM}(ninguno){C.RESET}")

    # Validaciones / candidatas
    if d.get("validations"):
        hr("IPs candidatas a origen")
        for v in d["validations"]:
            if v["cf_block"]:
                col, label = "YELLOW", "[BLOQUEO CF]"
            else:
                cname, label = VERDICT_COLOR[v["verdict"]]
                col = cname
            color = getattr(C, col)
            extra = []
            if v["status"]:
                extra.append(f"HTTP {v['status']}")
            if v.get("matched_host"):
                extra.append(f"match={v['matched_host']}")
            if v["title"]:
                extra.append(v["title"])
            src = v.get("sources") or v.get("hosts") or []
            srctxt = (" <- " + ", ".join(src)) if src else ""
            print(f"  {color}{label}{C.RESET} {C.BOLD}{v['ip']:<16}{C.RESET} "
                  f"score={v['score']} {C.DIM}{' · '.join(extra)}{srctxt}{C.RESET}")
    elif d.get("candidate_ips"):
        hr("IPs candidatas (sin validar)")
        for ip in d["candidate_ips"]:
            print(f"  {ip}")

    # Infraestructura de correo (MX/SPF) -- el correo suele salir del origen real
    if d.get("mail_ips"):
        hr("IPs de correo (MX/SPF)")
        for m in d["mail_ips"]:
            print(f"  {m['ip']:<16} {C.DIM}{', '.join(m['sources'])}{C.RESET}")
    if d.get("spf_ranges"):
        print(f"  {C.DIM}rangos SPF (no expandidos): {', '.join(d['spf_ranges'])}{C.RESET}")

    # Cloudflare descartadas
    if d.get("cloudflare_ips"):
        hr("IPs de Cloudflare (descartadas)")
        print("  " + ", ".join(d["cloudflare_ips"]))

    # Resumen
    hits = [v for v in d.get("validations", []) if v["verdict"].startswith("origin")]
    if hits:
        print(f"\n{C.GREEN}{C.BOLD}[+] {len(hits)} IP(s) de origen probable/confirmado:{C.RESET}")
        for v in hits:
            print(f"    -> {v['ip']}  ({v['verdict']}, score {v['score']})")
    else:
        print(f"\n{C.DIM}[-] Sin IP de origen clara. "
              f"Prueba MX/SPF, DNS historico o favicon/Shodan.{C.RESET}")


def save(d, path, fmt):
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2, ensure_ascii=False)
    else:
        rows = d.get("validations") or [{"ip": ip} for ip in d.get("candidate_ips", [])]
        fields = ["ip", "verdict", "score", "scheme", "status", "length",
                  "title", "cf_block", "reachable", "hosts"]
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                row = dict(r)
                row["hosts"] = ";".join(r.get("hosts", []))
                w.writerow(row)
    print(f"[+] Reporte guardado en: {path}")


def main():
    p = argparse.ArgumentParser(
        prog="cli.py",
        description="Recon de IP de origen tras Cloudflare (solo pentesting autorizado).")
    p.add_argument("domain", help="Dominio objetivo.")
    p.add_argument("--no-validate", action="store_true",
                   help="Omite la fase activa (no toca las IPs candidatas).")
    p.add_argument("--subdomains-file",
                   help="Usa subdominios de un archivo (uno por linea) en vez de "
                        "crt.sh. Util con amass/subfinder o en el laboratorio.")
    p.add_argument("-o", "--output", help="Archivo de reporte de salida.")
    p.add_argument("--format", choices=("json", "csv"), default="json")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--yes", action="store_true",
                   help="Omite la confirmacion de autorizacion.")
    args = p.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.off()

    if not args.yes:
        print("USO EXCLUSIVO PARA AUDITORIA / PENTESTING AUTORIZADO POR ESCRITO.")
        if input(f"Confirmas autorizacion para '{args.domain}'? (si/no): "
                 ).strip().lower() not in ("si", "s", "yes", "y"):
            sys.exit("[!] Cancelado.")

    print(f"[*] Escaneando {args.domain} ... (crt.sh puede tardar)")
    subs = None
    if args.subdomains_file:
        with open(args.subdomains_file, encoding="utf-8") as f:
            subs = [line for line in f.read().splitlines()]
    d = scanner.scan(args.domain, validate=not args.no_validate, subdomains=subs)
    print_report(d)
    if args.output:
        save(d, args.output, args.format)


if __name__ == "__main__":
    main()
