# -*- coding: utf-8 -*-
"""
scanner.py - Nucleo de recon. Logica reutilizable por el backend web.

   USO EXCLUSIVO PARA AUDITORIA / PENTESTING AUTORIZADO POR ESCRITO.

Expone scan(domain, validate=True) -> dict con todos los datos:
  - registros DNS (A, AAAA, MX, NS, TXT, SPF)
  - subdominios (Certificate Transparency / crt.sh)
  - deteccion de Cloudflare
  - IPs candidatas a origen + validacion por Host header
"""

import concurrent.futures
import hashlib
import ipaddress
import re
import socket
import ssl
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
import urllib3

try:
    import dns.resolver  # dnspython: registros MX/TXT/NS/SPF
    _HAS_DNS = True
except ImportError:
    _HAS_DNS = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) origin-scanner/1.0"

CF_IPV4_URL = "https://www.cloudflare.com/ips-v4"
CF_IPV6_URL = "https://www.cloudflare.com/ips-v6"
CF_FALLBACK_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
CF_FALLBACK_V6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
CF_BLOCK_MARKERS = (
    "cf-ray", "attention required", "cloudflare", "__cf_chl",
    "error 1020", "direct ip access not allowed",
)

# Cache en memoria de los rangos de Cloudflare (se recargan 1 vez por proceso).
_CF_NETS_CACHE = None


# --------------------------------------------------------------------------- #
#  DNS
# --------------------------------------------------------------------------- #

def dns_records(domain):
    """Devuelve dict con registros DNS clave. Usa dnspython si esta disponible."""
    out = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "SPF": []}

    # A / AAAA siempre via socket (no requiere dnspython).
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(domain, None):
            ip = sockaddr[0]
            key = "AAAA" if ":" in ip else "A"
            if ip not in out[key]:
                out[key].append(ip)
    except (socket.gaierror, OSError):
        pass

    if not _HAS_DNS:
        return out

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 8
    for rtype in ("MX", "NS", "TXT"):
        try:
            ans = resolver.resolve(domain, rtype)
            for r in ans:
                val = r.to_text().strip('"')
                out[rtype].append(val)
                # El SPF vive dentro de un TXT: nos interesa porque el correo
                # suele salir del origen real, no de Cloudflare.
                if rtype == "TXT" and val.lower().startswith("v=spf1"):
                    out["SPF"].append(val)
        except Exception:
            pass
    return out


# --------------------------------------------------------------------------- #
#  Certificate Transparency (crt.sh)
# --------------------------------------------------------------------------- #

def crtsh_subdomains(domain, timeout=25, retries=2):
    """Subdominios vistos en certificados (crt.sh)."""
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    hosts = set()
    for intento in range(1, retries + 1):
        try:
            r = requests.get(url, params=params, headers={"User-Agent": USER_AGENT},
                             timeout=timeout)
            if r.status_code != 200 or not r.text.strip():
                raise requests.RequestException(f"HTTP {r.status_code}")
            data = r.json()
            break
        except Exception:
            if intento == retries:
                return sorted(hosts)
            time.sleep(2)
    for entry in data:
        raw = entry.get("name_value", "") + "\n" + entry.get("common_name", "")
        for name in raw.split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and (name == domain or name.endswith("." + domain)):
                hosts.add(name)
    hosts.add(domain)
    return sorted(hosts)


# --------------------------------------------------------------------------- #
#  Cloudflare
# --------------------------------------------------------------------------- #

def load_cf_networks(timeout=10):
    global _CF_NETS_CACHE
    if _CF_NETS_CACHE is not None:
        return _CF_NETS_CACHE
    nets = []
    try:
        for u in (CF_IPV4_URL, CF_IPV6_URL):
            r = requests.get(u, headers={"User-Agent": USER_AGENT}, timeout=timeout)
            r.raise_for_status()
            for line in r.text.splitlines():
                if line.strip():
                    nets.append(ipaddress.ip_network(line.strip(), strict=False))
    except Exception:
        nets = [ipaddress.ip_network(c, strict=False)
                for c in CF_FALLBACK_V4 + CF_FALLBACK_V6]
    _CF_NETS_CACHE = nets
    return nets


def is_cf_ip(ip_str, cf_nets):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in n for n in cf_nets)


# --------------------------------------------------------------------------- #
#  Resolucion de hosts + validacion de origen
# --------------------------------------------------------------------------- #

def resolve_host(host):
    ips = set()
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(host, None):
            ips.add(sa[0])
    except (socket.gaierror, OSError, UnicodeError):
        pass
    return host, ips


class SNIAdapter(HTTPAdapter):
    """Fuerza el SNI al dominio aunque conectemos a una IP cruda."""
    def __init__(self, server_hostname, *a, **k):
        self._sni = server_hostname
        super().__init__(*a, **k)

    def init_poolmanager(self, connections, maxsize, block=False, **kw):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kw["ssl_context"] = ctx
        kw["server_hostname"] = self._sni
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize,
                                       block=block, **kw)


def _title(text):
    m = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
    return m.group(1).strip()[:120] if m else ""


def _fingerprint(text):
    norm = re.sub(r"\s+", " ", text or "").strip()
    return hashlib.sha256(norm.encode("utf-8", "ignore")).hexdigest()


def get_baseline(domain, timeout=12):
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{domain}/",
                             headers={"User-Agent": USER_AGENT},
                             timeout=timeout, allow_redirects=True)
            return {"status": r.status_code, "length": len(r.content),
                    "title": _title(r.text), "fingerprint": _fingerprint(r.text),
                    "server": r.headers.get("Server", "")}
        except requests.RequestException:
            continue
    return None


def _cf_block(resp):
    blob = (" ".join(f"{k}:{v}" for k, v in resp.headers.items())
            + (resp.text or "")[:3000]).lower()
    return any(m in blob for m in CF_BLOCK_MARKERS)


def _score(baseline, status, length, title, fp):
    if baseline is None:
        return 0.0
    if fp == baseline["fingerprint"]:
        return 1.0
    s = 0.0
    if title and title == baseline["title"]:
        s += 0.55
    if baseline["length"] > 0:
        s += 0.35 * (min(length, baseline["length"]) / max(length, baseline["length"]))
    if status == baseline["status"]:
        s += 0.10
    return round(s, 3)


def validate_ip(ip, domain, baseline, timeout=8):
    res = {"ip": ip, "reachable": False, "cf_block": False, "scheme": None,
           "status": None, "length": None, "title": None, "score": 0.0,
           "verdict": "no-origin"}
    for scheme in ("https", "http"):
        sess = requests.Session()
        if scheme == "https":
            sess.mount("https://", SNIAdapter(server_hostname=domain))
        try:
            r = sess.get(f"{scheme}://{ip}/", headers={"Host": domain, "User-Agent": USER_AGENT},
                         timeout=timeout, allow_redirects=False, verify=False)
        except requests.RequestException:
            continue
        finally:
            sess.close()
        res["reachable"] = True
        if _cf_block(r):
            res["cf_block"] = True
            continue
        sc = _score(baseline, r.status_code, len(r.content), _title(r.text), _fingerprint(r.text))
        if sc > res["score"]:
            res.update({"scheme": scheme, "status": r.status_code,
                        "length": len(r.content), "title": _title(r.text), "score": sc})
    if res["score"] >= 0.9:
        res["verdict"] = "origin-confirmado"
    elif res["score"] >= 0.6:
        res["verdict"] = "origin-probable"
    elif res["reachable"]:
        res["verdict"] = "responde-distinto"
    return res


# --------------------------------------------------------------------------- #
#  Orquestador principal
# --------------------------------------------------------------------------- #

def scan(domain, validate=True, max_candidates=40):
    """Ejecuta el recon completo y devuelve un dict serializable a JSON."""
    domain = domain.strip().lower().lstrip(".")
    t0 = time.time()
    cf_nets = load_cf_networks()

    records = dns_records(domain)
    subs = crtsh_subdomains(domain)

    # Resolver subdominios en paralelo.
    host_ip = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        for host, ips in pool.map(resolve_host, subs):
            if ips:
                host_ip[host] = sorted(ips)

    # Separar IPs de Cloudflare de las candidatas a origen.
    all_ips = {ip for ips in host_ip.values() for ip in ips}
    cf_ips = sorted(ip for ip in all_ips if is_cf_ip(ip, cf_nets))
    candidate_ips = sorted(ip for ip in all_ips if not is_cf_ip(ip, cf_nets))

    behind_cf = len(cf_ips) > 0

    # Validacion opcional (lo activo/activa el frontend).
    validations = []
    if validate and candidate_ips:
        baseline = get_baseline(domain)
        targets = candidate_ips[:max_candidates]
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            validations = list(pool.map(lambda ip: validate_ip(ip, domain, baseline), targets))
        # Adjuntar que hosts apuntan a cada IP.
        rev = {}
        for h, ips in host_ip.items():
            for ip in ips:
                rev.setdefault(ip, []).append(h)
        for v in validations:
            v["hosts"] = sorted(rev.get(v["ip"], []))
        validations.sort(key=lambda v: v["score"], reverse=True)

    return {
        "domain": domain,
        "elapsed": round(time.time() - t0, 1),
        "behind_cloudflare": behind_cf,
        "dns": records,
        "subdomains": subs,
        "subdomain_count": len(subs),
        "cloudflare_ips": cf_ips,
        "candidate_ips": candidate_ips,
        "candidate_count": len(candidate_ips),
        "host_ip_map": host_ip,
        "validations": validations,
        "disclaimer": "Uso exclusivo para pentesting autorizado por escrito.",
    }
