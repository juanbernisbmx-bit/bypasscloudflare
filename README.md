# origin::scanner

Web app estilo Shodan para descubrir y validar la **IP de origen** de un
dominio protegido por Cloudflare.

> **USO EXCLUSIVO PARA AUDITORIA / PENTESTING AUTORIZADO POR ESCRITO.**
> No lo ejecutes contra dominios de terceros sin permiso explicito.

## Que hace

Metes un dominio en la web y el backend devuelve:

- **Registros DNS**: A, AAAA, MX, NS, TXT y **SPF** (el correo suele salir del
  origen real, no de Cloudflare — de ahi su valor).
- **Subdominios** vistos en Certificate Transparency (crt.sh).
- **Deteccion de Cloudflare**: separa las IPs de rangos CF de las candidatas.
- **IPs candidatas a origen**, validadas con peticion directa + cabecera `Host`
  inyectada, comparadas contra la linea base que pasa por Cloudflare. Marca
  cada una como `confirmado` / `probable` / `responde` / `bloqueo CF`.

## Arquitectura

```
navegador  ->  Flask (app.py)  ->  scanner.py  ->  DNS / crt.sh / IPs directas
 (frontend)     (backend API)      (nucleo recon)
```

Una pagina web NO puede hacer esto sola: el navegador no resuelve DNS, no abre
sockets crudos ni inyecta la cabecera `Host`. Por eso hay un backend.

## Instalar y ejecutar

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
python3 app.py
```

Abre http://127.0.0.1:5000

> **Importante:** necesita salida a internet SIN proxy/sandbox (DNS crudo y
> conexiones directas a IPs). En entornos restringidos los escaneos salen
> vacios. Corre esto en tu maquina o un VPS.

## Uso desde terminal (CLI)

Mismo motor, sin navegador:

```bash
source venv/bin/activate
python3 cli.py objetivo.com                 # recon completo + validacion
python3 cli.py objetivo.com --no-validate   # solo pasivo (no toca las IPs)
python3 cli.py objetivo.com -o reporte.json
python3 cli.py objetivo.com -o reporte.csv --format csv
python3 cli.py objetivo.com --yes --no-color    # sin prompt, sin colores (scripts)
```

## API

```
GET /api/scan?domain=objetivo.com          # recon completo (incluye validacion activa)
GET /api/scan?domain=objetivo.com&validate=0   # solo pasivo (sin tocar IPs)
```

## Limitaciones honestas

- Si el origen filtra por IPs de Cloudflare (mTLS / Authenticated Origin Pulls)
  o usa Cloudflare Tunnel, **no hay IP de origen publica** que encontrar.
- crt.sh devuelve certificados historicos: muchas IPs seran obsoletas.
- Siguiente mejora de mayor retorno: busqueda por hash de favicon / certificado
  en Shodan / Censys (requiere API key).
