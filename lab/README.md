# Laboratorio `bataedu.lab`

Entorno **local y ficticio** para practicar el descubrimiento de IP de origen
sin tocar infraestructura real. Reproduce el escenario tipico: un apex detras
de un "Cloudflare" y subdominios (`admin`/`api`/`auth`) que se fugan directo al
servidor de origen.

> Todo corre en tu maquina, en una red Docker aislada. Nada sale a Internet.

## Topologia

| Servicio | IP (red lab)  | Rol |
|----------|---------------|-----|
| `dns`    | 172.28.0.53   | dnsmasq con la zona `bataedu.lab` |
| `edge`   | 172.28.0.10   | nginx que simula Cloudflare (mete `cf-ray`, pagina de bloqueo) |
| `origin` | 172.28.0.20   | el servidor REAL a descubrir: web 80/443 + FTP 21 + SSH 2222 |
| `mail`   | 172.28.0.30   | solo existe en DNS (MX/SPF); no sirve web |
| `scanner`| 172.28.0.40   | corre la herramienta usando el DNS del lab |

`admin/api/auth/n8n.bataedu.lab` resuelven **directo** al origen (la fuga).
El apex `bataedu.lab` resuelve al edge.

## Levantarlo

```bash
cd lab
docker compose up --build -d        # dns, edge, origin
```

## Correr la herramienta contra el lab

La herramienta corre en un contenedor dentro de la red del lab (usa su DNS):

```bash
docker compose run --rm scanner
```

Esto ejecuta, por dentro:
```
python cli.py bataedu.lab --subdomains-file lab/subdomains.txt --yes --no-color
```
(usa `--subdomains-file` porque `crt.sh` no conoce un dominio ficticio).

### Qué deberias ver

- `172.28.0.20` (origin) -> **origin-confirmado / score 1.0**, `match=admin.bataedu.lab`
  (sirve la app "Bata Edu | Aplicacion", sin `cf-ray`).
- `172.28.0.10` (edge)   -> **BLOQUEO CF** (responde con `cf-ray` y la pagina
  de "Attention Required").
- `172.28.0.30` (mail)   -> aparece como candidata por MX/SPF pero no sirve web
  => `no-origin`. Ejemplo perfecto de por que la validacion web filtra el correo.

## Practicar nmap desde el host (tu Mac)

Los puertos del origen estan publicados en `localhost`:

```bash
nmap -sV -p2121,2222,8080,8443 127.0.0.1
#   2121 -> FTP (21)    2222 -> SSH    8080 -> HTTP (80)    8443 -> HTTPS (443)
```
Probá tambien `--script ftp-anon` contra el 2121: el FTP tiene anonimo de solo
lectura a proposito.

> En Docker Desktop (Mac/Windows) las IPs `172.28.0.x` NO son alcanzables desde
> el host; por eso nmap va contra `127.0.0.1` y los puertos publicados. La
> herramienta, en cambio, corre DENTRO de la red y si ve las IPs reales.

## Bajarlo

```bash
docker compose down            # agrega -v si querés borrar volumenes
```

## Notas honestas (lo que el lab NO reproduce)

- **Filtrado por rango CIDR de Cloudflare.** El edge usa una IP privada, no un
  rango real de Cloudflare, asi que la herramienta no lo descarta por IP: lo
  detecta por la pagina de bloqueo (`cf-ray`). Por eso `behind_cloudflare`
  puede figurar como `NO` aunque el edge se comporte como CF. En la realidad,
  la IP del edge caeria en los rangos de CF y se filtraria por ahi.
- **crt.sh.** No se puede simular para un dominio ficticio; por eso alimentamos
  los subdominios con `--subdomains-file`.
- **El SSH 2222** aca es OpenSSH, no el servidor en Go del caso real. Lo que
  importa para practicar es el puerto/servicio, no el banner exacto.
- Credenciales (`labuser:labpass123`, FTP anonimo) son triviales **a proposito**:
  es un laboratorio para romper, no un modelo de servidor bien configurado.
