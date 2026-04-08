# ProxyZin — validador assíncrono de proxies

Script Python (**ProxyZin**) para coletar proxies de uma ou mais fontes (texto ou JSON), validar **HTTP**, **HTTPS** e opcionalmente **SOCKS4/SOCKS5** com `asyncio` + `aiohttp`, detectar vazamento de IP, exportar resultados e opcionalmente geolocalizar.

**Entrada principal:** `proxyzin.py` (o antigo `proxy_validator.py` foi descontinuado).

## Recursos

- Multi-fonte: `-s` / `--source-url` aceita **várias URLs separadas por vírgula** (listas texto ou JSON estilo Geonode).
- Validação com juiz configurável (`-j`), rotação/fallback entre juízes e limite de taxa (`-r`).
- `--try-socks` / `-S`: testa também `socks4` e `socks5` (depende de `aiohttp-socks`).
- Semáforo global de concorrência, writer incremental (`-m append`) e diagnóstico com `rich`.
- CSV opcional (`-d`) com `protocol`, `origin_ip`, `location`, `judge_url`.
- Geo opcional (`-g`) via `ip-api`.

## Requisitos

- Python 3.10+

Dependências: `aiohttp`, `aiohttp-socks`, `rich`.

## Instalação rápida

### Clone via HTTPS

```bash
git clone https://github.com/zGordola1/proxy-validator-async.git
cd proxy-validator-async
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python proxyzin.py --help
```

No Windows (PowerShell), ative o venv com: `.venv\Scripts\activate`

### Clone via SSH

```bash
git clone git@github.com:zGordola1/proxy-validator-async.git
cd proxy-validator-async
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python proxyzin.py --help
```

## Uso rápido

```bash
python proxyzin.py --help
```

Exemplo com atalhos:

```bash
python proxyzin.py -w 20 -c 30 -t 8 -o proxies_validados.txt -r 10 -m append
```

## Atalhos da CLI

| Atalho | Opção longa |
|--------|-------------|
| `-w` | `--workers` |
| `-c` | `--max-connections` |
| `-t` | `--timeout` |
| `-o` | `--output` |
| `-s` | `--source-url` |
| `-j` | `--judge-url` |
| `-r` | `--requests-per-second` |
| `-m` | `--write-mode` |
| `-S` | `--try-socks` |
| `-q` | `--no-banner` |
| `-g` | `--enable-geo` |
| `-P` | `--geo-provider` |
| `-y` | `--geo-timeout` |
| `-K` | `--geo-max-concurrent` |
| `-d` | `--detail-output` |

## Multi-fonte (texto + JSON)

Mesclagem sem duplicar `host:port`:

```bash
python proxyzin.py -s "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all,https://proxylist.geonode.com/api/proxy?limit=200&page=1&sort_by=lastChecked&sort_type=desc"
```

## SOCKS4 / SOCKS5

```bash
python proxyzin.py -S -w 20 -r 8
```

## Geolocalização e CSV

```bash
python proxyzin.py -g -d proxies_validados_detalhado.csv -y 3 -K 8
```

## Fluxo de validação

1. Baixa e unifica listas das URLs em `-s`.
2. Obtém IP baseline sem proxy (fallback entre juízes em `-j`).
3. Para cada proxy, testa `http` e `https` (e, com `-S`, `socks4` e `socks5`).
4. Aprova se HTTP 200, JSON com `origin` parseável e sem vazamento do baseline.
5. Persiste linhas aprovadas em `-o`; opcionalmente CSV em `-d` e geo com `-g`.

## Diagnóstico

Motivos comuns: `ok_http`, `ok_https`, `ok_socks4`, `ok_socks5`, `timeout`, `client_error`, `ip_leak_detected`, `judge_blocked_or_non_json`, etc.
