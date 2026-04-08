# ProxyZin — validador assíncrono de proxies

Script Python (**ProxyZin**) para coletar proxies de uma ou mais fontes (texto ou JSON), validar **HTTP**, **HTTPS** e opcionalmente **SOCKS4/SOCKS5** com `asyncio` + `aiohttp`, detectar vazamento de IP, exportar resultados e opcionalmente geolocalizar.

**Entrada principal:** `proxyzin.py` (o antigo `proxy_validator.py` foi descontinuado).

## Recursos

- Multi-fonte: `-s` / `--source-url` aceita **várias URLs separadas por vírgula** (listas texto ou JSON estilo Geonode); `--sources-file` lê **uma URL por linha** (comentários `#` e linhas vazias ignorados).
- Persistência opcional em **SQLite** (`--sqlite-db`), alinhada ao CSV detalhado (UPSERT por `proxy`).
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
| | `--sources-file` |
| | `--sqlite-db` |

## Fase 3: ficheiro de fontes e SQLite

**Ficheiro de URLs** (`--sources-file`, repetível para vários ficheiros):

```text
# urls.txt
https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all

https://proxylist.geonode.com/api/proxy?limit=200&page=1&sort_by=lastChecked&sort_type=desc
```

Combinar com `-s` (as URLs do CSV vêm primeiro, depois as dos ficheiros; duplicados entre fontes são ignorados na resolução de URLs):

```bash
python proxyzin.py -s "https://exemplo.com/lista1" --sources-file urls.txt
```

**SQLite** (tabela `validated_proxies`: `proxy`, `protocol`, `origin_ip`, `location`, `judge_url`, `validated_at` UTC). Não exige `-d` / `-g`:

```bash
python proxyzin.py --sqlite-db proxies_validados.db -d proxies_validados_detalhado.csv
```

Se não passar `-s` nem `--sources-file`, mantém-se o fallback para a fonte default ProxyScrape.

## Multi-fonte (texto + JSON)

Mesclagem sem duplicar `host:port`:

```bash
python proxyzin.py -s "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all,https://proxylist.geonode.com/api/proxy?limit=200&page=1&sort_by=lastChecked&sort_type=desc"
```

## SOCKS4 / SOCKS5

Com `-S`, o `aiohttp` negocia `socks4://` e `socks5://` contra o juiz; o pacote **`aiohttp-socks`** tem de estar instalado (o script importa-o no arranque só para confirmar que o conector suporta SOCKS).

```bash
python proxyzin.py -S -w 20 -r 8
```

## Geolocalização e CSV

```bash
python proxyzin.py -g -d proxies_validados_detalhado.csv -y 3 -K 8
```

## Fluxo de validação

1. Baixa e unifica listas das URLs em `-s`, `--sources-file` ou ambos (fallback ProxyScrape se nenhum for dado).
2. Obtém IP baseline sem proxy (fallback entre juízes em `-j`).
3. Para cada proxy, testa `http` e `https` (e, com `-S`, `socks4` e `socks5`).
4. Aprova se HTTP 200, JSON com `origin` parseável e sem vazamento do baseline.
5. Persiste linhas aprovadas em `-o`; opcionalmente CSV em `-d`, SQLite em `--sqlite-db` e geo com `-g`.

## Desenvolvimento e testes

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

## Docker

```bash
docker build -t proxyzin .
docker run --rm proxyzin -q --help
```

## CI

O repositório inclui [`.github/workflows/ci.yml`](.github/workflows/ci.yml): em cada push/PR para `main`, corre `py_compile` e `pytest` em Python 3.10 e 3.12.

## Comportamento e limitações (a conhecer)

1. **Fontes que falham** — Se o download de uma URL em `-s` / `--sources-file` falhar, o ProxyZin continua com as outras e mostra um **aviso** no terminal com URL e tipo de erro (não aborta a execução por uma fonte isolada).
2. **IPv6** — Em listas texto, use **`[IPv6]:porta`** (ex.: `[2001:db8::1]:8080`). Endereços IPv6 são guardados nesse formato para o URL do proxy ser válido. Em JSON (ex. Geonode), IPv6 é normalizado automaticamente quando possível.
3. **Juiz (`-j`)** — O default (`httpbin.org/ip`) pode sofrer **rate limit** ou indisponibilidade. Podes passar **vários** endpoints separados por vírgula; o baseline e os testes fazem rotação/fallback. O juiz tem de devolver **JSON com campo `origin`** no mesmo estilo do httpbin; APIs só com `ip` (ex. ipify) **não** são compatíveis sem alterar o código.
4. **SOCKS** — Ver secção SOCKS acima: dependência `aiohttp-socks` e import no arranque.

## Diagnóstico

Motivos comuns de contagem na tabela `rich`: `ok_http`, `ok_https`, `ok_socks4`, `ok_socks5`, `timeout`, `client_error`, `ip_leak_detected`, `judge_blocked_or_non_json`, etc.
