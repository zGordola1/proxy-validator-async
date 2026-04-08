# Validador avancado de proxies HTTP/HTTPS

Script Python assincrono para coletar proxies gratuitos do ProxyScrape, validar conectividade e anonimato em paralelo e exportar os proxies aprovados.

## Recursos

- Coleta automática de proxies via endpoint de texto do ProxyScrape.
- Processamento concorrente com `asyncio` + `aiohttp`.
- Limite global de conexoes simultaneas com `asyncio.Semaphore` (default: 100).
- Juiz de anonimato configuravel via `--judge-url` (um ou varios endpoints, separados por virgula).
- Limite opcional de taxa com `--requests-per-second` para reduzir rate limit.
- Barra de progresso no terminal com `rich`.
- Persistencia incremental (default `--write-mode append`) para evitar perda de progresso.
- Exportacao dos aprovados em `proxies_validados.txt`.

## Requisitos

- Python 3.10+

Instalação:

```bash
pip install -r requirements.txt
```

## Uso

Execução padrão:

```bash
python proxy_validator.py
```

Com parâmetros:

```bash
python proxy_validator.py --workers 50 --max-connections 100 --timeout 8 --output proxies_validados.txt
```

## Argumentos

- `--workers`: quantidade de workers assincronos (default: `50`)
- `--max-connections`: limite global de conexoes simultaneas (default: `100`)
- `--timeout`: timeout por request em segundos (intervalo permitido: `5` a `10`, default: `8`)
- `--output`: arquivo de saida dos proxies validados (default: `proxies_validados.txt`)
- `--source-url`: URL da fonte de proxies (default: ProxyScrape HTTP list)
- `--judge-url`: endpoint(s) do juiz para validar IP de saida, separados por virgula
- `--requests-per-second`: limite opcional de taxa de requests contra o juiz
- `--write-mode`: modo de escrita do output (`append` ou `final`, default: `append`)

## Como a validacao funciona

1. Busca lista de proxies (`host:port`) no ProxyScrape.
2. Descobre seu IP baseline sem proxy consultando a lista de juizes em fallback.
3. Testa cada proxy com esquemas `http://` e `https://`.
4. Considera valido somente quando:
   - resposta HTTP for 200;
   - JSON de resposta tiver `origin` parseavel;
   - IP visto pelo httpbin for diferente do IP baseline local.
5. Salva proxies aprovados no arquivo de saida:
   - em tempo real no modo `append`;
   - ao final no modo `final`.
6. Exibe diagnostico operacional com:
   - motivos de sucesso/falha;
   - taxa de sucesso por esquema (`ok_http`/`ok_https`);
   - telemetria por juiz (success/fail/rate);
   - estatisticas de espera do rate limiter.

## Observacoes

- Proxies gratuitos sao altamente instaveis; e normal baixa taxa de aprovacao.
- Caso `timeout` seja muito baixo, falsos negativos podem aumentar.
- Em juiz publico (`httpbin`), prefira iniciar com `--workers 20 --max-connections 30`.
- Para reduzir bloqueios, combine com `--requests-per-second 10` (ou valor menor).
- Em execucoes longas, use `--write-mode append` para nao perder resultados em interrupcao.

## Exemplos recomendados

Uso robusto em juiz publico:

```bash
python proxy_validator.py --workers 20 --max-connections 30 --requests-per-second 10 --write-mode append
```

Uso com juiz proprio:

```bash
python proxy_validator.py --judge-url http://seu-endpoint/ip --workers 30 --max-connections 50 --requests-per-second 15
```

Uso com juiz rotativo:

```bash
python proxy_validator.py --judge-url "http://seu-juiz-1/ip,http://seu-juiz-2/ip" --workers 25 --requests-per-second 8
```

## Diagnostico operacional

Ao final da execucao, o script imprime tabelas com distribuicao por `reason`, sucesso por esquema e telemetria por juiz.

Interpretacao rapida dos principais motivos:

- `ok_http` / `ok_https`: proxy aprovado no juiz.
- `timeout`: proxy nao respondeu dentro do timeout configurado.
- `client_error`: erro de conexao/protocolo com o proxy.
- `status_non_200`: juiz respondeu com status diferente de 200.
- `invalid_json`: resposta nao estava no formato JSON esperado.
- `judge_blocked_or_non_json`: bloqueio/rate limit no juiz ou resposta HTML inesperada.
- `empty_origin`: juiz respondeu sem IP util em `origin`.
- `ip_leak_detected`: vazamento de IP baseline local (proxy transparente).

Use esse resumo para ajustar `--timeout`, `--requests-per-second`, `--workers` e `--judge-url`.
