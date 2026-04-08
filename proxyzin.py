from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import aiohttp
from aiohttp import ClientError, ClientSession, ClientTimeout

try:
    import aiohttp_socks  # noqa: F401 — suporte a proxy socks4/socks5 no ClientSession

    SOCKS_AVAILABLE = True
except ImportError:
    aiohttp_socks = None  # type: ignore[assignment]
    SOCKS_AVAILABLE = False
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

PROXYSCRAPE_URL = (
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all"
)
# Exemplo de fonte JSON (Geonode); combine com -s "url1,url2"
PROXY_GEONODE_SAMPLE = (
    "https://proxylist.geonode.com/api/proxy?limit=200&page=1&sort_by=lastChecked&sort_type=desc"
)
JUDGE_URL = "http://httpbin.org/ip"
REASON_PROTOCOL_LABELS: Final[dict[str, str]] = {
    "ok_http": "HTTP",
    "ok_https": "HTTPS",
    "ok_socks4": "SOCKS4",
    "ok_socks5": "SOCKS5",
}
WRITE_MODES: Final[set[str]] = {"append", "final"}
GEO_PROVIDERS: Final[set[str]] = {"ip-api"}

PROXYZIN_BANNER = r"""
__________                             __________.__
\______   \_______  _______  ______.__.\____    /|__| ____
 |     ___/\_  __ \/  _ \  \/  <   |  |  /     / |  |/    \
 |    |     |  | \(  <_> >    < \___  | /     /_ |  |   |  \
 |____|     |__|   \____/__/\_ \/ ____|/_______ \|__|___|  /
                              \/\/             \/        \/
"""


@dataclass(slots=True)
class ProxyCheckResult:
    proxy: str
    is_valid: bool
    leaked: bool
    reason: str
    judge_url: str
    protocol: str = ""
    origin_ip: str = ""
    location: str = "unknown"


@dataclass(slots=True)
class ValidProxyDetail:
    """Linha exportavel para CSV e geo pos-validacao."""

    proxy: str
    protocol: str
    origin_ip: str
    judge_url: str
    location: str = "unknown"


class AsyncRateLimiter:
    """Simple cooperative rate limiter for asyncio workers."""

    def __init__(self, requests_per_second: float) -> None:
        self._interval = 1.0 / requests_per_second
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0

    async def wait_turn(self) -> float:
        loop = asyncio.get_running_loop()
        waited_seconds = 0.0
        while True:
            async with self._lock:
                now = loop.time()
                if now >= self._next_allowed:
                    self._next_allowed = now + self._interval
                    return waited_seconds * 1000.0
                sleep_for = self._next_allowed - now
                waited_seconds += max(0.0, sleep_for)
            await asyncio.sleep(sleep_for)


@dataclass(slots=True)
class JudgePicker:
    judge_urls: list[str]
    _next_index: int = 0
    _lock: asyncio.Lock = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._lock = asyncio.Lock()

    async def next_start_index(self) -> int:
        async with self._lock:
            current = self._next_index
            self._next_index = (self._next_index + 1) % len(self.judge_urls)
            return current


def parse_proxy_lines(raw_text: str) -> list[str]:
    """Normalize and deduplicate proxy list in host:port format."""
    unique: set[str] = set()
    proxies: list[str] = []

    for line in raw_text.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        if ":" not in candidate:
            continue
        host, port = candidate.rsplit(":", maxsplit=1)
        host = host.strip()
        port = port.strip()
        if not host or not port.isdigit():
            continue
        if not (1 <= int(port) <= 65535):
            continue

        if host not in ("localhost",):
            try:
                ipaddress.ip_address(host)
            except ValueError:
                # Keep domain-based proxies as well.
                pass

        normalized = f"{host}:{port}"
        if normalized in unique:
            continue
        unique.add(normalized)
        proxies.append(normalized)
    return proxies


def pick_primary_origin_ip(seen_ips: set[str]) -> str:
    """Pick a single representative IP from the judge origin set (stable order)."""
    return min(seen_ips)


def parse_origin_ips(origin_value: str) -> set[str]:
    """Parse the origin field returned by httpbin.org/ip."""
    origins: set[str] = set()
    for part in origin_value.split(","):
        token = part.strip()
        if not token:
            continue
        try:
            parsed = ipaddress.ip_address(token)
            origins.add(str(parsed))
        except ValueError:
            # Ignore malformed addresses; some proxies include noise.
            continue
    return origins


def _proxies_from_json_body(body: object) -> list[str] | None:
    """Extrai host:port de JSON comum (ex.: Geonode `data: [{ip, port}]`)."""
    rows: list[str] = []

    def from_items(items: list[object]) -> None:
        for item in items:
            if not isinstance(item, dict):
                continue
            ip = item.get("ip") or item.get("host")
            port = item.get("port")
            if ip is None or port is None:
                continue
            rows.append(f"{str(ip).strip()}:{str(port).strip()}")

    if isinstance(body, dict):
        data = body.get("data")
        if isinstance(data, list):
            from_items(data)
    elif isinstance(body, list):
        from_items(body)

    if not rows:
        return None
    return parse_proxy_lines("\n".join(rows))


async def fetch_proxies(session: ClientSession, source_url: str) -> list[str]:
    """Baixa lista: texto (host:port por linha) ou JSON com lista de ip/port."""
    async with session.get(source_url) as response:
        response.raise_for_status()
        payload = await response.text()
    stripped = payload.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            body = json.loads(payload)
            parsed = _proxies_from_json_body(body)
            if parsed:
                return parsed
        except json.JSONDecodeError:
            pass
    return parse_proxy_lines(payload)


async def fetch_proxies_from_sources(session: ClientSession, source_urls: list[str]) -> list[str]:
    """Mescla varias URLs sem duplicar (ordem da primeira ocorrencia)."""
    unique: set[str] = set()
    merged: list[str] = []
    for url in source_urls:
        try:
            batch = await fetch_proxies(session, url)
        except Exception:
            continue
        for proxy in batch:
            if proxy in unique:
                continue
            unique.add(proxy)
            merged.append(proxy)
    return merged


def build_proxy_schemes(try_socks: bool) -> tuple[str, ...]:
    if try_socks:
        if not SOCKS_AVAILABLE:
            raise RuntimeError("SOCKS requer o pacote aiohttp-socks. Instale: pip install aiohttp-socks")
        return ("http", "https", "socks4", "socks5")
    return ("http", "https")


async def fetch_baseline_ips(session: ClientSession, timeout_seconds: float, judge_url: str) -> set[str]:
    """Get local public IP(s) without proxy for leakage detection."""
    timeout = ClientTimeout(total=timeout_seconds)
    async with session.get(judge_url, timeout=timeout) as response:
        response.raise_for_status()
        payload = await response.json(content_type=None)
    origin_value = str(payload.get("origin", ""))
    baseline = parse_origin_ips(origin_value)
    if not baseline:
        raise RuntimeError("Nao foi possivel identificar IP baseline no endpoint do juiz.")
    return baseline


async def fetch_baseline_ips_with_fallback(
    session: ClientSession,
    timeout_seconds: float,
    judge_urls: list[str],
) -> tuple[set[str], str]:
    for judge_url in judge_urls:
        try:
            baseline = await fetch_baseline_ips(
                session=session,
                timeout_seconds=timeout_seconds,
                judge_url=judge_url,
            )
            return baseline, judge_url
        except Exception:
            continue
    raise RuntimeError("Nao foi possivel identificar IP baseline em nenhum endpoint de juiz.")


async def fetch_geo_location(
    session: ClientSession,
    ip: str,
    provider: str,
    timeout_seconds: float,
) -> str:
    """Resolve location string for an IP; never raises (returns unknown on failure)."""
    timeout = ClientTimeout(total=timeout_seconds)
    try:
        if provider == "ip-api":
            url = f"http://ip-api.com/json/{ip}"
            async with session.get(url, params={"fields": "status,country,regionName,city"}, timeout=timeout) as resp:
                if resp.status != 200:
                    return "unknown"
                data = await resp.json(content_type=None)
            if str(data.get("status", "")).lower() != "success":
                return "unknown"
            country = str(data.get("country", "") or "").strip()
            region = str(data.get("regionName", "") or "").strip()
            city = str(data.get("city", "") or "").strip()
            parts = [p for p in (country, region, city) if p]
            return ", ".join(parts) if parts else "unknown"
    except Exception:
        return "unknown"
    return "unknown"


async def apply_geo_to_details(
    session: ClientSession,
    details: list[ValidProxyDetail],
    provider: str,
    timeout_seconds: float,
    max_concurrent: int,
) -> None:
    if not details:
        return
    sem = asyncio.Semaphore(max(1, max_concurrent))

    async def one(d: ValidProxyDetail) -> None:
        async with sem:
            d.location = await fetch_geo_location(session, d.origin_ip, provider, timeout_seconds)

    await asyncio.gather(*(one(d) for d in details))


async def validate_with_scheme(
    session: ClientSession,
    proxy: str,
    scheme: str,
    baseline_ips: set[str],
    timeout_seconds: float,
    judge_url: str,
    semaphore: asyncio.Semaphore,
    rate_limiter: AsyncRateLimiter | None,
) -> tuple[ProxyCheckResult, float]:
    proxy_url = f"{scheme}://{proxy}"
    timeout = ClientTimeout(total=timeout_seconds)
    waited_ms = 0.0

    try:
        if rate_limiter is not None:
            waited_ms = await rate_limiter.wait_turn()
        async with semaphore:
            async with session.get(judge_url, proxy=proxy_url, timeout=timeout) as response:
                if response.status != 200:
                    return (
                        ProxyCheckResult(
                            proxy=proxy,
                            is_valid=False,
                            leaked=False,
                            reason="status_non_200",
                            judge_url=judge_url,
                        ),
                        waited_ms,
                    )
                text_payload = await response.text()
    except asyncio.TimeoutError:
        return (
            ProxyCheckResult(proxy=proxy, is_valid=False, leaked=False, reason="timeout", judge_url=judge_url),
            waited_ms,
        )
    except ClientError:
        return (
            ProxyCheckResult(proxy=proxy, is_valid=False, leaked=False, reason="client_error", judge_url=judge_url),
            waited_ms,
        )
    except Exception:
        return (
            ProxyCheckResult(
                proxy=proxy,
                is_valid=False,
                leaked=False,
                reason="unexpected_error",
                judge_url=judge_url,
            ),
            waited_ms,
        )

    try:
        body = json.loads(text_payload)
        origin_value = str(body.get("origin", ""))
        seen_ips = parse_origin_ips(origin_value)
    except json.JSONDecodeError:
        if "<html" in text_payload.lower():
            return (
                ProxyCheckResult(
                    proxy=proxy,
                    is_valid=False,
                    leaked=False,
                    reason="judge_blocked_or_non_json",
                    judge_url=judge_url,
                ),
                waited_ms,
            )
        return (
            ProxyCheckResult(proxy=proxy, is_valid=False, leaked=False, reason="invalid_json", judge_url=judge_url),
            waited_ms,
        )

    if not seen_ips:
        return (
            ProxyCheckResult(proxy=proxy, is_valid=False, leaked=False, reason="empty_origin", judge_url=judge_url),
            waited_ms,
        )

    if seen_ips & baseline_ips:
        return (
            ProxyCheckResult(
                proxy=proxy,
                is_valid=False,
                leaked=True,
                reason="ip_leak_detected",
                judge_url=judge_url,
            ),
            waited_ms,
        )

    primary_ip = pick_primary_origin_ip(seen_ips)
    return (
        ProxyCheckResult(
            proxy=proxy,
            is_valid=True,
            leaked=False,
            reason=f"ok_{scheme}",
            judge_url=judge_url,
            protocol=scheme,
            origin_ip=primary_ip,
            location="unknown",
        ),
        waited_ms,
    )


async def validate_proxy(
    session: ClientSession,
    proxy: str,
    baseline_ips: set[str],
    timeout_seconds: float,
    judge_urls: list[str],
    start_judge_index: int,
    semaphore: asyncio.Semaphore,
    rate_limiter: AsyncRateLimiter | None,
    schemes: tuple[str, ...],
) -> tuple[ProxyCheckResult, list[tuple[str, bool]], int, float]:
    """Testa esquemas de proxy (http, https, socks4, socks5) ate o primeiro valido."""
    last_result: ProxyCheckResult | None = None
    attempts: list[tuple[str, bool]] = []
    rate_wait_events = 0
    rate_wait_total_ms = 0.0
    for offset in range(len(judge_urls)):
        judge_url = judge_urls[(start_judge_index + offset) % len(judge_urls)]
        for scheme in schemes:
            result, waited_ms = await validate_with_scheme(
                session=session,
                proxy=proxy,
                scheme=scheme,
                baseline_ips=baseline_ips,
                timeout_seconds=timeout_seconds,
                judge_url=judge_url,
                semaphore=semaphore,
                rate_limiter=rate_limiter,
            )
            if waited_ms > 0:
                rate_wait_events += 1
                rate_wait_total_ms += waited_ms
            if result.is_valid:
                attempts.append((judge_url, True))
                return result, attempts, rate_wait_events, rate_wait_total_ms
            attempts.append((judge_url, False))
            last_result = result
    assert last_result is not None
    return last_result, attempts, rate_wait_events, rate_wait_total_ms


async def append_proxy_async(file_path: Path, proxy: str) -> None:
    line = f"{proxy}\n"
    await asyncio.to_thread(_append_proxy_sync, file_path, line)


def _append_proxy_sync(file_path: Path, line: str) -> None:
    with file_path.open("a", encoding="utf-8") as handle:
        handle.write(line)


async def writer_worker(
    file_path: Path,
    writer_queue: asyncio.Queue[str | None],
    persisted_counter: dict[str, int],
    persisted_lock: asyncio.Lock,
) -> None:
    while True:
        item = await writer_queue.get()
        try:
            if item is None:
                return
            await append_proxy_async(file_path, item)
            async with persisted_lock:
                persisted_counter["count"] += 1
        finally:
            writer_queue.task_done()


async def worker(
    queue: asyncio.Queue[str],
    session: ClientSession,
    baseline_ips: set[str],
    timeout_seconds: float,
    semaphore: asyncio.Semaphore,
    valid_proxies: list[str],
    write_mode: str,
    writer_queue: asyncio.Queue[str | None] | None,
    state_lock: asyncio.Lock,
    progress: Progress,
    task_id: TaskID,
    counters: dict[str, int],
    reasons_counter: Counter[str],
    scheme_counter: Counter[str],
    judge_counter: Counter[str],
    judge_picker: JudgePicker,
    rate_stats: dict[str, float],
    rate_limiter: AsyncRateLimiter | None,
    valid_details: list[ValidProxyDetail],
    schemes: tuple[str, ...],
) -> None:
    while True:
        proxy = await queue.get()
        try:
            start_judge_index = await judge_picker.next_start_index()
            result, attempts, rate_wait_events, rate_wait_total_ms = await validate_proxy(
                session=session,
                proxy=proxy,
                baseline_ips=baseline_ips,
                timeout_seconds=timeout_seconds,
                judge_urls=judge_picker.judge_urls,
                start_judge_index=start_judge_index,
                semaphore=semaphore,
                rate_limiter=rate_limiter,
                schemes=schemes,
            )
            async with state_lock:
                counters["checked"] += 1
                reasons_counter[result.reason] += 1
                if result.reason.startswith("ok_"):
                    scheme_counter[result.reason] += 1
                for judge_url, success in attempts:
                    if success:
                        judge_counter[f"{judge_url}::success"] += 1
                    else:
                        judge_counter[f"{judge_url}::fail"] += 1
                rate_stats["events"] += rate_wait_events
                rate_stats["wait_ms"] += rate_wait_total_ms
                if result.is_valid:
                    counters["valid"] += 1
                    valid_details.append(
                        ValidProxyDetail(
                            proxy=result.proxy,
                            protocol=result.protocol,
                            origin_ip=result.origin_ip,
                            judge_url=result.judge_url,
                            location=result.location,
                        )
                    )
                    if write_mode == "append":
                        if writer_queue is not None:
                            writer_queue.put_nowait(result.proxy)
                    else:
                        valid_proxies.append(result.proxy)
                else:
                    counters["invalid"] += 1

                progress.update(
                    task_id,
                    advance=1,
                    description=(
                        f"[cyan]Testando[/cyan] "
                        f"Checked={counters['checked']} "
                        f"Valid={counters['valid']} "
                        f"Invalid={counters['invalid']} "
                        f"RateWaits={int(rate_stats['events'])}"
                    ),
                )
        finally:
            queue.task_done()


def write_valid_details_csv(path: Path, rows: list[ValidProxyDetail]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["proxy", "protocol", "origin_ip", "location", "judge_url"])
        for row in rows:
            writer.writerow([row.proxy, row.protocol, row.origin_ip, row.location, row.judge_url])


async def run_validation(
    workers: int,
    max_connections: int,
    timeout_seconds: float,
    output_file: Path,
    source_url: str,
    judge_url: str,
    requests_per_second: float | None,
    write_mode: str,
    no_banner: bool,
    enable_geo: bool,
    geo_provider: str,
    geo_timeout: float,
    geo_max_concurrent: int,
    detail_output: Path | None,
    schemes: tuple[str, ...],
) -> None:
    console = Console()
    if not no_banner:
        console.print(f"[bold magenta]{PROXYZIN_BANNER}[/bold magenta]")
        console.print(
            "[bold]ProxyZin[/bold] — validador assincrono de proxies HTTP, HTTPS e SOCKS (opcional)\n"
        )
    timeout = ClientTimeout(total=timeout_seconds)
    # Concurrency is controlled by semaphore only; connector keeps defaults.
    connector = aiohttp.TCPConnector()
    semaphore = asyncio.Semaphore(max_connections)
    rate_limiter = AsyncRateLimiter(requests_per_second) if requests_per_second is not None else None

    judge_urls = [item.strip() for item in judge_url.split(",") if item.strip()]
    if not judge_urls:
        raise ValueError("Ao menos um judge-url valido deve ser informado.")
    judge_picker = JudgePicker(judge_urls=judge_urls)
    valid_details: list[ValidProxyDetail] = []

    source_urls = [u.strip() for u in source_url.split(",") if u.strip()]
    if not source_urls:
        source_urls = [PROXYSCRAPE_URL]

    async with ClientSession(timeout=timeout, connector=connector) as session:
        console.print("[bold cyan]ProxyZin:[/bold cyan] Baixando proxies...")
        proxies = await fetch_proxies_from_sources(session, source_urls)
        if not proxies:
            console.print("[bold yellow]Nenhum proxy encontrado na fonte.[/bold yellow]")
            output_file.write_text("", encoding="utf-8")
            if detail_output is not None:
                write_valid_details_csv(detail_output, [])
            return

        console.print(f"[green]Proxies coletados:[/green] {len(proxies)}")
        console.print("[bold cyan]ProxyZin:[/bold cyan] Descobrindo IP baseline (sem proxy)...")
        baseline_ips, baseline_judge = await fetch_baseline_ips_with_fallback(
            session=session,
            timeout_seconds=timeout_seconds,
            judge_urls=judge_urls,
        )
        console.print(f"[green]Baseline IP(s):[/green] {', '.join(sorted(baseline_ips))} via {baseline_judge}")

        queue: asyncio.Queue[str] = asyncio.Queue()
        for proxy in proxies:
            queue.put_nowait(proxy)

        valid_proxies: list[str] = []
        if write_mode == "append":
            output_file.write_text("", encoding="utf-8")
        writer_queue: asyncio.Queue[str | None] | None = asyncio.Queue() if write_mode == "append" else None
        persisted_counter = {"count": 0}
        persisted_lock = asyncio.Lock()
        writer_task: asyncio.Task[None] | None = None
        if writer_queue is not None:
            writer_task = asyncio.create_task(
                writer_worker(
                    file_path=output_file,
                    writer_queue=writer_queue,
                    persisted_counter=persisted_counter,
                    persisted_lock=persisted_lock,
                )
            )

        lock = asyncio.Lock()
        counters = {"checked": 0, "valid": 0, "invalid": 0}
        reasons_counter: Counter[str] = Counter()
        scheme_counter: Counter[str] = Counter()
        judge_counter: Counter[str] = Counter()
        rate_stats = {"events": 0.0, "wait_ms": 0.0}

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )

        with progress:
            task_id = progress.add_task("[cyan]Testando[/cyan]", total=queue.qsize())
            worker_tasks = [
                asyncio.create_task(
                    worker(
                        queue=queue,
                        session=session,
                        baseline_ips=baseline_ips,
                        timeout_seconds=timeout_seconds,
                        semaphore=semaphore,
                        valid_proxies=valid_proxies,
                        write_mode=write_mode,
                        writer_queue=writer_queue,
                        state_lock=lock,
                        progress=progress,
                        task_id=task_id,
                        counters=counters,
                        reasons_counter=reasons_counter,
                        scheme_counter=scheme_counter,
                        judge_counter=judge_counter,
                        judge_picker=judge_picker,
                        rate_stats=rate_stats,
                        rate_limiter=rate_limiter,
                        valid_details=valid_details,
                        schemes=schemes,
                    )
                )
                for _ in range(workers)
            ]

            try:
                await queue.join()
            finally:
                for task in worker_tasks:
                    task.cancel()
                await asyncio.gather(*worker_tasks, return_exceptions=True)

                if writer_queue is not None and writer_task is not None:
                    writer_queue.put_nowait(None)
                    await writer_queue.join()
                    await asyncio.gather(writer_task, return_exceptions=False)

            if enable_geo and valid_details:
                console.print("[bold cyan]ProxyZin:[/bold cyan] Geolocalizacao dos IPs validos (direto, sem proxy)...")
                await apply_geo_to_details(
                    session=session,
                    details=valid_details,
                    provider=geo_provider,
                    timeout_seconds=geo_timeout,
                    max_concurrent=geo_max_concurrent,
                )

    if write_mode == "final":
        output_file.write_text("\n".join(valid_proxies) + ("\n" if valid_proxies else ""), encoding="utf-8")

    if detail_output is not None:
        write_valid_details_csv(detail_output, valid_details)

    persisted_total = persisted_counter["count"] if write_mode == "append" else len(valid_proxies)
    detail_msg = f" | Detalhado: {detail_output.as_posix()}" if detail_output is not None else ""
    console.print(
        f"[bold green]ProxyZin — Finalizado.[/bold green] Validos: {persisted_total} | "
        f"Arquivo: {output_file.as_posix()}{detail_msg}"
    )
    console.print(
        f"[bold]Totais:[/bold] Testados={counters['checked']} "
        f"Validos={counters['valid']} Invalidos={counters['invalid']}"
    )

    diagnostics = Table(
        title="ProxyZin — Resumo do Diagnostico Operacional",
        show_header=True,
        header_style="bold magenta",
    )
    diagnostics.add_column("Categoria", style="bold")
    diagnostics.add_column("Motivo/Status", style="cyan")
    diagnostics.add_column("Quantidade", justify="right")
    diagnostics.add_column("Percentual", justify="right")
    total_reasons = sum(reasons_counter.values())
    success_prefix = "ok_"
    ordered_items = sorted(
        reasons_counter.items(),
        key=lambda item: (0 if item[0].startswith(success_prefix) else 1, -item[1], item[0]),
    )
    for reason, count in ordered_items:
        category = "Sucesso" if reason.startswith(success_prefix) else "Falha"
        ratio = (count / total_reasons * 100.0) if total_reasons else 0.0
        diagnostics.add_row(category, reason, str(count), f"{ratio:.1f}%")
    console.print(diagnostics)

    scheme_table = Table(
        title="ProxyZin — Protocolos validos",
        show_header=True,
        header_style="bold blue",
    )
    scheme_table.add_column("Protocolo", style="cyan")
    scheme_table.add_column("Sucessos", justify="right")
    scheme_table.add_column("Percentual dos validos", justify="right")
    valid_total = max(1, counters["valid"])
    for key in sorted(k for k in scheme_counter if k.startswith("ok_")):
        label = REASON_PROTOCOL_LABELS.get(key, key)
        count = scheme_counter[key]
        scheme_table.add_row(label, str(count), f"{(count / valid_total) * 100.0:.1f}%")
    if not any(k.startswith("ok_") for k in scheme_counter):
        scheme_table.add_row("(nenhum)", "0", "0.0%")
    console.print(scheme_table)

    if enable_geo and valid_details:
        loc_counter = Counter(d.location for d in valid_details)
        loc_table = Table(
            title="ProxyZin — Top localizacoes (geolocalizacao)",
            show_header=True,
            header_style="bold yellow",
        )
        loc_table.add_column("Localizacao", style="cyan")
        loc_table.add_column("Quantidade", justify="right")
        loc_table.add_column("Percentual dos validos", justify="right")
        n_valid = len(valid_details)
        denom = max(1, n_valid)
        for loc, cnt in loc_counter.most_common(15):
            loc_table.add_row(loc, str(cnt), f"{(cnt / denom) * 100.0:.1f}%")
        console.print(loc_table)

    judge_table = Table(
        title="ProxyZin — Telemetria por Juiz",
        show_header=True,
        header_style="bold green",
    )
    judge_table.add_column("Juiz", style="cyan")
    judge_table.add_column("Success", justify="right")
    judge_table.add_column("Fail", justify="right")
    judge_table.add_column("SuccessRate", justify="right")
    for endpoint in judge_urls:
        success = judge_counter.get(f"{endpoint}::success", 0)
        fail = judge_counter.get(f"{endpoint}::fail", 0)
        total = success + fail
        rate = (success / total * 100.0) if total else 0.0
        judge_table.add_row(endpoint, str(success), str(fail), f"{rate:.1f}%")
    console.print(judge_table)

    console.print(
        f"[bold]Rate limiter:[/bold] waits={int(rate_stats['events'])} "
        f"total_wait_ms={rate_stats['wait_ms']:.1f}"
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ProxyZin",
        description="ProxyZin — validador assincrono (HTTP/HTTPS/SOCKS), multi-fonte e diagnostico operacional.",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=50,
        help="Workers assincronos (default: 50).",
    )
    parser.add_argument(
        "-c",
        "--max-connections",
        type=int,
        default=100,
        help="Conexoes simultaneas globais (default: 100).",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=8.0,
        help="Timeout por request ao juiz em segundos (5-10, default: 8).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("proxies_validados.txt"),
        help="Arquivo de saida com proxies aprovados (host:port).",
    )
    parser.add_argument(
        "-s",
        "--source-url",
        type=str,
        default=PROXYSCRAPE_URL,
        help=(
            "Uma ou mais URLs de lista (texto ou JSON Geonode), separadas por virgula. "
            f"Exemplo extra: {PROXY_GEONODE_SAMPLE}"
        ),
    )
    parser.add_argument(
        "-j",
        "--judge-url",
        type=str,
        default=JUDGE_URL,
        help="Endpoint(s) do juiz, separados por virgula.",
    )
    parser.add_argument(
        "-r",
        "--requests-per-second",
        type=float,
        default=None,
        help="Limite opcional de taxa contra o juiz.",
    )
    parser.add_argument(
        "-m",
        "--write-mode",
        type=str,
        default="append",
        choices=sorted(WRITE_MODES),
        help="append (incremental) ou final.",
    )
    parser.add_argument(
        "-S",
        "--try-socks",
        action="store_true",
        help="Tambem testar socks4 e socks5 (requer aiohttp-socks).",
    )
    parser.add_argument(
        "-q",
        "--no-banner",
        action="store_true",
        help="Oculta o banner ASCII (CI/scripts).",
    )
    parser.add_argument(
        "-g",
        "--enable-geo",
        action="store_true",
        help="Geolocalizacao do IP de saida (direto, sem proxy).",
    )
    parser.add_argument(
        "-P",
        "--geo-provider",
        type=str,
        default="ip-api",
        choices=sorted(GEO_PROVIDERS),
        help="Provedor de geo (default: ip-api).",
    )
    parser.add_argument(
        "-y",
        "--geo-timeout",
        type=float,
        default=3.0,
        help="Timeout por consulta geo (default: 3).",
    )
    parser.add_argument(
        "-K",
        "--geo-max-concurrent",
        type=int,
        default=10,
        help="Concorrencia maxima para geo (default: 10).",
    )
    parser.add_argument(
        "-d",
        "--detail-output",
        type=Path,
        default=None,
        help="CSV: proxy, protocol, origin_ip, location, judge_url.",
    )
    return parser


def validate_args(
    workers: int,
    max_connections: int,
    timeout_seconds: float,
    requests_per_second: float | None,
    write_mode: str,
    geo_timeout: float,
    geo_max_concurrent: int,
    try_socks: bool,
) -> None:
    if workers <= 0:
        raise ValueError("--workers deve ser > 0.")
    if max_connections <= 0:
        raise ValueError("--max-connections deve ser > 0.")
    if not (5.0 <= timeout_seconds <= 10.0):
        raise ValueError("--timeout deve estar entre 5 e 10 segundos.")
    if requests_per_second is not None and requests_per_second <= 0:
        raise ValueError("--requests-per-second deve ser > 0.")
    if write_mode not in WRITE_MODES:
        raise ValueError("--write-mode invalido.")
    if geo_timeout <= 0:
        raise ValueError("--geo-timeout deve ser > 0.")
    if geo_max_concurrent <= 0:
        raise ValueError("--geo-max-concurrent deve ser > 0.")
    if try_socks and not SOCKS_AVAILABLE:
        raise RuntimeError("SOCKS requer aiohttp-socks. Instale: pip install aiohttp-socks")


async def async_main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    try:
        validate_args(
            args.workers,
            args.max_connections,
            args.timeout,
            args.requests_per_second,
            args.write_mode,
            args.geo_timeout,
            args.geo_max_concurrent,
            args.try_socks,
        )
        schemes = build_proxy_schemes(args.try_socks)
        await run_validation(
            workers=args.workers,
            max_connections=args.max_connections,
            timeout_seconds=args.timeout,
            output_file=args.output,
            source_url=args.source_url,
            judge_url=args.judge_url,
            requests_per_second=args.requests_per_second,
            write_mode=args.write_mode,
            no_banner=args.no_banner,
            enable_geo=args.enable_geo,
            geo_provider=args.geo_provider,
            geo_timeout=args.geo_timeout,
            geo_max_concurrent=args.geo_max_concurrent,
            detail_output=args.detail_output,
            schemes=schemes,
        )
        return 0
    except KeyboardInterrupt:
        Console().print("[bold yellow]Interrompido pelo usuario.[/bold yellow]")
        return 130
    except Exception as exc:
        Console().print(f"[bold red]Erro fatal:[/bold red] {exc}")
        return 1


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
