from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import aiohttp
from aiohttp import ClientError, ClientSession, ClientTimeout
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
JUDGE_URL = "http://httpbin.org/ip"
WRITE_MODES: Final[set[str]] = {"append", "final"}


@dataclass(slots=True)
class ProxyCheckResult:
    proxy: str
    is_valid: bool
    leaked: bool
    reason: str
    judge_url: str


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


async def fetch_proxies(session: ClientSession, source_url: str) -> list[str]:
    """Download proxy list from ProxyScrape and return normalized entries."""
    async with session.get(source_url) as response:
        response.raise_for_status()
        payload = await response.text()
    return parse_proxy_lines(payload)


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

    return (
        ProxyCheckResult(proxy=proxy, is_valid=True, leaked=False, reason=f"ok_{scheme}", judge_url=judge_url),
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
) -> tuple[ProxyCheckResult, list[tuple[str, bool]], int, float]:
    """Try both HTTP and HTTPS proxy schemes and accept first valid result."""
    last_result: ProxyCheckResult | None = None
    attempts: list[tuple[str, bool]] = []
    rate_wait_events = 0
    rate_wait_total_ms = 0.0
    for offset in range(len(judge_urls)):
        judge_url = judge_urls[(start_judge_index + offset) % len(judge_urls)]
        for scheme in ("http", "https"):
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
            )
            async with state_lock:
                counters["checked"] += 1
                reasons_counter[result.reason] += 1
                if result.reason in ("ok_http", "ok_https"):
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


async def run_validation(
    workers: int,
    max_connections: int,
    timeout_seconds: float,
    output_file: Path,
    source_url: str,
    judge_url: str,
    requests_per_second: float | None,
    write_mode: str,
) -> None:
    console = Console()
    timeout = ClientTimeout(total=timeout_seconds)
    # Concurrency is controlled by semaphore only; connector keeps defaults.
    connector = aiohttp.TCPConnector()
    semaphore = asyncio.Semaphore(max_connections)
    rate_limiter = AsyncRateLimiter(requests_per_second) if requests_per_second is not None else None

    judge_urls = [item.strip() for item in judge_url.split(",") if item.strip()]
    if not judge_urls:
        raise ValueError("Ao menos um judge-url valido deve ser informado.")
    judge_picker = JudgePicker(judge_urls=judge_urls)

    async with ClientSession(timeout=timeout, connector=connector) as session:
        console.print("[bold cyan]Baixando proxies...[/bold cyan]")
        proxies = await fetch_proxies(session, source_url)
        if not proxies:
            console.print("[bold yellow]Nenhum proxy encontrado na fonte.[/bold yellow]")
            output_file.write_text("", encoding="utf-8")
            return

        console.print(f"[green]Proxies coletados:[/green] {len(proxies)}")
        console.print("[bold cyan]Descobrindo IP baseline (sem proxy)...[/bold cyan]")
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

    if write_mode == "final":
        output_file.write_text("\n".join(valid_proxies) + ("\n" if valid_proxies else ""), encoding="utf-8")

    persisted_total = persisted_counter["count"] if write_mode == "append" else len(valid_proxies)
    console.print(
        f"[bold green]Finalizado.[/bold green] Validos: {persisted_total} | "
        f"Arquivo: {output_file.as_posix()}"
    )
    console.print(
        f"[bold]Totais:[/bold] Testados={counters['checked']} "
        f"Validos={counters['valid']} Invalidos={counters['invalid']}"
    )

    diagnostics = Table(title="Resumo do Diagnostico Operacional", show_header=True, header_style="bold magenta")
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

    scheme_table = Table(title="Taxa de Sucesso por Esquema", show_header=True, header_style="bold blue")
    scheme_table.add_column("Esquema", style="cyan")
    scheme_table.add_column("Sucessos", justify="right")
    scheme_table.add_column("Percentual dos validos", justify="right")
    valid_total = max(1, counters["valid"])
    for scheme in ("ok_http", "ok_https"):
        count = scheme_counter.get(scheme, 0)
        scheme_table.add_row(scheme, str(count), f"{(count / valid_total) * 100.0:.1f}%")
    console.print(scheme_table)

    judge_table = Table(title="Telemetria por Juiz", show_header=True, header_style="bold green")
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
    parser = argparse.ArgumentParser(description="Validador assincrono de proxies HTTP/HTTPS.")
    parser.add_argument("--workers", type=int, default=50, help="Quantidade de workers assincronos (default: 50).")
    parser.add_argument(
        "--max-connections",
        type=int,
        default=100,
        help="Maximo de conexoes simultaneas globais (default: 100).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Timeout total por request em segundos (recomendado: 5-10).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("proxies_validados.txt"),
        help="Arquivo de saida com proxies aprovados.",
    )
    parser.add_argument(
        "--source-url",
        type=str,
        default=PROXYSCRAPE_URL,
        help="URL de coleta dos proxies (default: ProxyScrape).",
    )
    parser.add_argument(
        "--judge-url",
        type=str,
        default=JUDGE_URL,
        help="Endpoint(s) de validacao de IP, separado por virgula.",
    )
    parser.add_argument(
        "--requests-per-second",
        type=float,
        default=None,
        help="Limite opcional de taxa contra o juiz (ex: 20).",
    )
    parser.add_argument(
        "--write-mode",
        type=str,
        default="append",
        choices=sorted(WRITE_MODES),
        help="Modo de escrita: append (incremental) ou final.",
    )
    return parser


def validate_args(
    workers: int,
    max_connections: int,
    timeout_seconds: float,
    requests_per_second: float | None,
    write_mode: str,
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
        )
        await run_validation(
            workers=args.workers,
            max_connections=args.max_connections,
            timeout_seconds=args.timeout,
            output_file=args.output,
            source_url=args.source_url,
            judge_url=args.judge_url,
            requests_per_second=args.requests_per_second,
            write_mode=args.write_mode,
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
