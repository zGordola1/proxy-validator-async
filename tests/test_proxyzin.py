from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import ClientError

import proxyzin


def test_split_host_port_ipv4() -> None:
    assert proxyzin._split_host_port("192.168.0.1:8080") == ("192.168.0.1", "8080")


def test_split_host_port_ipv6_brackets() -> None:
    assert proxyzin._split_host_port("[2001:db8::1]:3128") == ("2001:db8::1", "3128")


def test_split_host_port_invalid() -> None:
    assert proxyzin._split_host_port("nocolon") is None
    assert proxyzin._split_host_port("[::1]") is None


def test_parse_proxy_lines_mixed_and_dedupe() -> None:
    raw = """
192.168.1.2:80
[2001:db8::2]:443
192.168.1.2:80
"""
    out = proxyzin.parse_proxy_lines(raw)
    assert out == ["192.168.1.2:80", "[2001:db8::2]:443"]


def test_parse_origin_ips() -> None:
    assert proxyzin.parse_origin_ips("203.0.113.1, 198.51.100.2") == {"203.0.113.1", "198.51.100.2"}


def test_pick_primary_origin_ip() -> None:
    assert proxyzin.pick_primary_origin_ip({"10.0.0.2", "10.0.0.1"}) == "10.0.0.1"


def test_protocol_display_label() -> None:
    assert proxyzin.protocol_display_label("socks5") == "SOCKS5"
    assert proxyzin.protocol_display_label("http") == "HTTP"


def test_format_output_line() -> None:
    d = proxyzin.ValidProxyDetail(
        proxy="192.168.0.1:8080",
        protocol="http",
        origin_ip="1.1.1.1",
        judge_url="http://x",
    )
    assert proxyzin.format_output_line(d, False) == "192.168.0.1:8080 HTTP"
    br = proxyzin.ValidProxyDetail(
        proxy="192.168.0.1:8080",
        protocol="http",
        origin_ip="1.1.1.1",
        judge_url="http://x",
        country_code="BR",
    )
    assert proxyzin.format_output_line(br, True) == "192.168.0.1:8080 BR HTTP"
    us = proxyzin.ValidProxyDetail(
        proxy="1.2.3.4:80",
        protocol="https",
        origin_ip="8.8.8.8",
        judge_url="http://x",
        country_code="US",
    )
    assert proxyzin.format_output_line(us, True) == "1.2.3.4:80 US HTTPS"
    gb = proxyzin.ValidProxyDetail(
        proxy="10.0.0.1:1080",
        protocol="socks4",
        origin_ip="9.9.9.9",
        judge_url="http://x",
        country_code="GB",
    )
    assert proxyzin.format_output_line(gb, True) == "10.0.0.1:1080 UK SOCKS4"


def test_country_code_for_output() -> None:
    assert proxyzin.country_code_for_output("br") == "BR"
    assert proxyzin.country_code_for_output("GB") == "UK"


def test_reason_display_label() -> None:
    assert proxyzin.reason_display_label("ok_http") == "HTTP"
    assert proxyzin.reason_display_label("ok_socks5") == "SOCKS5"
    assert proxyzin.reason_display_label("timeout") == "timeout"


def test_validate_geo_requests_per_second_rejects_non_positive() -> None:
    with pytest.raises(ValueError, match="geo-requests-per-second"):
        proxyzin.validate_args(
            workers=1,
            max_connections=1,
            timeout_seconds=8.0,
            requests_per_second=None,
            write_mode="append",
            geo_timeout=3.0,
            geo_max_concurrent=10,
            geo_requests_per_second=0.0,
            try_socks=False,
        )


def test_resolve_source_urls_fallback() -> None:
    assert proxyzin.resolve_source_urls(None, []) == [proxyzin.PROXYSCRAPE_URL]


def test_resolve_source_urls_merge_and_dedupe(tmp_path: Path) -> None:
    f = tmp_path / "u.txt"
    f.write_text("https://b.example/list\n# skip\nhttps://a.example/x\n", encoding="utf-8")
    out = proxyzin.resolve_source_urls("https://a.example/x,https://c.example/y", [f])
    assert out == ["https://a.example/x", "https://c.example/y", "https://b.example/list"]


def test_proxies_from_json_geonode_shape() -> None:
    body = {
        "data": [
            {"ip": "1.2.3.4", "port": 80},
            {"ip": "2001:db8::5", "port": "443"},
        ]
    }
    parsed = proxyzin._proxies_from_json_body(body)
    assert parsed is not None
    assert "1.2.3.4:80" in parsed
    assert "[2001:db8::5]:443" in parsed


@pytest.mark.asyncio
async def test_fetch_proxies_from_sources_records_failure() -> None:
    session = MagicMock()

    class BoomCM:
        async def __aenter__(self) -> None:
            raise ClientError("network down")

        async def __aexit__(self, *args: object) -> None:
            return None

    class OkCM:
        async def __aenter__(self) -> MagicMock:
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.text = AsyncMock(return_value="9.8.7.6:1234\n")
            return resp

        async def __aexit__(self, *args: object) -> None:
            return None

    def get_side_effect(url: str, **_kwargs: object) -> BoomCM | OkCM:
        if "bad" in url:
            return BoomCM()
        return OkCM()

    session.get = MagicMock(side_effect=get_side_effect)

    merged, failures = await proxyzin.fetch_proxies_from_sources(
        session, ["https://bad.example/x", "https://ok.example/y"]
    )
    assert merged == ["9.8.7.6:1234"]
    assert len(failures) == 1
    assert failures[0][0] == "https://bad.example/x"
    assert "ClientError" in failures[0][1]
