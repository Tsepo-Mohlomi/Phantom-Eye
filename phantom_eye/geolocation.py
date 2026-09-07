from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class GeoLocation:
    ip: str
    city: Optional[str]
    region: Optional[str]
    country: Optional[str]
    country_code: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    provider: str


def lookup_public_ip(ip: str, timeout: float = 5.0) -> GeoLocation:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {ip}") from exc
    if not address.is_global:
        raise ValueError("geolocation is available only for globally routable public IP addresses")
    if timeout <= 0 or timeout > 30:
        raise ValueError("timeout must be greater than zero and no more than 30 seconds")

    url = f"https://ipapi.co/{address}/json/"
    request = urllib.request.Request(url, headers={"User-Agent": "Phantom-Eye/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"geolocation provider request failed: {exc}") from exc
    if payload.get("error"):
        raise RuntimeError(f"geolocation provider error: {payload.get('reason', 'unknown error')}")
    return GeoLocation(
        ip=str(payload.get("ip", address)),
        city=payload.get("city"),
        region=payload.get("region"),
        country=payload.get("country_name"),
        country_code=payload.get("country_code"),
        latitude=payload.get("latitude"),
        longitude=payload.get("longitude"),
        provider="ipapi.co",
    )
