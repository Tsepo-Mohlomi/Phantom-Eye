from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ScanResult:
    ip: str
    port: int
    service: str
    state: str


COMMON_SERVICES = {
    22: "ssh",
    53: "dns",
    80: "http",
    443: "https",
    445: "smb",
    631: "ipp",
    8080: "http-alt",
}


def validate_private_network(cidr: str, max_hosts: int = 256) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid network CIDR: {cidr}") from exc
    if network.version != 4:
        raise ValueError("network scanning currently supports IPv4 only")
    if not (network.is_private or network.is_loopback or network.is_link_local):
        raise ValueError("refusing to scan public address space; provide a private, loopback, or link-local CIDR")
    if network.num_addresses > max_hosts:
        raise ValueError(f"network is too large; maximum is {max_hosts} addresses")
    return network


def parse_ports(value: str) -> list[int]:
    ports: set[int] = set()
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            port = int(item)
        except ValueError as exc:
            raise ValueError(f"invalid port: {item}") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"port out of range: {port}")
        ports.add(port)
    if not ports:
        raise ValueError("at least one TCP port is required")
    return sorted(ports)


def scan_network(cidr: str, ports: Iterable[int], timeout: float = 0.35) -> list[ScanResult]:
    network = validate_private_network(cidr)
    if timeout <= 0 or timeout > 10:
        raise ValueError("timeout must be greater than zero and no more than 10 seconds")
    results: list[ScanResult] = []
    for address in network.hosts():
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                try:
                    code = sock.connect_ex((str(address), port))
                except OSError:
                    code = 1
            if code == 0:
                results.append(ScanResult(str(address), port, COMMON_SERVICES.get(port, "unknown"), "open"))
    return results
