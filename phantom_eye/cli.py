from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from typing import Iterable, Optional

from .geolocation import lookup_public_ip
from .scanner import ScanResult, parse_ports, scan_network


@dataclass(frozen=True)
class Device:
    ip: str
    mac: Optional[str]
    interface: Optional[str]
    state: str
    hostname: Optional[str] = None


def _parse_neighbor_line(line: str) -> Optional[Device]:
    parts = line.split()
    if not parts or parts[0] in {"default", "Failed"}:
        return None
    try:
        ipaddress.ip_address(parts[0])
    except ValueError:
        return None
    mac = None
    interface = None
    state = "UNKNOWN"
    for i, token in enumerate(parts[1:], 1):
        if token == "lladdr" and i + 1 < len(parts):
            mac = parts[i + 1].lower()
        elif token == "dev" and i + 1 < len(parts):
            interface = parts[i + 1]
    states = {"INCOMPLETE", "REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "NOARP", "PERMANENT"}
    for token in parts[1:]:
        if token in states:
            state = token
            break
    return Device(ip=parts[0], mac=mac, interface=interface, state=state)


def read_neighbors(interface: Optional[str] = None, resolve: bool = False) -> list[Device]:
    if shutil.which("ip") is None:
        raise RuntimeError("the 'ip' command is required (install iproute2)")
    command = ["ip", "-j", "neigh"]
    if interface:
        command.extend(["dev", interface])
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode == 0:
        try:
            raw = json.loads(result.stdout)
            devices = [Device(ip=str(item.get("dst", "")), mac=(item.get("lladdr") or None), interface=item.get("dev"), state=str(item.get("state", "UNKNOWN")).upper()) for item in raw if item.get("dst")]
        except (json.JSONDecodeError, TypeError):
            devices = []
    else:
        fallback = subprocess.run(["ip", "neigh"] + (["dev", interface] if interface else []), check=False, capture_output=True, text=True)
        if fallback.returncode != 0:
            raise RuntimeError(f"could not read neighbor table: {fallback.stderr.strip()}")
        devices = [d for line in fallback.stdout.splitlines() if (d := _parse_neighbor_line(line))]
    if resolve:
        resolved = []
        for device in devices:
            try:
                hostname = socket.gethostbyaddr(device.ip)[0]
            except (socket.herror, socket.gaierror, OSError):
                hostname = None
            resolved.append(Device(**{**asdict(device), "hostname": hostname}))
        devices = resolved
    return sorted(devices, key=lambda d: ipaddress.ip_address(d.ip))


def render_table(devices: Iterable[Device]) -> str:
    rows = [[d.ip, d.mac or "-", d.interface or "-", d.state, d.hostname or "-"] for d in devices]
    headers = ["IP", "MAC", "INTERFACE", "STATE", "HOSTNAME"]
    widths = [max([len(headers[i])] + [len(row[i]) for row in rows]) for i in range(len(headers))]
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)), "  ".join("-" * w for w in widths)]
    lines.extend("  ".join(value.ljust(widths[i]) for i, value in enumerate(row)) for row in rows)
    return "\n".join(lines) if rows else "No devices found in the local neighbor table."


def render_scan(results: Iterable[ScanResult]) -> str:
    rows = [[r.ip, str(r.port), r.service, r.state] for r in results]
    if not rows:
        return "No open ports found."
    headers = ["IP", "PORT", "SERVICE", "STATE"]
    widths = [max([len(headers[i])] + [len(row[i]) for row in rows]) for i in range(4)]
    lines = [
        "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)),
        "  ".join("-" * w for w in widths),
    ]
    lines.extend("  ".join(v.ljust(widths[i]) for i, v in enumerate(row)) for row in rows)
    return "\n".join(lines)


def emit(devices: list[Device], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps([asdict(d) for d in devices], indent=2))
    elif fmt == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=["ip", "mac", "interface", "state", "hostname"])
        writer.writeheader()
        writer.writerows(asdict(d) for d in devices)
    else:
        print(render_table(devices))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Consent-based Linux LAN inventory, monitoring, and bounded private-network scanning.")
    parser.add_argument("--interface", help="limit neighbor results to one local network interface")
    parser.add_argument("--format", choices=("table", "json", "csv"), default="table")
    parser.add_argument("--json", dest="json_flag", action="store_true", help="shortcut for --format json")
    parser.add_argument("--resolve", action="store_true", help="perform reverse DNS lookups")
    parser.add_argument("--watch", type=float, metavar="SECONDS", help="monitor and refresh the local neighbor inventory")
    parser.add_argument("--scan", metavar="CIDR", help="TCP-connect scan a private/loopback/link-local IPv4 CIDR of at most 256 addresses")
    parser.add_argument("--ports", default="22,80,443", help="comma-separated TCP ports for --scan (default: 22,80,443)")
    parser.add_argument("--timeout", type=float, default=0.35, help="per-port TCP timeout for --scan")
    parser.add_argument("--geo", metavar="PUBLIC_IP", help="look up one public IP using ipapi.co; never sends private IPs")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    fmt = "json" if args.json_flag else args.format
    if args.watch is not None and args.watch <= 0:
        print("--watch must be greater than zero", file=sys.stderr)
        return 2
    if args.scan and args.geo:
        print("--scan and --geo cannot be combined", file=sys.stderr)
        return 2
    print("Phantom Eye: use only on networks you own or are authorized to administer.", file=sys.stderr)
    try:
        if args.geo:
            location = lookup_public_ip(args.geo, timeout=5.0)
            print(json.dumps(asdict(location), indent=2) if fmt == "json" else asdict(location))
            return 0
        if args.scan:
            results = scan_network(args.scan, parse_ports(args.ports), timeout=args.timeout)
            if fmt == "json":
                print(json.dumps([asdict(result) for result in results], indent=2))
            elif fmt == "csv":
                writer = csv.DictWriter(sys.stdout, fieldnames=["ip", "port", "service", "state"])
                writer.writeheader()
                writer.writerows(asdict(result) for result in results)
            else:
                print(render_scan(results))
            return 0
        while True:
            devices = read_neighbors(args.interface, args.resolve)
            if args.watch:
                print("\033[2J\033[H", end="")
            emit(devices, fmt)
            if not args.watch:
                return 0
            time.sleep(args.watch)
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
