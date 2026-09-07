# Phantom Eye

**Phantom Eye** is a consent-based Linux LAN device inventory, monitoring, and bounded network-audit tool for administrators auditing networks they own or are authorized to manage.

It reads the local kernel neighbor table (`ip neigh`), can monitor that inventory over time, can perform a deliberately bounded TCP-connect scan of a private IPv4 CIDR, and can optionally geolocate one public IP through `ipapi.co`. It does **not** collect phone numbers, identify people, bypass access controls, intercept traffic, or scan public address space.

## Features

- Linux-only, dependency-free Python implementation
- Local neighbor inventory with IP, MAC, interface, state, and optional reverse DNS
- Watch mode for basic local-network monitoring
- Bounded TCP scanner limited to private, loopback, or link-local IPv4 networks of 256 addresses or fewer
- JSON, CSV, and human-readable output
- Opt-in geolocation for globally routable public IPs only
- Explicit authorization and privacy warnings in the CLI

## Requirements

- Linux
- Python 3.9+
- The `ip` command from `iproute2` for neighbor inventory and monitoring
- Network access is required only for `--geo`

## Usage

```bash
# Local neighbor inventory
python3 -m phantom_eye
python3 -m phantom_eye --json
python3 -m phantom_eye --csv
python3 -m phantom_eye --interface eth0 --resolve

# Monitor the local kernel neighbor table every 10 seconds
python3 -m phantom_eye --watch 10

# Scan only an authorized private network; defaults to ports 22, 80, and 443
python3 -m phantom_eye --scan 192.168.1.0/24 --ports 22,80,443
python3 -m phantom_eye --scan 192.168.1.0/28 --ports 22,443 --timeout 0.5 --json

# Geolocate one public IP (contacts ipapi.co; private IPs are rejected)
python3 -m phantom_eye --geo 1.1.1.1 --json
```

The scanner uses TCP connection attempts and reports open ports only. It intentionally refuses public CIDRs and networks larger than 256 addresses. Monitoring refreshes the local neighbor table; it is not a covert traffic monitor.

## Install locally

```bash
python3 -m pip install .
phantom-eye --json
```

## Security and privacy

Use this tool only on systems and networks you own or are explicitly authorized to administer. MAC addresses and IP geolocation can be personal data in some jurisdictions. Store output securely, minimize retention, and avoid correlating device identifiers with individuals without a lawful basis and informed consent. The `--geo` option sends the requested public IP to the third-party provider `ipapi.co`; do not use it for sensitive addresses unless your organization permits that disclosure.

## Development

```bash
python3 -m unittest discover -v
```

## License

MIT License. See [LICENSE](LICENSE).
