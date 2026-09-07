# Phantom Eye

**Phantom Eye** is a consent-based Linux LAN device inventory tool for administrators auditing networks they own or are authorized to manage.

It reads the local kernel neighbor table (`ip neigh`) and reports IP addresses, MAC addresses, interface names, reachability state, and optional reverse DNS names. It does **not** collect phone numbers, identify people, bypass access controls, or track devices outside the operator's authorized local network.

## Features

- Linux-only, dependency-free Python implementation
- Uses the OS neighbor table instead of covert traffic interception
- Human-readable table, JSON, and CSV output
- Optional watch mode for changes in the local inventory
- Explicit authorization and privacy warnings in the CLI

## Requirements

- Linux
- Python 3.9+
- The `ip` command from `iproute2`

## Usage

```bash
python3 -m phantom_eye
python3 -m phantom_eye --json
python3 -m phantom_eye --csv
python3 -m phantom_eye --interface eth0
python3 -m phantom_eye --watch 10
```

The tool only shows entries already known by the local kernel. To inspect another network, use an approved network-management system and obtain the required authorization first.

## Install locally

```bash
python3 -m pip install .
phantom-eye --json
```

## Security and privacy

Use this tool only on systems and networks you own or are explicitly authorized to administer. MAC addresses can be personal data in some jurisdictions. Store output securely, minimize retention, and avoid correlating device identifiers with individuals without a lawful basis and informed consent.

## Development

```bash
python3 -m unittest discover -v
```

## License

MIT License. See [LICENSE](LICENSE).
