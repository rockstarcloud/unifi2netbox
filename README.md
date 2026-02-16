# unifi2netbox

Synchronize devices, interfaces, VLANs, WLANs, uplink cables, and device type templates from UniFi controllers into NetBox.

Synchronization direction is one-way: **UniFi -> NetBox**.

## Features

- UniFi Integration API (v1) support with API key auth
- UniFi OS / legacy session auth fallback (username/password, optional MFA)
- Multi-controller processing in parallel
- Interface, VLAN, WLAN, and uplink cable sync
- Device type enrichment from:
  - hardcoded `UNIFI_MODEL_SPECS` in `main.py`
  - bundled community library (`data/ubiquiti_device_specs.json`)
- Optional destructive NetBox cleanup (`NETBOX_CLEANUP=true`)
- Continuous sync loop (`SYNC_INTERVAL`) or run-once mode

## Quick Start

### Docker (recommended)

```bash
cp .env.example .env
# edit .env
docker compose up --build -d
docker compose logs -f
```

Notes:
- The sample `.env.example` sets `SYNC_INTERVAL=600` (10 minutes).
- If `SYNC_INTERVAL` is unset, code default is `0` (run once and exit).

### Bare-metal / VM (systemd installer)

```bash
sudo bash lxc/install.sh
# edit /opt/unifi2netbox/.env
systemctl start unifi2netbox
journalctl -u unifi2netbox -f
```

### Proxmox LXC helper

```bash
bash lxc/create-lxc.sh [CTID]
```

## Configuration

Configuration is built from:
- `config/config.yaml` (optional)
- environment variables (`.env`)

Environment variables override YAML values.

### Required

- `UNIFI_URLS`
- `NETBOX_URL`
- `NETBOX_TOKEN`
- `NETBOX_TENANT`
- UniFi credentials:
  - either `UNIFI_API_KEY`
  - or `UNIFI_USERNAME` + `UNIFI_PASSWORD`

### API modes

- **Integration API v1** (preferred):
  - URL examples:
    - `https://controller.example.com/proxy/network/integration/v1`
    - `https://controller.example.com/integration/v1`
  - Auth header candidates are auto-probed (`X-API-KEY`, `Authorization`, or custom `UNIFI_API_KEY_HEADER`)

- **Session login (legacy / UniFi OS)**:
  - login endpoints are auto-tried:
    - `/api/auth/login` (UniFi OS)
    - `/api/login` (legacy)

### Common toggles

- `SYNC_INTERFACES`, `SYNC_VLANS`, `SYNC_WLANS`, `SYNC_CABLES`
- `SYNC_STALE_CLEANUP`
- `NETBOX_CLEANUP`
- `CLEANUP_STALE_DAYS`
- `NETBOX_VRF_MODE` (`none`, `existing`, `create`)
- `NETBOX_SERIAL_MODE` (`mac`, `unifi`, `id`, `none`)
- `MAX_CONTROLLER_THREADS`, `MAX_SITE_THREADS`, `MAX_DEVICE_THREADS`

Full reference: `docs/configuration.md`.

## Device Type Specs

Data sources merged at runtime:
- `UNIFI_MODEL_SPECS` in `main.py` (**42 hardcoded models**)
- `data/ubiquiti_device_specs.json` (**173 by model**, **166 by part number**)

Hardcoded fields override community fields when both exist.

Details: `docs/device-specs.md`.

## Cleanup

When `NETBOX_CLEANUP=true`, cleanup runs after sync and can delete:
- stale devices
- garbage interfaces (`?` in name)
- orphan IPs
- orphan cables
- unused Ubiquiti device types

Guide: `docs/cleanup.md`.

## Project Structure

```text
.
├── main.py
├── unifi/
│   ├── unifi.py
│   ├── resources.py
│   ├── sites.py
│   ├── device.py
│   ├── networkconf.py
│   └── wlanconf.py
├── data/
│   └── ubiquiti_device_specs.json
├── config/
│   ├── config.yaml.SAMPLE
│   └── site_mapping.yaml
├── docs/
├── tests/
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Testing

```bash
pip install -r requirements.txt
pip install pytest~=8.0
pytest tests/ -v
```

Current suite: **52 tests**.

## Documentation

- `docs/configuration.md`
- `docs/cleanup.md`
- `docs/device-specs.md`
- `docs/architecture.md`
- `docs/troubleshooting.md`
- `docs/faq.md`
- `CHANGELOG.md`

## Important Runtime Notes

- UniFi requests are sent with `verify=False` in current implementation.
- NetBox client session is also configured with `verify=False`.
- Validate this behavior against your security requirements before production use.

## License

MIT (`LICENSE`).
