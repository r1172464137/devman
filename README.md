# devman — OpenWrt Device Manager

Real-time device monitoring and control daemon + LuCI UI.

## Features

| Feature | Description |
|---------|-------------|
| Auto-discovery | `ip neigh` + conntrack, no polling |
| Hostnames | Reads dnsmasq DHCP leases |
| DHCP fingerprint | Raw AF_PACKET socket captures Option 60+55 |
| Device type | MAC OUI lookup + random MAC detection |
| Per-device speed | Conntrack byte delta (lazy-calc, only on API call) |
| Block | nftables set, O(1) drop |
| Rate limit | nftables limit (no kernel modules needed) |
| Merge | Fingerprint-based dedup, survives privacy MAC switch |
| Persistence | SQLite at `/etc/devman/devman.db` |

## Structure

```
devman/
├── devman/                  # Go daemon package
│   ├── src/main.go          # 1200+ lines, pure Go
│   ├── src/go.mod           # SQLite dependency
│   └── files/               # init script + shell scripts
├── luci-app-devman/         # LuCI frontend
│   ├── luasrc/controller/   # Lua API proxy
│   ├── root/usr/share/luci/ # View templates + menu
│   └── po/                  # Translations (zh-cn)
└── Makefile                 # Top-level build
```

## Quick Build

```bash
# Go daemon (standalone)
make

# Or via OpenWrt build system
./scripts/feeds update luci
./scripts/feeds install -a -p luci
cp -r feeds/luci/../devman package/
make package/devman/compile V=s
make package/luci-app-devman/compile V=s
```

## Requirements

- OpenWrt 23.05+ / ImmortalWrt 24.10+
- nftables (firewall4)
- dnsmasq (for DHCP hostnames)

## API

| Route | Method | Description |
|-------|--------|-------------|
| `/api/devices` | GET | Device list (triggers speed calc) |
| `/api/block` | POST | Block/unblock `{device_id, block}` |
| `/api/limit` | POST | Rate limit/rename `{device_id, rate_limit, alias}` |
| `/api/dhcp-event` | POST | DHCP fingerprint hook |

## License

MIT
