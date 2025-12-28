# Tonnet Proxy

Private gateway to TON sites. Access `.ton`, `.adnl`, and `.t.me` domains anonymously through encrypted multi-hop circuits.

## How It Works

```
You -> [Encrypted] -> Entry -> Middle -> Exit -> TON Site
              |          |        |        |
           3 layers   sees IP  sees     sees dest
           of crypto  only    nothing   only
```

Your traffic is encrypted in 3 layers and routed through 3 relays. No single node can link you to your destination.

## Installation

**Linux:**
```bash
curl -L https://github.com/TONresistor/tonnet-proxy/releases/latest/download/tonnet-proxy-linux-amd64 -o tonnet-proxy
chmod +x tonnet-proxy
```

**macOS:**
```bash
curl -L https://github.com/TONresistor/tonnet-proxy/releases/latest/download/tonnet-proxy-darwin-arm64 -o tonnet-proxy
chmod +x tonnet-proxy
```

**From Source:**
```bash
git clone https://github.com/TONresistor/tonnet-proxy.git
cd tonnet-proxy
make build
```

## Usage

```bash
# Auto-select relays
./tonnet-proxy --auto

# With circuit rotation
./tonnet-proxy --auto --rotate
```

Configure your browser to use `http://localhost:8080` as HTTP proxy.

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--auto` | Auto-select relays from directory | - |
| `--rotate` | Circuit rotation interval | 10m |
| `--listen` | Local proxy address | :8080 |
| `--retries` | Circuit build attempts | 3 |

## Related

- [tonnet-relay](https://github.com/TONresistor/tonnet-relay) - Run a relay node

## License

MIT
