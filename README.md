# Tonnet Proxy

Private gateway to TON sites. Access `.ton`, `.adnl`, and `.t.me` domains anonymously through encrypted multi-hop circuits.

## What is Tonnet?

Tonnet is an anonymity layer for TON Network, similar to Tor but built on TON protocols. Your traffic is encrypted in 3 layers and routed through 3 relays, so no single node can link you to your destination.

```
You -> [Encrypted] -> Entry -> Middle -> Exit -> TON Site
              |          |        |        |
           3 layers   sees IP  sees     sees dest
           of crypto  only    nothing   only
```

## This Repository

**tonnet-proxy** is the client application that runs on your computer. It creates a local HTTP proxy that routes your TON site requests through the Tonnet network.

Looking to run a relay? See [tonnet-relay](https://github.com/TONresistor/tonnet-relay).

## Installation

### From Releases

**Linux/macOS:**
```bash
# Linux
curl -L https://github.com/TONresistor/tonnet-proxy/releases/latest/download/tonnet-proxy-linux-amd64 -o tonnet-proxy

# macOS (Apple Silicon)
curl -L https://github.com/TONresistor/tonnet-proxy/releases/latest/download/tonnet-proxy-darwin-arm64 -o tonnet-proxy

chmod +x tonnet-proxy
```

**Windows:**

Download `tonnet-proxy-windows-amd64.exe` from [Releases](https://github.com/TONresistor/tonnet-proxy/releases).

### From Source

```bash
git clone https://github.com/TONresistor/tonnet-proxy.git
cd tonnet-proxy
make build
```

## Quick Start

```bash
# Start with automatic relay selection
./tonnet-proxy --auto

# Then configure your browser to use http://localhost:8080 as proxy
```

That's it. Visit any `.ton` site through your browser.

## Usage

### Auto Mode (Recommended)

```bash
# Basic usage - auto-select relays
./tonnet-proxy --auto

# With circuit rotation every 10 minutes (better anonymity)
./tonnet-proxy --auto --rotate

# Custom rotation interval
./tonnet-proxy --auto --rotate 5m
```

### Manual Mode

Specify your own relay path:

```bash
./tonnet-proxy \
  --relay1 "1.2.3.4:9001,<entry_pubkey>" \
  --relay2 "5.6.7.8:9001,<middle_pubkey>" \
  --relay3 "9.10.11.12:9001,<exit_pubkey>"
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--auto` | Auto-select relays from community directory | - |
| `--rotate` | Enable circuit rotation | 10m |
| `--listen` | Local proxy address | :8080 |
| `--retries` | Circuit build retry attempts | 3 |
| `--directory` | Custom relay directory URL | community |

## Browser Setup

### Firefox (Recommended)

1. Open Settings
2. Search "proxy"
3. Click "Settings..." in Network Settings
4. Select "Manual proxy configuration"
5. HTTP Proxy: `localhost`, Port: `8080`
6. Check "Also use this proxy for HTTPS"
7. Click OK

### Chrome / Chromium

```bash
chromium --proxy-server="http://localhost:8080"
```

### Command Line

```bash
# curl
curl -x http://localhost:8080 http://foundation.ton

# wget
http_proxy=http://localhost:8080 wget http://foundation.ton
```

## Supported Domains

| Domain | Description |
|--------|-------------|
| `.ton` | TON DNS domains (e.g., `foundation.ton`) |
| `.adnl` | Direct ADNL addresses |
| `.t.me` | Telegram TON sites |

## How It Works

1. **Circuit Building**: Proxy connects to 3 random relays and negotiates encryption keys with each using X25519 key exchange

2. **Layered Encryption**: Each request is encrypted 3 times (once per hop) using ChaCha20-Poly1305

3. **Onion Routing**: Each relay peels one layer of encryption and forwards to the next hop

4. **Response**: The exit relay fetches the TON site and the response travels back through the circuit

## Security Considerations

| What's Protected | What's Not |
|-----------------|------------|
| Your IP from destination | Traffic content at exit node |
| Destination from your ISP | Timing correlation attacks |
| Traffic from middle relay | Browser fingerprinting |

**Recommendations:**
- Use `--rotate` to change circuits periodically
- Don't log into personal accounts through the proxy
- The exit relay can see HTTP content (but not who you are)

## Troubleshooting

**"Failed to build circuit"**
- Check your internet connection
- Try again (relays might be temporarily unavailable)
- Use `--retries 5` for more attempts

**"Connection refused on :8080"**
- Make sure tonnet-proxy is running
- Check if another app is using port 8080
- Use `--listen :8888` for a different port

**Slow responses**
- This is normal - traffic goes through 3 hops
- Try `--auto` to pick closer relays

## License

MIT
