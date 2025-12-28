<div align="center">

# Tonnet Proxy

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![TON](https://img.shields.io/badge/TON-Network-0088CC?logo=telegram)](https://ton.org/)

**Private gateway to TON sites**

[Installation](#installation) · [Usage](#usage) · [Options](#options)

</div>

---

## Overview

Tonnet Proxy is an anonymous proxy that enables private, anonymous access to TON Sites through multi-hop garlic routing. Like Tor for the TON Network, each relay only knows its immediate neighbors, never the full path.

Built natively on TON protocols (ADNL, RLDP, DHT), it provides:

- **True anonymity**: no single relay knows both source and destination
- **Layered encryption**: ChaCha20-Poly1305 at each hop, X25519 key exchange
- **Decentralized**: run your own relay, strengthen the network
- **TON-native**: direct integration with TON DNS and RLDP HTTP

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

## Usage

```bash
./tonnet-proxy --auto
```

Configure browser to use `http://localhost:8080` as proxy.

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--auto` | - | Auto-select relays |
| `--rotate` | 10m | Circuit rotation |
| `--listen` | :8080 | Proxy address |

## Related

- [tonnet-relay](https://github.com/TONresistor/tonnet-relay) - Run a relay node

## License

MIT
