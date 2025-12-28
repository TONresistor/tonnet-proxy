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

Access `.ton`, `.adnl`, and `.t.me` sites anonymously through 3-hop encrypted circuits. No single relay knows both who you are and what you access.

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
