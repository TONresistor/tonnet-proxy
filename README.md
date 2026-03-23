<div align="center">

# Tonnet Proxy

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![TON](https://img.shields.io/badge/TON-Network-0088CC?logo=telegram)](https://ton.org/)

**Private gateway to TON sites with multi-chain domain resolution**

[Installation](#installation) · [Usage](#usage) · [Options](#options)

</div>

---

## Overview

Tonnet Proxy is an anonymous proxy that enables private access to TON Sites through multi-hop garlic routing. Like Tor for the TON Network, each relay only knows its immediate neighbors, never the full path.

Built natively on TON protocols (ADNL, RLDP, DHT), it provides:

- **True anonymity**: no single relay knows both source and destination
- **Layered encryption**: ChaCha20-Poly1305 at each hop, X25519 key exchange
- **Multi-chain domains**: resolve `.eth`, `.sol`, `.btc`, `.bnb`, `.wallet`, `.nft`, `.crypto` and more
- **Direct mode**: fast, non-anonymous access for development and testing
- **Decentralized**: run your own relay, strengthen the network
- **TON-native**: direct integration with TON DNS and RLDP HTTP

---

## Features

| Feature | Description |
|---------|-------------|
| **3-Hop Circuits** | Traffic routes through Entry, Middle, and Exit relays for maximum privacy |
| **Garlic Encryption** | ChaCha20-Poly1305 with X25519 key exchange at each hop |
| **TON Sites** | Access `.ton`, `.adnl`, and `.t.me` domains anonymously |
| **Multi-Chain Domains** | Resolve `.eth` (ENS), `.sol` (SNS), `.btc` (BNS), `.bnb` (Space ID), `.wallet`/`.nft`/`.crypto` (Unstoppable Domains) to ADNL addresses |
| **Direct Mode** | Fast direct connection without anonymity for development |
| **Auto-Discovery** | Fetches community relays from GitHub directory |
| **Circuit Rotation** | Automatic circuit rotation for enhanced privacy |
| **YAML Config** | Optional config file for all settings |

---

## Supported Domains

| TLD | Name Service | Chain |
|-----|-------------|-------|
| `.ton`, `.adnl`, `.t.me` | TON DNS | TON |
| `.eth` | ENS | Ethereum |
| `.sol` | Solana Name Service | Solana |
| `.btc` | BNS | Bitcoin (Stacks) |
| `.bnb` | Space ID | BNB Chain |
| `.wallet`, `.nft`, `.crypto`, `.x`, `.dao`, `.zil` | Unstoppable Domains | Polygon |

Domain owners store their ADNL address in their name service record. The proxy resolves it and routes traffic to the TON site.

---

## Architecture

Traffic flows through 3 relays: **Client → Entry → Middle → Exit → TON Site**

Each hop has its own encryption layer (ChaCha20-Poly1305). The client encrypts data for all 3 hops in reverse order: `[[[payload]K3]K2]K1`. Each relay decrypts one layer and forwards to the next.

### Circuit Flow

1. Client establishes shared keys with each relay via X25519 key exchange
2. Client sends request encrypted in 3 layers
3. Each relay peels one layer and forwards
4. Exit node resolves domain via DHT and fetches via RLDP
5. Response is encrypted by the exit node and forwarded back through the circuit

---

## Installation

**Linux:**
```bash
curl -L https://github.com/TONresistor/tonnet-proxy/releases/latest/download/tonnet-proxy-linux-amd64 -o tonnet-proxy
chmod +x tonnet-proxy
```

**macOS (universal):**
```bash
curl -L https://github.com/TONresistor/tonnet-proxy/releases/latest/download/tonnet-proxy-darwin-universal -o tonnet-proxy
chmod +x tonnet-proxy
```

**From source:**
```bash
git clone https://github.com/TONresistor/tonnet-proxy.git
cd tonnet-proxy
make build
```

---

## Usage

```bash
# Anonymous mode with auto-discovered relays
./tonnet-proxy --auto

# Direct mode (fast, no anonymity)
./tonnet-proxy --direct

# Manual relay selection
./tonnet-proxy \
  --relay1 "192.168.1.10:9001,<entry_pubkey_hex>" \
  --relay2 "192.168.1.11:9001,<middle_pubkey_hex>" \
  --relay3 "192.168.1.12:9001,<exit_pubkey_hex>"

# Configure browser to use http://127.0.0.1:8080 as HTTP proxy
curl --proxy http://127.0.0.1:8080 http://foundation.ton/
curl --proxy http://127.0.0.1:8080 http://cortexagent.eth/
```

---

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--auto` | - | Auto-select relays from community directory |
| `--direct` | - | Direct connection mode (no anonymity, faster) |
| `--listen` | `127.0.0.1:8080` | Local proxy address |
| `--config-file` | - | YAML config file (CLI flags override) |
| `--directory` | GitHub | Relay directory URL |
| `--retries` | 3 | Max circuit build attempts in auto mode |
| `--relay1` | - | Entry relay (format: ip:port,pubkey_hex) |
| `--relay2` | - | Middle relay (format: ip:port,pubkey_hex) |
| `--relay3` | - | Exit relay (format: ip:port,pubkey_hex) |
| `--rotate` | 10m | Circuit rotation interval |
| `--debug` | false | Enable debug logging |
| `--eth-rpc` | public | Ethereum RPC endpoint |
| `--sol-rpc` | public | Solana RPC endpoint |
| `--polygon-rpc` | public | Polygon RPC for Unstoppable Domains |
| `--bnb-rpc` | public | BNB Chain RPC for Space ID |
| `--btc-rpc` | public | Stacks API for BNS |
| `--no-<tld>` | - | Disable specific TLD resolution (e.g. `--no-eth`) |

---

## How It Works

### Garlic Encryption

Each data packet is encrypted in layers (like a garlic bulb). Each relay decrypts one layer with its shared key and forwards to the next hop.

### Key Exchange

X25519 Diffie-Hellman establishes shared keys at circuit creation. Client sends `CircuitCreate` with its public key, relay responds with `CircuitCreated` containing the relay's public key. Both derive the same shared key via `SHA256(X25519(priv, other_pub))`.

### Protocol Messages

| Message | Purpose |
|---------|---------|
| `CircuitCreate` | Establish circuit with first relay |
| `CircuitExtend` | Extend circuit through existing hop |
| `CircuitRelay` | Forward encrypted command through circuit |
| `Data` | Send/receive encrypted payload |
| `StreamConnect` | Open connection to destination |
| `StreamData` | HTTP request/response data |

---

## Security Considerations

### Privacy Guarantees

| Relay | Knows Client | Knows Destination | Knows Content |
|-------|--------------|-------------------|---------------|
| Entry | IP only | No | No |
| Middle | No | No | No |
| Exit | No | Yes | Decrypted at exit |

### Threat Model

- **Traffic Analysis**: Correlating entry/exit timing could deanonymize users
- **Malicious Relays**: A single malicious relay cannot break anonymity
- **Colluding Relays**: All 3 relays colluding could identify user-destination pairs
- **Exit Node Sniffing**: Exit nodes see decrypted traffic (use HTTPS where possible)

### Best Practices

1. **Use diverse relays** - Don't use relays from the same operator
2. **Rotate circuits** - Use the `--rotate` flag for automatic rotation
3. **Run your own relay** - Contribute to network diversity

---

## Project Structure

- `cmd/` - Main proxy binary
- `internal/client` - Circuit builder and stream management
- `internal/proxy` - HTTP proxy handler
- `internal/resolver` - Multi-chain domain resolution (ENS, SNS, BNS, Space ID, UD)
- `internal/direct` - Direct TON connection client
- `internal/directory` - Relay discovery
- `internal/config` - YAML config loading
- `internal/logger` - Structured logging

---

## Contributing

Contributions are welcome!

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

---

## Acknowledgments

- **[tonutils-go](https://github.com/xssnick/tonutils-go)** - Foundation for TON protocol interactions
- **[TON Foundation](https://ton.org)** - TON Network and documentation
- **Tor Project** - Inspiration for onion routing architecture

---

## Related

- [tonnet-relayer](https://github.com/TONresistor/tonnet-relayer) - Run a relay node

## License

MIT
