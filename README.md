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

---

## Features

| Feature | Description |
|---------|-------------|
| **3-Hop Circuits** | Traffic routes through Entry, Middle, and Exit relays for maximum privacy |
| **Garlic Encryption** | ChaCha20-Poly1305 with X25519 key exchange at each hop |
| **TON Sites Support** | Access `.ton`, `.adnl`, and `.t.me` domains anonymously |
| **RLDP Transport** | Uses TON's Reliable Large Datagram Protocol for site access |
| **Auto-Discovery** | Fetches community relays from GitHub directory |
| **Circuit Rotation** | Automatic circuit rotation for enhanced privacy |

---

## Architecture

Traffic flows through 3 relays: **Client → Entry → Middle → Exit → TON Site**

Each hop has its own encryption layer (ChaCha20-Poly1305). The client encrypts data for all 3 hops in reverse order: `[[[payload]K3]K2]K1`. Each relay decrypts one layer and forwards to the next.

### Circuit Flow

1. Client establishes shared keys with each relay via X25519 key exchange
2. Client sends request encrypted in 3 layers
3. Each relay peels one layer and forwards
4. Exit node resolves `.ton` domain via DHT and fetches via RLDP
5. Response travels back through the circuit with encryption added at each hop

---

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

---

## Usage

```bash
# Start with auto-discovery of community relays
./tonnet-proxy --auto

# Or specify relays manually
./tonnet-proxy \
  --relay1 "192.168.1.10:9001,<entry_pubkey_hex>" \
  --relay2 "192.168.1.11:9001,<middle_pubkey_hex>" \
  --relay3 "192.168.1.12:9001,<exit_pubkey_hex>"

# Configure browser to use http://localhost:8080 as HTTP proxy
curl --proxy http://localhost:8080 http://foundation.ton/
```

---

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--auto` | - | Auto-select relays from community directory |
| `--directory` | GitHub | Relay directory URL |
| `--retries` | 3 | Max circuit build attempts in auto mode |
| `--relay1` | - | Entry relay (format: ip:port,pubkey_hex) |
| `--relay2` | - | Middle relay (format: ip:port,pubkey_hex) |
| `--relay3` | - | Exit relay (format: ip:port,pubkey_hex) |
| `--listen` | :8080 | Local proxy address |
| `--rotate` | 10m | Circuit rotation interval |

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

## Development

### Building from Source

```bash
git clone https://github.com/TONresistor/tonnet-proxy.git
cd tonnet-proxy
go mod download
make build
make test
```

### Project Structure

- `cmd/tonnet-proxy` - Main proxy client
- `internal/client` - Circuit builder and stream management
- `internal/tunnel` - Garlic encryption
- `internal/directory` - Relay discovery

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

- [tonnet-relay](https://github.com/TONresistor/tonnet-relay) - Run a relay node

## License

MIT
