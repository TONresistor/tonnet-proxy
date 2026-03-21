# ADNL Proxy

Multi-chain HTTP proxy for accessing decentralized websites via TON's ADNL network.

Resolves blockchain domain names (.eth, .sol, .ton, .crypto, .bnb, .btc, and more) to ADNL addresses, then serves dynamic websites through TON's peer-to-peer network with native encryption.

## Supported Domains

| TLD | Chain | Resolver |
|-----|-------|----------|
| .ton, .adnl, .t.me | TON | TON DNS (native) |
| .eth | Ethereum | ENS text record |
| .sol | Solana | SNS name registry |
| .crypto, .x, .wallet, .nft, .dao, .blockchain, .bitcoin, .zil | Polygon | Unstoppable Domains ProxyReader |
| .bnb | BNB Chain | Space ID resolver |
| .btc | Bitcoin/Stacks | BNS zone file TXT record |

## Usage

```bash
# Direct mode (fast, no anonymity)
./adnl-proxy --direct --listen :8080

# Anonymous mode with 3-hop garlic routing
./adnl-proxy --auto --listen :8080
```

Then configure your browser to use `http://localhost:8080` as HTTP proxy, or use curl:

```bash
curl -x http://localhost:8080 http://domainame.sol/
```

All chain resolvers are enabled by default with public RPCs. No API keys needed.

## Flags

```
--direct          Direct connection (no anonymity, faster)
--auto            Anonymous 3-hop garlic circuit
--listen          Proxy listen address (default: 127.0.0.1:8080)
--eth-rpc         Custom Ethereum RPC
--sol-rpc         Custom Solana RPC
--polygon-rpc     Custom Polygon RPC (Unstoppable Domains)
--bnb-rpc         Custom BNB Chain RPC (Space ID)
--btc-rpc         Custom Stacks API (BNS)
--no-eth          Disable .eth resolution
--no-sol          Disable .sol resolution
--no-crypto       Disable .crypto resolution
...               (--no-<tld> for any supported TLD)
```

## Adding a New Chain

Create a single file in `internal/resolver/`:

```go
package resolver

func init() {
    RegisterChain(ChainConfig{
        TLD:         ".newchain",
        Name:        "NewChain DNS",
        DefaultRPCs: []string{"https://rpc.newchain.io"},
        NewResolver: func(rpcURL string) (Resolver, error) {
            return newMyResolver(rpcURL)
        },
    })
}
```

The CLI flags and initialization are handled automatically.

## Build

```bash
go build -o adnl-proxy ./cmd/main.go
```

## License

MIT
