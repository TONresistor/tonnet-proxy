package resolver

import (
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	ens "github.com/wealdtech/go-ens/v3"
)

func init() {
	RegisterChain(ChainConfig{
		TLD:       ".eth",
		Name:      "Ethereum ENS",
		RecordKey: ADNLRecordKey,
		DefaultRPCs: []string{
			"https://eth.drpc.org",
			"https://ethereum-rpc.publicnode.com",
			"https://cloudflare-eth.com",
			"https://1rpc.io/eth",
		},
		NewResolver: func(rpcURL string) (Resolver, error) {
			return newENSResolver(rpcURL)
		},
	})
}

// ENSResolver resolves .eth domains to ADNL addresses via Ethereum Name Service.
type ENSResolver struct {
	client *ethclient.Client
}

func newENSResolver(rpcURL string) (*ENSResolver, error) {
	client, err := dialEVMWithFallback(rpcURL, ".eth")
	if err != nil {
		return nil, err
	}
	return &ENSResolver{client: client}, nil
}

func (r *ENSResolver) Resolve(domain string) (string, error) {
	normalized, err := ens.Normalize(domain)
	if err != nil {
		return "", fmt.Errorf("normalize %q: %w", domain, err)
	}

	resolver, err := ens.NewResolver(r.client, normalized)
	if err != nil {
		return "", fmt.Errorf("ENS resolver for %q: %w", domain, err)
	}

	adnlAddr, err := resolver.Text(ADNLRecordKey)
	if err != nil {
		return "", fmt.Errorf("read ADNL record for %q: %w", domain, err)
	}

	if adnlAddr == "" {
		return "", fmt.Errorf("no ADNL record set for %q", domain)
	}

	if _, err := ParseADNLAddress(adnlAddr); err != nil {
		return "", fmt.Errorf("invalid ADNL record for %q: %w", domain, err)
	}

	return adnlAddr, nil
}

func (r *ENSResolver) Close() {
	r.client.Close()
}
