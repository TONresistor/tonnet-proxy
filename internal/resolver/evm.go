package resolver

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	// evmDialTimeout is the maximum time allowed for an EVM RPC health check.
	evmDialTimeout = 5 * time.Second
)

// dialAndVerifyEVM dials an EVM-compatible JSON-RPC endpoint and verifies
// connectivity by requesting the chain ID.
func dialAndVerifyEVM(rpcURL string) (*ethclient.Client, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", rpcURL, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), evmDialTimeout)
	defer cancel()

	if _, err = client.ChainID(ctx); err != nil {
		client.Close()
		return nil, fmt.Errorf("RPC check failed for %s: %w", rpcURL, err)
	}

	return client, nil
}

// dialEVMWithFallback connects to rpcURL if non-empty, otherwise iterates
// through the default RPCs registered for tld until one succeeds.
func dialEVMWithFallback(rpcURL string, tld string) (*ethclient.Client, error) {
	if rpcURL != "" {
		return dialAndVerifyEVM(rpcURL)
	}

	cfg := findChainConfig(tld)
	if len(cfg.DefaultRPCs) == 0 {
		return nil, fmt.Errorf("no RPC endpoints configured for %s", tld)
	}

	var lastErr error
	for _, url := range cfg.DefaultRPCs {
		c, err := dialAndVerifyEVM(url)
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("no working RPC found for %s: %w", tld, lastErr)
}

// findChainConfig looks up a chain config by TLD from the global registry.
// Returns an empty ChainConfig if no match is found.
func findChainConfig(tld string) ChainConfig {
	for _, cfg := range registry {
		if cfg.TLD == tld {
			return cfg
		}
	}
	return ChainConfig{}
}
