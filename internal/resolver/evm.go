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

// evmChainIDs maps TLD suffixes to their expected EVM chain IDs.
var evmChainIDs = map[string]int64{
	".eth": 1,
	".bnb": 56,
	".crypto": 137, ".x": 137, ".wallet": 137, ".nft": 137,
	".dao": 137, ".blockchain": 137, ".bitcoin": 137, ".zil": 137,
}

// dialAndVerifyEVM dials an EVM-compatible JSON-RPC endpoint and verifies
// connectivity by requesting the chain ID. If expectedChainID is provided,
// the actual chain ID must match.
func dialAndVerifyEVM(rpcURL string, expectedChainID ...int64) (*ethclient.Client, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", rpcURL, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), evmDialTimeout)
	defer cancel()

	chainID, err := client.ChainID(ctx)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("RPC check failed for %s: %w", rpcURL, err)
	}

	if len(expectedChainID) > 0 && chainID.Int64() != expectedChainID[0] {
		client.Close()
		return nil, fmt.Errorf("chain ID mismatch for %s: expected %d, got %d", rpcURL, expectedChainID[0], chainID.Int64())
	}

	return client, nil
}

// dialEVMWithFallback connects to rpcURL if non-empty, otherwise iterates
// through the default RPCs registered for tld until one succeeds.
func dialEVMWithFallback(rpcURL string, tld string) (*ethclient.Client, error) {
	expected := evmChainIDs[tld]
	if rpcURL != "" {
		return dialAndVerifyEVM(rpcURL, expected)
	}

	cfg := findChainConfig(tld)
	if len(cfg.DefaultRPCs) == 0 {
		return nil, fmt.Errorf("no RPC endpoints configured for %s", tld)
	}

	var lastErr error
	for _, url := range cfg.DefaultRPCs {
		c, err := dialAndVerifyEVM(url, expected)
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
