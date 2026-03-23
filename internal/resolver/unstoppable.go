package resolver

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	ens "github.com/wealdtech/go-ens/v3"
)

const (
	// ProxyReader on Polygon mainnet — resolves all UD domains in one call
	udProxyReaderAddr = "0x423F2531bd5d3C3D4EF7C318c2D1d9BEDE67c680"
)

// All TLDs managed by Unstoppable Domains
var udTLDs = []string{".crypto", ".x", ".wallet", ".nft", ".dao", ".blockchain", ".bitcoin", ".zil"}

// sharedUDClient is lazily initialized on first UD TLD resolution
// so that all 8 UD TLDs share a single Polygon RPC connection.
var (
	sharedUDClient   *ethclient.Client
	sharedUDClientMu sync.Mutex
)

// getSharedUDClient returns (or creates) the shared Polygon ethclient.
func getSharedUDClient(rpcURL string) (*ethclient.Client, error) {
	sharedUDClientMu.Lock()
	defer sharedUDClientMu.Unlock()
	if sharedUDClient != nil {
		return sharedUDClient, nil
	}
	c, err := dialEVMWithFallback(rpcURL, ".crypto")
	if err != nil {
		return nil, err
	}
	sharedUDClient = c
	return sharedUDClient, nil
}

func init() {
	for _, tld := range udTLDs {
		RegisterChain(ChainConfig{
			TLD:       tld,
			Name:      "Unstoppable Domains",
			RecordKey: ADNLRecordKey,
			DefaultRPCs: []string{
				"https://polygon-rpc.com",
				"https://polygon-bor-rpc.publicnode.com",
			},
			NewResolver: func(rpcURL string) (Resolver, error) {
				return newUDResolver(rpcURL)
			},
		})
	}
}

// UDResolver resolves Unstoppable Domains (.crypto, .x, .wallet, etc.)
// via the ProxyReader contract on Polygon.
type UDResolver struct {
	client *ethclient.Client
}

// Minimal ABI for ProxyReader.getMany(string[],uint256)
var udGetManyABI abi.ABI

func init() {
	parsed, err := abi.JSON(strings.NewReader(`[{
		"inputs": [
			{"name": "keys", "type": "string[]"},
			{"name": "tokenId", "type": "uint256"}
		],
		"name": "getMany",
		"outputs": [
			{"name": "values", "type": "string[]"}
		],
		"stateMutability": "view",
		"type": "function"
	}]`))
	if err != nil {
		panic("failed to parse UD ABI: " + err.Error())
	}
	udGetManyABI = parsed
}

func newUDResolver(rpcURL string) (*UDResolver, error) {
	client, err := getSharedUDClient(rpcURL)
	if err != nil {
		return nil, err
	}
	return &UDResolver{client: client}, nil
}

func (r *UDResolver) Resolve(domain string) (string, error) {
	// Compute EIP-137 namehash (same as ENS) — used as tokenId by UD
	nameHash, err := ens.NameHash(domain)
	if err != nil {
		return "", fmt.Errorf("namehash %q: %w", domain, err)
	}
	tokenID := new(big.Int).SetBytes(nameHash[:])

	// Pack: getMany(["adnl"], tokenId)
	callData, err := udGetManyABI.Pack("getMany", []string{ADNLRecordKey}, tokenID)
	if err != nil {
		return "", fmt.Errorf("pack getMany: %w", err)
	}

	proxyReader := common.HexToAddress(udProxyReaderAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := r.client.CallContract(ctx, ethereum.CallMsg{
		To:   &proxyReader,
		Data: callData,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("call ProxyReader for %q: %w", domain, err)
	}

	output, err := udGetManyABI.Unpack("getMany", result)
	if err != nil {
		return "", fmt.Errorf("unpack result for %q: %w", domain, err)
	}

	values := output[0].([]string)
	if len(values) == 0 || values[0] == "" {
		return "", fmt.Errorf("no ADNL record set for %q", domain)
	}

	adnlAddr := values[0]
	if _, err := ParseADNLAddress(adnlAddr); err != nil {
		return "", fmt.Errorf("invalid ADNL record for %q: %w", domain, err)
	}

	return adnlAddr, nil
}

// Close is a no-op because all UD resolvers share a single Polygon ethclient.
// The shared client is closed via CloseSharedUDClient at shutdown.
func (r *UDResolver) Close() {}

// CloseSharedUDClient closes the shared Polygon ethclient (call at shutdown).
func CloseSharedUDClient() {
	sharedUDClientMu.Lock()
	defer sharedUDClientMu.Unlock()
	if sharedUDClient != nil {
		sharedUDClient.Close()
		sharedUDClient = nil
	}
}
