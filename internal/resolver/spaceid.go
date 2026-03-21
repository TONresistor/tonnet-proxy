package resolver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	ens "github.com/wealdtech/go-ens/v3"
)

// Space ID registry and resolver addresses per chain
type spaceIDChain struct {
	TLD             string
	Name            string
	RegistryAddr    string
	PublicResolver  string
	DefaultRPCs     []string
}

var spaceIDChains = []spaceIDChain{
	{
		TLD:            ".bnb",
		Name:           "Space ID (.bnb)",
		RegistryAddr:   "0x08ced32a7f3eec915ba84415e9c07a7286977956",
		PublicResolver: "0x7a18768edb2619e73c4d5067b90fd84a71993c1d",
		DefaultRPCs: []string{
			"https://bsc-dataseed.binance.org",
			"https://bsc-rpc.publicnode.com",
		},
	},
}

// Minimal ABI for ENS-compatible resolver.text(bytes32,string)
var sidTextABI abi.ABI

func init() {
	parsed, err := abi.JSON(strings.NewReader(`[{
		"inputs": [
			{"name": "node", "type": "bytes32"},
			{"name": "key", "type": "string"}
		],
		"name": "text",
		"outputs": [
			{"name": "", "type": "string"}
		],
		"stateMutability": "view",
		"type": "function"
	}]`))
	if err != nil {
		panic("failed to parse Space ID ABI: " + err.Error())
	}
	sidTextABI = parsed

	// Register each Space ID chain
	for _, chain := range spaceIDChains {
		RegisterChain(ChainConfig{
			TLD:         chain.TLD,
			Name:        chain.Name,
			RecordKey:   ADNLRecordKey,
			DefaultRPCs: chain.DefaultRPCs,
			NewResolver: func(rpcURL string) (Resolver, error) {
				return newSpaceIDResolver(rpcURL, chain)
			},
		})
	}
}

// SpaceIDResolver resolves Space ID domains (.bnb, .arb) via ENS-compatible contracts.
type SpaceIDResolver struct {
	client         *ethclient.Client
	publicResolver common.Address
}

func newSpaceIDResolver(rpcURL string, chain spaceIDChain) (*SpaceIDResolver, error) {
	client, err := dialEVMWithFallback(rpcURL, chain.TLD)
	if err != nil {
		return nil, err
	}

	return &SpaceIDResolver{
		client:         client,
		publicResolver: common.HexToAddress(chain.PublicResolver),
	}, nil
}

func (r *SpaceIDResolver) Resolve(domain string) (string, error) {
	// Compute EIP-137 namehash
	nameHash, err := ens.NameHash(domain)
	if err != nil {
		return "", fmt.Errorf("namehash %q: %w", domain, err)
	}

	// Pack: text(node, "adnl")
	callData, err := sidTextABI.Pack("text", nameHash, ADNLRecordKey)
	if err != nil {
		return "", fmt.Errorf("pack text call: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := r.client.CallContract(ctx, ethereum.CallMsg{
		To:   &r.publicResolver,
		Data: callData,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("call resolver for %q: %w", domain, err)
	}

	output, err := sidTextABI.Unpack("text", result)
	if err != nil {
		return "", fmt.Errorf("unpack result for %q: %w", domain, err)
	}

	adnlAddr := output[0].(string)
	if adnlAddr == "" {
		return "", fmt.Errorf("no ADNL record set for %q", domain)
	}

	if _, err := ParseADNLAddress(adnlAddr); err != nil {
		return "", fmt.Errorf("invalid ADNL record for %q: %w", domain, err)
	}

	return adnlAddr, nil
}

func (r *SpaceIDResolver) Close() {
	r.client.Close()
}
