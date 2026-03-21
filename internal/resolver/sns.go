package resolver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

const (
	// SPL Name Service program ID
	snsNameProgramID = "namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX"

	// .sol TLD authority (root domain account)
	solTLDAuthority = "58PwtjSDuFHuUkYjH9BYnnQKHfwo9reZhC2zMJv9JPkx"

	// Hash prefix used by SNS to derive name accounts
	snsHashPrefix = "SPL Name Service"

	// Name registry header size: parent (32) + owner (32) + class (32) = 96 bytes
	nameRegistryHeaderSize = 96
)

func init() {
	RegisterChain(ChainConfig{
		TLD:       ".sol",
		Name:      "Solana SNS",
		RecordKey: "data",
		DefaultRPCs: []string{
			"https://api.mainnet-beta.solana.com",
			"https://solana-rpc.publicnode.com",
		},
		NewResolver: func(rpcURL string) (Resolver, error) {
			return newSNSResolver(rpcURL)
		},
	})
}

// SNSResolver resolves .sol domains to ADNL addresses via Solana Name Service.
// The ADNL address is stored in the domain's name registry data section
// as a UTF-8 hex string (64 chars, with optional 0x prefix).
type SNSResolver struct {
	client *rpc.Client
}

func newSNSResolver(rpcURL string) (*SNSResolver, error) {
	if rpcURL != "" {
		client, err := dialAndVerifySolana(rpcURL)
		if err != nil {
			return nil, err
		}
		return &SNSResolver{client: client}, nil
	}

	cfg := findChainConfig(".sol")
	for _, url := range cfg.DefaultRPCs {
		client, err := dialAndVerifySolana(url)
		if err == nil {
			return &SNSResolver{client: client}, nil
		}
	}
	return nil, fmt.Errorf("no working Solana RPC found")
}

func (r *SNSResolver) Resolve(domain string) (string, error) {
	// Strip .sol suffix
	name := strings.TrimSuffix(domain, ".sol")
	if name == "" {
		return "", fmt.Errorf("empty domain name")
	}

	// Derive the name registry PDA
	nameKey, err := deriveDomainKey(name)
	if err != nil {
		return "", fmt.Errorf("derive domain key for %q: %w", domain, err)
	}

	// Fetch the account data
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	info, err := r.client.GetAccountInfo(ctx, nameKey)
	if err != nil {
		return "", fmt.Errorf("fetch account for %q: %w", domain, err)
	}

	if info == nil || info.Value == nil {
		return "", fmt.Errorf("domain %q not found", domain)
	}

	data := info.Value.Data.GetBinary()
	if len(data) <= nameRegistryHeaderSize {
		return "", fmt.Errorf("no data set for %q", domain)
	}

	// Data section is after the 96-byte header
	payload := data[nameRegistryHeaderSize:]

	// Try to parse the data as a UTF-8 hex string (ADNL address)
	adnlHex := strings.TrimSpace(string(payload))
	adnlHex = strings.TrimRight(adnlHex, "\x00") // Remove null padding
	adnlHex = strings.TrimPrefix(adnlHex, "0x")
	adnlHex = strings.TrimPrefix(adnlHex, "0X")

	// If data is raw 32 bytes (not hex-encoded), convert to hex
	if len(adnlHex) != 64 && len(payload) >= 32 {
		adnlHex = hex.EncodeToString(payload[:32])
	}

	if _, err := ParseADNLAddress(adnlHex); err != nil {
		return "", fmt.Errorf("invalid ADNL data for %q: %w", domain, err)
	}

	return adnlHex, nil
}

func (r *SNSResolver) Close() {
	// rpc.Client doesn't have a Close method
}

// deriveDomainKey derives the PDA for a .sol domain name.
// Algorithm: SHA256("SPL Name Service" + name) → seeds [hashed, zeros32, SOL_TLD] → findProgramAddress
func deriveDomainKey(name string) (solana.PublicKey, error) {
	// Hash the domain name with the prefix
	h := sha256.Sum256([]byte(snsHashPrefix + name))

	// Parse the well-known public keys
	programID := solana.MustPublicKeyFromBase58(snsNameProgramID)
	tldAuthority := solana.MustPublicKeyFromBase58(solTLDAuthority)

	// Seeds: [hashedName, classKey (zeros), parentKey (SOL TLD authority)]
	classKey := make([]byte, 32) // zero-filled = Pubkey::default()

	pda, _, err := solana.FindProgramAddress(
		[][]byte{
			h[:],
			classKey,
			tldAuthority.Bytes(),
		},
		programID,
	)
	if err != nil {
		return solana.PublicKey{}, fmt.Errorf("find program address: %w", err)
	}

	return pda, nil
}

func dialAndVerifySolana(rpcURL string) (*rpc.Client, error) {
	client := rpc.New(rpcURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.GetSlot(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("RPC check failed: %w", err)
	}

	return client, nil
}
