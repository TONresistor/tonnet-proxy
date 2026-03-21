package resolver

import (
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sigurn/crc16"
)

const (
	// resolveCacheTTL is how long a resolved ADNL address is cached.
	resolveCacheTTL = 5 * time.Minute
)

const (
	// ADNLAddressSize is the length in bytes of a raw ADNL address.
	ADNLAddressSize = 32

	// adnlAddressHexLen is the expected length of a hex-encoded ADNL address (without 0x prefix).
	adnlAddressHexLen = ADNLAddressSize * 2

	// adnlSerializePrefix is the single-byte tag prepended before CRC computation
	// when encoding an ADNL address to base32.
	adnlSerializePrefix = 0x2d

	// adnlDomainSuffix is appended to the base32-encoded address to form a routable .adnl host.
	adnlDomainSuffix = ".adnl"

	// ADNLRecordKey is the standard record key used across name services to store ADNL addresses.
	ADNLRecordKey = "adnl"
)

// Resolver resolves a domain name to a 32-byte ADNL address hex string.
type Resolver interface {
	// Resolve returns the ADNL address (64-char hex) for the given domain.
	Resolve(domain string) (string, error)

	// Close releases resources held by the resolver.
	Close()
}

// ChainConfig describes a blockchain name service that can be resolved.
type ChainConfig struct {
	// TLD is the domain suffix, e.g. ".eth", ".sol"
	TLD string

	// Name is a human-readable chain name for logs, e.g. "Ethereum ENS"
	Name string

	// DefaultRPCs are public RPC endpoints tried in order (no API key needed).
	DefaultRPCs []string

	// RecordKey is the key used to store the ADNL address in the name service.
	// e.g. "adnl" for ENS text records
	RecordKey string

	// NewResolver creates a resolver for this chain given an RPC URL.
	// If rpcURL is empty, DefaultRPCs are tried.
	NewResolver func(rpcURL string) (Resolver, error)
}

// registry holds all known chain configs, populated by init() in each chain file.
var registry []ChainConfig

// RegisterChain adds a chain to the global registry.
// Called from init() in each chain-specific file (ens.go, sns.go, etc.)
func RegisterChain(cfg ChainConfig) {
	registry = append(registry, cfg)
}

// AllChains returns all registered chain configs.
func AllChains() []ChainConfig {
	return registry
}

// cacheEntry holds a cached ADNL resolution result.
type cacheEntry struct {
	adnlHost  string
	expiresAt time.Time
}

// MultiResolver routes resolution to chain-specific resolvers based on TLD.
type MultiResolver struct {
	resolvers map[string]Resolver
	cache     sync.Map // domain -> cacheEntry
}

// NewMultiResolver creates a new multi-chain resolver.
func NewMultiResolver() *MultiResolver {
	return &MultiResolver{
		resolvers: make(map[string]Resolver),
	}
}

// Register adds a resolver for a TLD (e.g. ".eth", ".sol").
func (m *MultiResolver) Register(tld string, r Resolver) {
	m.resolvers[tld] = r
}

// Resolve resolves a domain by routing to the appropriate chain resolver.
func (m *MultiResolver) Resolve(domain string) (string, error) {
	for tld, r := range m.resolvers {
		if strings.HasSuffix(domain, tld) {
			return r.Resolve(domain)
		}
	}
	return "", fmt.Errorf("no resolver for domain: %s", domain)
}

// Supports returns true if any registered resolver handles this TLD.
func (m *MultiResolver) Supports(domain string) bool {
	for tld := range m.resolvers {
		if strings.HasSuffix(domain, tld) {
			return true
		}
	}
	return false
}

// EnabledTLDs returns a list of all enabled TLDs.
func (m *MultiResolver) EnabledTLDs() []string {
	var tlds []string
	for tld := range m.resolvers {
		tlds = append(tlds, tld)
	}
	return tlds
}

// Close closes all registered resolvers.
func (m *MultiResolver) Close() {
	for _, r := range m.resolvers {
		r.Close()
	}
}

// InitAll initializes all registered chains with optional per-chain RPC overrides.
// rpcOverrides maps TLD (e.g. ".eth") to a custom RPC URL.
// disabled is a set of TLDs to skip.
// Returns the MultiResolver and a list of (chain, error) for chains that failed.
// InitAll initializes all registered chain resolvers in parallel.
func InitAll(rpcOverrides map[string]string, disabled map[string]bool) (*MultiResolver, []string) {
	multi := NewMultiResolver()

	type result struct {
		tld     string
		r       Resolver
		warning string
	}

	// Filter active chains
	var active []ChainConfig
	for _, cfg := range registry {
		if !disabled[cfg.TLD] {
			active = append(active, cfg)
		}
	}

	// Initialize all resolvers in parallel
	results := make(chan result, len(active))
	for _, cfg := range active {
		go func(c ChainConfig) {
			rpc := rpcOverrides[c.TLD]
			r, err := c.NewResolver(rpc)
			if err != nil {
				results <- result{tld: c.TLD, warning: fmt.Sprintf("%s (%s): %v", c.Name, c.TLD, err)}
				return
			}
			results <- result{tld: c.TLD, r: r}
		}(cfg)
	}

	// Collect results
	var warnings []string
	for range active {
		res := <-results
		if res.warning != "" {
			warnings = append(warnings, res.warning)
			continue
		}
		multi.Register(res.tld, res.r)
	}

	return multi, warnings
}

// SerializeADNLAddress converts a raw 32-byte ADNL address to the base32 format
// used by tonutils (.adnl domains): prefix byte (0x2d) + addr + CRC16-XMODEM,
// then base32-encoded with the leading padding character stripped.
func SerializeADNLAddress(addr []byte) (string, error) {
	if len(addr) != ADNLAddressSize {
		return "", fmt.Errorf("invalid address length: expected %d, got %d", ADNLAddressSize, len(addr))
	}
	a := append([]byte{adnlSerializePrefix}, addr...)
	crcBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(crcBytes, crc16.Checksum(a, crc16.MakeTable(crc16.CRC16_XMODEM)))
	return strings.ToLower(base32.StdEncoding.EncodeToString(append(a, crcBytes...))[1:]), nil
}

// ResolveToADNL resolves a multi-chain domain to a routable ".adnl" hostname.
// Results are cached for resolveCacheTTL to avoid redundant blockchain RPCs.
// The pipeline: cache check → Resolve → strip 0x → hex-decode → validate 32 bytes →
// SerializeADNLAddress → append ".adnl" → cache store.
func (m *MultiResolver) ResolveToADNL(domain string) (string, error) {
	// Check cache first.
	if v, ok := m.cache.Load(domain); ok {
		entry := v.(cacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.adnlHost, nil
		}
		m.cache.Delete(domain)
	}

	rawHex, err := m.Resolve(domain)
	if err != nil {
		return "", err
	}

	rawHex = strings.TrimPrefix(strings.TrimPrefix(rawHex, "0x"), "0X")
	adnlBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return "", fmt.Errorf("invalid ADNL hex for %s: %w", domain, err)
	}
	if len(adnlBytes) != ADNLAddressSize {
		return "", fmt.Errorf("invalid ADNL address for %s: expected %d bytes, got %d", domain, ADNLAddressSize, len(adnlBytes))
	}

	b32, err := SerializeADNLAddress(adnlBytes)
	if err != nil {
		return "", fmt.Errorf("encode ADNL address for %s: %w", domain, err)
	}

	adnlHost := b32 + adnlDomainSuffix
	m.cache.Store(domain, cacheEntry{
		adnlHost:  adnlHost,
		expiresAt: time.Now().Add(resolveCacheTTL),
	})

	return adnlHost, nil
}

// ParseADNLAddress parses a hex string into a 32-byte ADNL address.
// Accepts with or without "0x" prefix.
func ParseADNLAddress(hexStr string) ([ADNLAddressSize]byte, error) {
	var addr [ADNLAddressSize]byte
	hexStr = strings.TrimPrefix(hexStr, "0x")
	hexStr = strings.TrimPrefix(hexStr, "0X")

	if len(hexStr) != adnlAddressHexLen {
		return addr, fmt.Errorf("invalid ADNL address length: expected %d hex chars, got %d", adnlAddressHexLen, len(hexStr))
	}

	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return addr, fmt.Errorf("invalid ADNL hex: %w", err)
	}

	copy(addr[:], b)
	return addr, nil
}
