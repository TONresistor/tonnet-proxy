package resolver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	RegisterChain(ChainConfig{
		TLD:       ".btc",
		Name:      "Bitcoin BNS",
		RecordKey: "_adnl TXT",
		DefaultRPCs: []string{
			"https://api.mainnet.hiro.so",
		},
		NewResolver: func(rpcURL string) (Resolver, error) {
			return newBNSResolver(rpcURL)
		},
	})
}

// BNSResolver resolves .btc domains via the Stacks BNS API.
// The ADNL address is stored as a TXT record in the domain's zone file:
//
//	_adnl IN TXT "0x<64 hex chars>"
type BNSResolver struct {
	apiURL     string
	httpClient *http.Client
}

func newBNSResolver(rpcURL string) (*BNSResolver, error) {
	apiURL := "https://api.mainnet.hiro.so"
	if rpcURL != "" {
		apiURL = strings.TrimSuffix(rpcURL, "/")
	}

	// Verify the API is reachable
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(apiURL + "/v1/names/btc.btc")
	if err != nil {
		return nil, fmt.Errorf("BNS API check failed: %w", err)
	}
	resp.Body.Close()

	return &BNSResolver{
		apiURL:     apiURL,
		httpClient: client,
	}, nil
}

// adnlTXTRegex matches _adnl TXT records in zone files
var adnlTXTRegex = regexp.MustCompile(`(?mi)^_adnl[\s.]+(?:\S+\s+)?IN\s+TXT\s+"([^"]+)"`)

func (r *BNSResolver) Resolve(domain string) (string, error) {
	// Strip .btc suffix
	name := strings.TrimSuffix(domain, ".btc")
	if name == "" {
		return "", fmt.Errorf("empty domain name")
	}

	// Step 1: Check that the name exists
	nameURL := fmt.Sprintf("%s/v1/names/%s.btc", r.apiURL, url.PathEscape(name))
	resp, err := r.httpClient.Get(nameURL)
	if err != nil {
		return "", fmt.Errorf("fetch name info for %q: %w", domain, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return "", fmt.Errorf("domain %q not found", domain)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("BNS API error %d for %q", resp.StatusCode, domain)
	}

	var nameInfo struct {
		Status       string `json:"status"`
		ZonefileHash string `json:"zonefile_hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&nameInfo); err != nil {
		return "", fmt.Errorf("parse name info for %q: %w", domain, err)
	}

	if nameInfo.ZonefileHash == "" {
		return "", fmt.Errorf("no zone file for %q", domain)
	}

	// Step 2: Fetch the zone file
	zoneURL := fmt.Sprintf("%s/v1/names/%s.btc/zonefile", r.apiURL, url.PathEscape(name))
	resp2, err := r.httpClient.Get(zoneURL)
	if err != nil {
		return "", fmt.Errorf("fetch zone file for %q: %w", domain, err)
	}
	defer resp2.Body.Close()

	var zoneResp struct {
		Zonefile string `json:"zonefile"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&zoneResp); err != nil {
		return "", fmt.Errorf("parse zone file for %q: %w", domain, err)
	}

	// Step 3: Parse the zone file for _adnl TXT record
	matches := adnlTXTRegex.FindStringSubmatch(zoneResp.Zonefile)
	if len(matches) < 2 {
		return "", fmt.Errorf("no _adnl TXT record in zone file for %q", domain)
	}

	adnlAddr := matches[1]
	if _, err := ParseADNLAddress(adnlAddr); err != nil {
		return "", fmt.Errorf("invalid ADNL in zone file for %q: %w", domain, err)
	}

	return adnlAddr, nil
}

func (r *BNSResolver) Close() {
	// HTTP client doesn't need closing
}
