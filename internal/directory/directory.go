package directory

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/TONresistor/tonnet-proxy/internal/client"
)

// DefaultURL is the community relay directory
const DefaultURL = "https://raw.githubusercontent.com/TONresistor/tonnet-directory/main/relays.json"

// Relay represents a relay node from the directory
type Relay struct {
	Name     string   `json:"name"`
	Pubkey   string   `json:"pubkey"`
	Address  string   `json:"address"`
	Roles    []string `json:"roles"`
	Operator string   `json:"operator,omitempty"`
}

// HasRole checks if the relay has a specific role
func (r *Relay) HasRole(role string) bool {
	for _, rl := range r.Roles {
		if rl == role {
			return true
		}
	}
	return false
}

// ToRelayInfo converts to client.RelayInfo
func (r *Relay) ToRelayInfo() (client.RelayInfo, error) {
	pubkeyBytes, err := hex.DecodeString(r.Pubkey)
	if err != nil {
		return client.RelayInfo{}, fmt.Errorf("invalid pubkey hex: %w", err)
	}

	if len(pubkeyBytes) != ed25519.PublicKeySize {
		return client.RelayInfo{}, fmt.Errorf("invalid pubkey length: %d", len(pubkeyBytes))
	}

	return client.RelayInfo{
		Address:   r.Address,
		PublicKey: ed25519.PublicKey(pubkeyBytes),
	}, nil
}

// Directory represents the community relay directory
type Directory struct {
	Version int     `json:"version"`
	Updated string  `json:"updated"`
	Relays  []Relay `json:"relays"`
}

// Fetch downloads the directory from a URL
func Fetch(url string) (*Directory, error) {
	if url == "" {
		url = DefaultURL
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch directory: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch directory: status %d", resp.StatusCode)
	}

	var dir Directory
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		return nil, fmt.Errorf("parse directory: %w", err)
	}

	return &dir, nil
}

// FilterByRole returns relays that have a specific role
func (d *Directory) FilterByRole(role string) []Relay {
	var result []Relay
	for _, r := range d.Relays {
		if r.HasRole(role) {
			result = append(result, r)
		}
	}
	return result
}

// SelectCircuit selects 3 different relays for entry, middle, and exit
func (d *Directory) SelectCircuit() (entry, middle, exit *Relay, err error) {
	entries := d.FilterByRole("entry")
	middles := d.FilterByRole("middle")
	exits := d.FilterByRole("exit")

	if len(entries) == 0 {
		return nil, nil, nil, fmt.Errorf("no entry relays available")
	}
	if len(middles) == 0 {
		return nil, nil, nil, fmt.Errorf("no middle relays available")
	}
	if len(exits) == 0 {
		return nil, nil, nil, fmt.Errorf("no exit relays available")
	}

	// Select entry
	entryRelay := entries[cryptoRandInt(len(entries))]

	// Select middle (different from entry)
	var middleRelay Relay
	for attempts := 0; attempts < 100; attempts++ {
		middleRelay = middles[cryptoRandInt(len(middles))]
		if middleRelay.Pubkey != entryRelay.Pubkey {
			break
		}
	}
	if middleRelay.Pubkey == entryRelay.Pubkey {
		return nil, nil, nil, fmt.Errorf("not enough distinct middle relays")
	}

	// Select exit (different from entry and middle)
	var exitRelay Relay
	for attempts := 0; attempts < 100; attempts++ {
		exitRelay = exits[cryptoRandInt(len(exits))]
		if exitRelay.Pubkey != entryRelay.Pubkey && exitRelay.Pubkey != middleRelay.Pubkey {
			break
		}
	}
	if exitRelay.Pubkey == entryRelay.Pubkey || exitRelay.Pubkey == middleRelay.Pubkey {
		return nil, nil, nil, fmt.Errorf("not enough distinct exit relays")
	}

	return &entryRelay, &middleRelay, &exitRelay, nil
}

// SelectCircuitRelays returns 3 RelayInfo for circuit creation
func (d *Directory) SelectCircuitRelays() ([]client.RelayInfo, error) {
	entry, middle, exit, err := d.SelectCircuit()
	if err != nil {
		return nil, err
	}

	entryInfo, err := entry.ToRelayInfo()
	if err != nil {
		return nil, fmt.Errorf("entry relay: %w", err)
	}

	middleInfo, err := middle.ToRelayInfo()
	if err != nil {
		return nil, fmt.Errorf("middle relay: %w", err)
	}

	exitInfo, err := exit.ToRelayInfo()
	if err != nil {
		return nil, fmt.Errorf("exit relay: %w", err)
	}

	return []client.RelayInfo{entryInfo, middleInfo, exitInfo}, nil
}

// GetRelayName returns the name of a relay by address
func (d *Directory) GetRelayName(address string) string {
	for _, r := range d.Relays {
		if r.Address == address {
			return r.Name
		}
	}
	return "unknown"
}

// cryptoRandInt returns a cryptographically secure random int in [0, n)
func cryptoRandInt(n int) int {
	if n <= 0 {
		return 0
	}
	var b [8]byte
	rand.Read(b[:])
	return int(binary.BigEndian.Uint64(b[:]) % uint64(n))
}
