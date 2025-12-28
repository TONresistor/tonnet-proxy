package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"net"
)

// RelayNode represents a node that can relay tunnel traffic
type RelayNode struct {
	PublicKey ed25519.PublicKey
	Address   net.Addr
	Capacity  int     // Estimated capacity (0-100)
	Latency   int     // Estimated latency in ms
}

// DHT interface for discovering relay nodes
type DHT interface {
	// FindRelayNodes discovers nodes that can act as relays
	FindRelayNodes(count int) ([]RelayNode, error)
	// GetNodeByID gets a specific node by its ADNL ID
	GetNodeByID(id [32]byte) (*RelayNode, error)
}

// RouteBuilder constructs routes through the tunnel network
type RouteBuilder struct {
	dht      DHT
	minHops  int
	maxHops  int
	maxDummies int
}

// RouteBuilderConfig configures the route builder
type RouteBuilderConfig struct {
	DHT       DHT
	MinHops   int // Minimum number of hops (default: 3)
	MaxHops   int // Maximum number of hops (default: 5)
	MaxDummies int // Maximum dummy hops to add (default: 2)
}

// NewRouteBuilder creates a new route builder
func NewRouteBuilder(cfg RouteBuilderConfig) *RouteBuilder {
	if cfg.MinHops == 0 {
		cfg.MinHops = 3
	}
	if cfg.MaxHops == 0 {
		cfg.MaxHops = 5
	}
	if cfg.MaxDummies == 0 {
		cfg.MaxDummies = 2
	}

	return &RouteBuilder{
		dht:      cfg.DHT,
		minHops:  cfg.MinHops,
		maxHops:  cfg.MaxHops,
		maxDummies: cfg.MaxDummies,
	}
}

// BuildRoute constructs a route to a destination
func (rb *RouteBuilder) BuildRoute(destPubKey ed25519.PublicKey, destAddr net.Addr) (*Route, error) {
	// 1. Determine number of hops
	numHops := rb.minHops + randInt(rb.maxHops-rb.minHops+1)

	// 2. Discover relay nodes
	relays, err := rb.discoverRelays(numHops - 1) // -1 because destination is last hop
	if err != nil {
		return nil, fmt.Errorf("discover relays: %w", err)
	}

	// 3. Build the route
	route := &Route{
		Hops: make([]Hop, 0, numHops),
	}

	// Add relay hops
	for _, relay := range relays {
		route.Hops = append(route.Hops, Hop{
			PublicKey: relay.PublicKey,
			KeyHash:   sha256.Sum256(relay.PublicKey),
			Address:   relay.Address,
			IsDummy:   false,
		})
	}

	// Add destination as final hop
	route.Hops = append(route.Hops, Hop{
		PublicKey: destPubKey,
		KeyHash:   sha256.Sum256(destPubKey),
		Address:   destAddr,
		IsDummy:   false,
	})

	return route, nil
}

// BuildRouteFromHops creates a route from explicit hops
func BuildRouteFromHops(hops []Hop) *Route {
	return &Route{Hops: hops}
}

// BuildRouteFromKeys creates a route from public keys and addresses
func BuildRouteFromKeys(keys []ed25519.PublicKey, addrs []net.Addr) (*Route, error) {
	if len(keys) != len(addrs) {
		return nil, fmt.Errorf("keys and addresses must have same length")
	}

	hops := make([]Hop, len(keys))
	for i, key := range keys {
		hops[i] = NewHop(key, addrs[i])
	}

	return &Route{Hops: hops}, nil
}

// AddDummyHops adds dummy hops to obscure the route structure
func (rb *RouteBuilder) AddDummyHops(route *Route) *Route {
	if rb.maxDummies == 0 {
		return route
	}

	numDummies := 1 + randInt(rb.maxDummies)
	newHops := make([]Hop, 0, len(route.Hops)+numDummies)
	newHops = append(newHops, route.Hops...)

	for i := 0; i < numDummies; i++ {
		// Generate random dummy key
		dummyKey := make([]byte, 32)
		rand.Read(dummyKey)

		// Insert at random position (but not at the end - destination must be last)
		pos := randInt(len(newHops))
		if pos == len(newHops) {
			pos = len(newHops) - 1
		}

		dummy := Hop{
			PublicKey: dummyKey,
			KeyHash:   sha256.Sum256(dummyKey),
			IsDummy:   true,
		}

		// Insert at position
		newHops = append(newHops[:pos], append([]Hop{dummy}, newHops[pos:]...)...)
	}

	return &Route{Hops: newHops}
}

// discoverRelays finds relay nodes via DHT
func (rb *RouteBuilder) discoverRelays(count int) ([]RelayNode, error) {
	if rb.dht == nil {
		// No DHT available, return empty
		return nil, fmt.Errorf("no DHT available")
	}

	relays, err := rb.dht.FindRelayNodes(count * 2) // Get more than needed for selection
	if err != nil {
		return nil, err
	}

	if len(relays) < count {
		return nil, fmt.Errorf("not enough relay nodes: need %d, found %d", count, len(relays))
	}

	// Randomly select 'count' relays
	return selectRandom(relays, count), nil
}

// selectRandom randomly selects n items from a slice
func selectRandom(relays []RelayNode, n int) []RelayNode {
	if n >= len(relays) {
		return relays
	}

	// Fisher-Yates shuffle and take first n
	result := make([]RelayNode, len(relays))
	copy(result, relays)

	for i := len(result) - 1; i > 0; i-- {
		j := randInt(i + 1)
		result[i], result[j] = result[j], result[i]
	}

	return result[:n]
}

// randInt returns a random int in [0, n)
func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	max := big.NewInt(int64(n))
	r, _ := rand.Int(rand.Reader, max)
	return int(r.Int64())
}

// StaticRouteBuilder creates routes from static configuration
// Useful for testing or when DHT is not available
type StaticRouteBuilder struct {
	relays []RelayNode
}

// NewStaticRouteBuilder creates a builder with static relay nodes
func NewStaticRouteBuilder(relays []RelayNode) *StaticRouteBuilder {
	return &StaticRouteBuilder{relays: relays}
}

// BuildRoute creates a route using the static relay list
func (srb *StaticRouteBuilder) BuildRoute(destPubKey ed25519.PublicKey, destAddr net.Addr) (*Route, error) {
	hops := make([]Hop, 0, len(srb.relays)+1)

	// Add relay hops
	for _, relay := range srb.relays {
		hops = append(hops, NewHop(relay.PublicKey, relay.Address))
	}

	// Add destination
	hops = append(hops, NewHop(destPubKey, destAddr))

	return &Route{Hops: hops}, nil
}

// ValidateRoute checks if a route is valid
func ValidateRoute(route *Route) error {
	if route == nil {
		return fmt.Errorf("route is nil")
	}

	if len(route.Hops) == 0 {
		return fmt.Errorf("route has no hops")
	}

	// Check each hop
	for i, hop := range route.Hops {
		if len(hop.PublicKey) != ed25519.PublicKeySize && !hop.IsDummy {
			return fmt.Errorf("hop %d: invalid public key size", i)
		}

		// Last hop must have an address
		if i == len(route.Hops)-1 && hop.Address == nil && !hop.IsDummy {
			return fmt.Errorf("last hop must have an address")
		}
	}

	return nil
}

// ReverseRoute creates a return route (for bidirectional communication)
func ReverseRoute(route *Route) *Route {
	if route == nil {
		return nil
	}

	reversed := &Route{
		Hops: make([]Hop, len(route.Hops)),
	}

	for i, hop := range route.Hops {
		reversed.Hops[len(route.Hops)-1-i] = hop
	}

	return reversed
}
