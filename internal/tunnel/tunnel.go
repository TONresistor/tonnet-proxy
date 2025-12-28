// Package tunnel implements garlic-style multi-hop encrypted tunnels for ADNL.
// Based on TON's adnl-tunnel.cpp implementation.
package tunnel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"net"
	"sync"
)

var (
	ErrPacketTooShort   = errors.New("packet too short")
	ErrKeyHashMismatch  = errors.New("key hash mismatch")
	ErrKeyNotFound      = errors.New("key not found in keyring")
	ErrTooManyLayers    = errors.New("too many encryption layers")
	ErrInvalidChecksum  = errors.New("invalid checksum")
	ErrInvalidPacket    = errors.New("invalid packet structure")
	ErrEncryptionFailed = errors.New("encryption failed")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrInvalidProxyID   = errors.New("invalid proxy ID")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrTimestampExpired = errors.New("timestamp expired or too far in future")
	ErrReplayDetected   = errors.New("replay attack detected")
)

// TunnelPoint represents a point in the tunnel (endpoint or midpoint)
type TunnelPoint interface {
	// ReceivePacket processes an incoming encrypted packet
	ReceivePacket(data []byte, srcAddr net.Addr) error
	// Close shuts down the tunnel point
	Close() error
}

// Hop represents a node in the tunnel route
type Hop struct {
	PublicKey ed25519.PublicKey // Ed25519 public key of this hop
	KeyHash   [32]byte          // SHA256 hash of the public key
	Address   net.Addr          // Network address (optional for some hops)
	IsDummy   bool              // True if this is a dummy hop for obfuscation
}

// NewHop creates a new Hop from a public key
func NewHop(pubKey ed25519.PublicKey, addr net.Addr) Hop {
	return Hop{
		PublicKey: pubKey,
		KeyHash:   sha256.Sum256(pubKey),
		Address:   addr,
		IsDummy:   false,
	}
}

// Route represents a complete path through the tunnel network
type Route struct {
	Hops []Hop
}

// NewRoute creates a new route from a list of hops
func NewRoute(hops ...Hop) *Route {
	return &Route{Hops: hops}
}

// Len returns the number of hops in the route
func (r *Route) Len() int {
	return len(r.Hops)
}

// TunnelConfig holds configuration for creating tunnels
type TunnelConfig struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	ListenAddr string
}

// PacketHandler is a callback for received decrypted packets
type PacketHandler func(data []byte, srcAddr net.Addr) error

// Keyring manages private keys for decryption
type Keyring interface {
	// GetPrivateKey returns the private key for a given key hash
	GetPrivateKey(keyHash [32]byte) (ed25519.PrivateKey, bool)
	// AddKey adds a private key to the keyring
	AddKey(privKey ed25519.PrivateKey)
	// RemoveKey removes a key from the keyring
	RemoveKey(keyHash [32]byte)
}

// SimpleKeyring is a basic in-memory keyring implementation
type SimpleKeyring struct {
	mu   sync.RWMutex
	keys map[[32]byte]ed25519.PrivateKey
}

// NewKeyring creates a new SimpleKeyring
func NewKeyring() *SimpleKeyring {
	return &SimpleKeyring{
		keys: make(map[[32]byte]ed25519.PrivateKey),
	}
}

// GetPrivateKey returns the private key for a given key hash
func (kr *SimpleKeyring) GetPrivateKey(keyHash [32]byte) (ed25519.PrivateKey, bool) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	key, ok := kr.keys[keyHash]
	return key, ok
}

// AddKey adds a private key to the keyring
func (kr *SimpleKeyring) AddKey(privKey ed25519.PrivateKey) {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	pubKey := privKey.Public().(ed25519.PublicKey)
	keyHash := sha256.Sum256(pubKey)
	kr.keys[keyHash] = privKey
}

// RemoveKey removes a key from the keyring
func (kr *SimpleKeyring) RemoveKey(keyHash [32]byte) {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	delete(kr.keys, keyHash)
}

// PeerTable interface for forwarding packets to ADNL peers
type PeerTable interface {
	SendMessage(peerID [32]byte, data []byte) error
}
