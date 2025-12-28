package tunnel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
)

// EndpointConfig holds configuration for creating a TunnelEndpoint
type EndpointConfig struct {
	Keyring    Keyring       // Key storage for decryption
	DecryptVia [][32]byte    // Ordered list of key hashes to decrypt through
	ProxyTo    [32]byte      // Final destination ADNL ID
	Handler    PacketHandler // Callback for fully decrypted packets
	SenderKey  ed25519.PublicKey // Expected sender's public key for decryption
}

// TunnelEndpoint is the entry or exit point of a tunnel
// It handles multi-layer decryption of incoming packets
type TunnelEndpoint struct {
	mu sync.RWMutex

	keyring    Keyring
	decryptVia [][32]byte   // Ordered list of key hashes for layer-by-layer decryption
	proxyTo    [32]byte     // Final destination (ADNL ID)
	senderKey  ed25519.PublicKey // Sender's public key

	conn      net.PacketConn
	peerTable PeerTable     // Interface to ADNL peer table

	handler PacketHandler // Callback for decrypted packets

	closed bool
}

// NewTunnelEndpoint creates a new tunnel endpoint
func NewTunnelEndpoint(cfg EndpointConfig) (*TunnelEndpoint, error) {
	if cfg.Keyring == nil {
		return nil, fmt.Errorf("keyring is required")
	}

	if len(cfg.DecryptVia) == 0 {
		return nil, fmt.Errorf("at least one decryption key required")
	}

	return &TunnelEndpoint{
		keyring:    cfg.Keyring,
		decryptVia: cfg.DecryptVia,
		proxyTo:    cfg.ProxyTo,
		senderKey:  cfg.SenderKey,
		handler:    cfg.Handler,
	}, nil
}

// SetPeerTable sets the peer table for forwarding
func (e *TunnelEndpoint) SetPeerTable(pt PeerTable) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.peerTable = pt
}

// SetConnection sets the network connection
func (e *TunnelEndpoint) SetConnection(conn net.PacketConn) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.conn = conn
}

// ReceivePacket processes an incoming encrypted packet
func (e *TunnelEndpoint) ReceivePacket(data []byte, srcAddr net.Addr) error {
	e.mu.RLock()
	if e.closed {
		e.mu.RUnlock()
		return fmt.Errorf("endpoint closed")
	}
	e.mu.RUnlock()

	return e.receivePacketCont(data, srcAddr, 0)
}

// receivePacketCont recursively decrypts layers
func (e *TunnelEndpoint) receivePacketCont(data []byte, srcAddr net.Addr, idx int) error {
	if len(data) < 32 {
		return ErrPacketTooShort
	}

	// Verify key hash matches expected
	var keyHash [32]byte
	copy(keyHash[:], data[:32])

	if idx >= len(e.decryptVia) {
		return ErrTooManyLayers
	}

	if keyHash != e.decryptVia[idx] {
		return fmt.Errorf("%w: expected %x, got %x", ErrKeyHashMismatch, e.decryptVia[idx][:8], keyHash[:8])
	}

	// Get private key from keyring
	privKey, ok := e.keyring.GetPrivateKey(keyHash)
	if !ok {
		return fmt.Errorf("%w: %x", ErrKeyNotFound, keyHash[:8])
	}

	// Decrypt this layer
	decrypted, err := DecryptLayer(data[32:], privKey, e.senderKey)
	if err != nil {
		return fmt.Errorf("decrypt layer %d: %w", idx, err)
	}

	// If this is the last layer, forward to destination
	if idx == len(e.decryptVia)-1 {
		return e.forwardToDestination(decrypted, srcAddr)
	}

	// Otherwise, continue decrypting
	return e.receivePacketCont(decrypted, srcAddr, idx+1)
}

// forwardToDestination handles the fully decrypted packet
func (e *TunnelEndpoint) forwardToDestination(data []byte, srcAddr net.Addr) error {
	// Try to parse as tunnel packet contents
	var contents TunnelPacketContents
	if err := contents.Parse(data); err == nil && contents.Flags&FlagHasMessage != 0 {
		data = contents.Message
		if contents.Flags&FlagHasSourceAddr != 0 {
			srcAddr = contents.GetSourceAddr()
		}
	}

	// Call handler if set
	if e.handler != nil {
		return e.handler(data, srcAddr)
	}

	// Otherwise forward via peer table
	e.mu.RLock()
	pt := e.peerTable
	e.mu.RUnlock()

	if pt != nil {
		return pt.SendMessage(e.proxyTo, data)
	}

	return nil
}

// Close shuts down the endpoint
func (e *TunnelEndpoint) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.closed = true

	if e.conn != nil {
		return e.conn.Close()
	}

	return nil
}

// CreateEndpointKeys generates keys for a new endpoint with N layers
func CreateEndpointKeys(numLayers int) ([]ed25519.PrivateKey, [][32]byte, error) {
	if numLayers < 1 {
		return nil, nil, fmt.Errorf("need at least 1 layer")
	}

	privKeys := make([]ed25519.PrivateKey, numLayers)
	keyHashes := make([][32]byte, numLayers)

	for i := 0; i < numLayers; i++ {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, nil, fmt.Errorf("generate key %d: %w", i, err)
		}

		privKeys[i] = priv
		keyHashes[i] = hashPublicKey(pub)
	}

	return privKeys, keyHashes, nil
}

// hashPublicKey returns SHA256 hash of public key
func hashPublicKey(pub ed25519.PublicKey) [32]byte {
	return sha256.Sum256(pub)
}
