package tunnel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"net"
	"sync"

	"go.uber.org/zap"
)

// MidpointConfig holds configuration for creating a TunnelMidpoint
type MidpointConfig struct {
	PrivateKey  ed25519.PrivateKey
	PublicKey   ed25519.PublicKey
	ProxyTo     [32]byte  // Next hop ADNL ID
	ProxyAs     [32]byte  // Our identity towards next hop
	NextHopAddr net.Addr  // Network address of next hop
	SenderKey   ed25519.PublicKey // Expected sender's public key
}

// TunnelMidpoint is a relay node in the tunnel
// It decrypts one layer and forwards to the next hop
type TunnelMidpoint struct {
	mu sync.RWMutex

	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyHash    [32]byte

	proxyTo  [32]byte // Next hop ADNL ID
	proxyAs  [32]byte // Our identity towards next hop

	senderKey ed25519.PublicKey // For decryption

	conn     net.PacketConn
	nextHop  net.Addr // Address of next hop

	closed bool
}

// NewTunnelMidpoint creates a new relay midpoint
func NewTunnelMidpoint(cfg MidpointConfig) (*TunnelMidpoint, error) {
	if cfg.PrivateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}

	keyHash := sha256.Sum256(cfg.PublicKey)

	return &TunnelMidpoint{
		privateKey: cfg.PrivateKey,
		publicKey:  cfg.PublicKey,
		keyHash:    keyHash,
		proxyTo:    cfg.ProxyTo,
		proxyAs:    cfg.ProxyAs,
		senderKey:  cfg.SenderKey,
		nextHop:    cfg.NextHopAddr,
	}, nil
}

// SetConnection sets the network connection for sending
func (m *TunnelMidpoint) SetConnection(conn net.PacketConn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.conn = conn
}

// SetNextHop sets the address of the next hop
func (m *TunnelMidpoint) SetNextHop(addr net.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextHop = addr
}

// KeyHash returns the key hash for this midpoint
func (m *TunnelMidpoint) KeyHash() [32]byte {
	return m.keyHash
}

// ReceivePacket processes an incoming packet
func (m *TunnelMidpoint) ReceivePacket(data []byte, srcAddr net.Addr) error {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return fmt.Errorf("midpoint closed")
	}
	m.mu.RUnlock()

	if len(data) < 32 {
		return ErrPacketTooShort
	}

	// Verify key hash
	var keyHash [32]byte
	copy(keyHash[:], data[:32])

	if keyHash != m.keyHash {
		return fmt.Errorf("%w: expected %x, got %x", ErrKeyHashMismatch, m.keyHash[:8], keyHash[:8])
	}

	// Decrypt our layer
	decrypted, err := DecryptLayer(data[32:], m.privateKey, m.senderKey)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	// Try to parse as tunnel packet contents
	var contents TunnelPacketContents
	if err := contents.Parse(decrypted); err == nil {
		// Successfully parsed, forward the message
		return m.forward(contents.Message, srcAddr)
	}

	// Couldn't parse, forward raw decrypted data
	return m.forward(decrypted, srcAddr)
}

// forward sends the packet to the next hop
func (m *TunnelMidpoint) forward(data []byte, srcAddr net.Addr) error {
	m.mu.RLock()
	conn := m.conn
	nextHop := m.nextHop
	m.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("no connection set")
	}

	if nextHop == nil {
		return fmt.Errorf("no next hop set")
	}

	// Build packet for next hop with source metadata
	packet := m.buildPacketForNextHop(data, srcAddr)

	_, err := conn.WriteTo(packet, nextHop)
	if err != nil {
		return fmt.Errorf("write to next hop: %w", err)
	}

	return nil
}

// buildPacketForNextHop creates the packet to send to the next hop
func (m *TunnelMidpoint) buildPacketForNextHop(data []byte, srcAddr net.Addr) []byte {
	// The data should already be prefixed with the next hop's key hash
	// (it was encrypted for them by the sender)
	// We just forward it as-is

	// Optionally, we could wrap in TunnelPacketContents to preserve source info
	// But for now, just forward the encrypted layers

	return data
}

// Close shuts down the midpoint
func (m *TunnelMidpoint) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true

	if m.conn != nil {
		return m.conn.Close()
	}

	return nil
}

// ProxyNode manages multiple midpoint tunnels
type ProxyNode struct {
	mu sync.RWMutex

	midpoints map[[32]byte]*TunnelMidpoint
	keyring   Keyring
	conn      net.PacketConn
	logger    *zap.Logger
}

// NewProxyNode creates a new proxy node coordinator
func NewProxyNode(keyring Keyring) *ProxyNode {
	return &ProxyNode{
		midpoints: make(map[[32]byte]*TunnelMidpoint),
		keyring:   keyring,
	}
}

// SetConnection sets the shared connection
func (p *ProxyNode) SetConnection(conn net.PacketConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conn = conn
}

// SetLogger sets the logger for the proxy node
func (p *ProxyNode) SetLogger(logger *zap.Logger) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.logger = logger
}

// AddMidpoint registers a midpoint with this proxy node
func (p *ProxyNode) AddMidpoint(m *TunnelMidpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.midpoints[m.keyHash] = m
	p.keyring.AddKey(m.privateKey)
}

// RemoveMidpoint unregisters a midpoint
func (p *ProxyNode) RemoveMidpoint(keyHash [32]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.midpoints, keyHash)
	p.keyring.RemoveKey(keyHash)
}

// ReceivePacket routes an incoming packet to the appropriate midpoint
func (p *ProxyNode) ReceivePacket(data []byte, srcAddr net.Addr) error {
	if len(data) < 32 {
		return ErrPacketTooShort
	}

	var keyHash [32]byte
	copy(keyHash[:], data[:32])

	p.mu.RLock()
	midpoint, ok := p.midpoints[keyHash]
	p.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no midpoint for key hash %x", keyHash[:8])
	}

	return midpoint.ReceivePacket(data, srcAddr)
}

// ListenAndServe starts listening for incoming packets
func (p *ProxyNode) ListenAndServe(addr string) error {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	p.SetConnection(conn)

	// Set connection on all midpoints
	p.mu.RLock()
	for _, m := range p.midpoints {
		m.SetConnection(conn)
	}
	p.mu.RUnlock()

	buf := make([]byte, 65536)
	for {
		n, srcAddr, err := conn.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		go func(data []byte, srcAddr net.Addr) {
			if err := p.ReceivePacket(data, srcAddr); err != nil {
				// Log error but continue
				_ = err
			}
		}(data, srcAddr)
	}
}

// Close shuts down the proxy node
func (p *ProxyNode) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, m := range p.midpoints {
		m.Close()
	}

	if p.conn != nil {
		return p.conn.Close()
	}

	return nil
}
