package tunnel

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// Control packet type IDs (TL constructors)
// These are CRC32(IEEE) of the TL schema string
const (
	// adnl.proxyControlPacketPing id:int256 = adnl.ProxyControlPacket
	ControlPacketPingID uint32 = 0x3796e44b

	// adnl.proxyControlPacketPong id:int256 = adnl.ProxyControlPacket
	ControlPacketPongID uint32 = 0x4bd1dbfc

	// adnl.proxyControlPacketRegister ip:int port:int = adnl.ProxyControlPacket
	ControlPacketRegisterID uint32 = 0xc309b23f
)

// ControlPacketPing represents a ping control packet
type ControlPacketPing struct {
	ID [32]byte
}

// Serialize converts the ping packet to bytes
func (p *ControlPacketPing) Serialize() []byte {
	buf := make([]byte, 4+32)
	binary.LittleEndian.PutUint32(buf[:4], ControlPacketPingID)
	copy(buf[4:], p.ID[:])
	return buf
}

// Parse deserializes a ping packet from bytes
func (p *ControlPacketPing) Parse(data []byte) error {
	if len(data) < 36 {
		return ErrPacketTooShort
	}
	typeID := binary.LittleEndian.Uint32(data[:4])
	if typeID != ControlPacketPingID {
		return fmt.Errorf("invalid ping packet type: %x", typeID)
	}
	copy(p.ID[:], data[4:36])
	return nil
}

// ControlPacketPong represents a pong control packet
type ControlPacketPong struct {
	ID [32]byte
}

// Serialize converts the pong packet to bytes
func (p *ControlPacketPong) Serialize() []byte {
	buf := make([]byte, 4+32)
	binary.LittleEndian.PutUint32(buf[:4], ControlPacketPongID)
	copy(buf[4:], p.ID[:])
	return buf
}

// Parse deserializes a pong packet from bytes
func (p *ControlPacketPong) Parse(data []byte) error {
	if len(data) < 36 {
		return ErrPacketTooShort
	}
	typeID := binary.LittleEndian.Uint32(data[:4])
	if typeID != ControlPacketPongID {
		return fmt.Errorf("invalid pong packet type: %x", typeID)
	}
	copy(p.ID[:], data[4:36])
	return nil
}

// ControlPacketRegister represents a register control packet
// Used for NAT traversal - client registers its external IP/port with the proxy
type ControlPacketRegister struct {
	IP   int32
	Port int32
}

// Serialize converts the register packet to bytes
func (p *ControlPacketRegister) Serialize() []byte {
	buf := make([]byte, 4+4+4)
	binary.LittleEndian.PutUint32(buf[:4], ControlPacketRegisterID)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(p.IP))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(p.Port))
	return buf
}

// Parse deserializes a register packet from bytes
func (p *ControlPacketRegister) Parse(data []byte) error {
	if len(data) < 12 {
		return ErrPacketTooShort
	}
	typeID := binary.LittleEndian.Uint32(data[:4])
	if typeID != ControlPacketRegisterID {
		return fmt.Errorf("invalid register packet type: %x", typeID)
	}
	p.IP = int32(binary.LittleEndian.Uint32(data[4:8]))
	p.Port = int32(binary.LittleEndian.Uint32(data[8:12]))
	return nil
}

// ParseControlPacket parses a control packet and returns its type
func ParseControlPacket(data []byte) (interface{}, error) {
	if len(data) < 4 {
		return nil, ErrPacketTooShort
	}

	typeID := binary.LittleEndian.Uint32(data[:4])

	switch typeID {
	case ControlPacketPingID:
		p := &ControlPacketPing{}
		if err := p.Parse(data); err != nil {
			return nil, err
		}
		return p, nil

	case ControlPacketPongID:
		p := &ControlPacketPong{}
		if err := p.Parse(data); err != nil {
			return nil, err
		}
		return p, nil

	case ControlPacketRegisterID:
		p := &ControlPacketRegister{}
		if err := p.Parse(data); err != nil {
			return nil, err
		}
		return p, nil

	default:
		return nil, fmt.Errorf("unknown control packet type: %x", typeID)
	}
}

// IsControlPacket checks if data starts with a known control packet type ID
func IsControlPacket(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	typeID := binary.LittleEndian.Uint32(data[:4])
	switch typeID {
	case ControlPacketPingID, ControlPacketPongID, ControlPacketRegisterID:
		return true
	default:
		return false
	}
}

// ControlHandler handles control packets for a proxy connection
type ControlHandler struct {
	mu sync.RWMutex

	// Registered client address (from Register packet)
	clientAddr net.Addr

	// Last ping/pong times
	lastPingSent     time.Time
	lastPongReceived time.Time

	// Ping interval and timeout
	pingInterval time.Duration
	pingTimeout  time.Duration

	// Callback for sending responses
	sendFunc func(data []byte, addr net.Addr) error
}

// NewControlHandler creates a new control packet handler
func NewControlHandler(sendFunc func([]byte, net.Addr) error) *ControlHandler {
	return &ControlHandler{
		pingInterval: 30 * time.Second,
		pingTimeout:  60 * time.Second,
		sendFunc:     sendFunc,
	}
}

// HandlePacket processes a control packet
func (h *ControlHandler) HandlePacket(data []byte, srcAddr net.Addr) error {
	packet, err := ParseControlPacket(data)
	if err != nil {
		return err
	}

	switch p := packet.(type) {
	case *ControlPacketPing:
		return h.handlePing(p, srcAddr)
	case *ControlPacketPong:
		return h.handlePong(p, srcAddr)
	case *ControlPacketRegister:
		return h.handleRegister(p, srcAddr)
	default:
		return fmt.Errorf("unknown control packet type")
	}
}

// handlePing responds to a ping with a pong
func (h *ControlHandler) handlePing(ping *ControlPacketPing, srcAddr net.Addr) error {
	pong := &ControlPacketPong{ID: ping.ID}

	if h.sendFunc != nil {
		return h.sendFunc(pong.Serialize(), srcAddr)
	}
	return nil
}

// handlePong records the pong response
func (h *ControlHandler) handlePong(pong *ControlPacketPong, srcAddr net.Addr) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastPongReceived = time.Now()
	return nil
}

// handleRegister stores the client's registered address
func (h *ControlHandler) handleRegister(reg *ControlPacketRegister, srcAddr net.Addr) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Convert IP and port to net.Addr
	ip := uint32ToIP(uint32(reg.IP))
	h.clientAddr = &net.UDPAddr{
		IP:   ip,
		Port: int(reg.Port),
	}

	return nil
}

// GetClientAddr returns the registered client address
func (h *ControlHandler) GetClientAddr() net.Addr {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.clientAddr
}

// SendPing sends a ping packet
func (h *ControlHandler) SendPing(id [32]byte, addr net.Addr) error {
	h.mu.Lock()
	h.lastPingSent = time.Now()
	h.mu.Unlock()

	ping := &ControlPacketPing{ID: id}
	if h.sendFunc != nil {
		return h.sendFunc(ping.Serialize(), addr)
	}
	return nil
}

// IsAlive checks if the connection is still alive based on pong responses
func (h *ControlHandler) IsAlive() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.lastPingSent.IsZero() {
		return true // No ping sent yet
	}

	if h.lastPongReceived.IsZero() {
		// No pong received yet, check if timeout exceeded
		return time.Since(h.lastPingSent) < h.pingTimeout
	}

	return time.Since(h.lastPongReceived) < h.pingTimeout
}

// SetPingInterval sets the ping interval
func (h *ControlHandler) SetPingInterval(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pingInterval = d
}

// SetPingTimeout sets the ping timeout
func (h *ControlHandler) SetPingTimeout(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pingTimeout = d
}

// NeedsPing returns true if a ping should be sent
func (h *ControlHandler) NeedsPing() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.lastPingSent.IsZero() {
		return true
	}
	return time.Since(h.lastPingSent) >= h.pingInterval
}
