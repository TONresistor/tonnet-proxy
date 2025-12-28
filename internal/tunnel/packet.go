package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
)

// TunnelPacketContents represents the contents of a tunnel packet
// Based on adnl.tunnelPacketContents from TON TL schema:
// adnl.tunnelPacketContents rand1:bytes flags:# from_ip:flags.0?int
//
//	from_port:flags.0?int message:flags.1?bytes statistics:flags.2?bytes
//	payment:flags.3?bytes rand2:bytes = adnl.TunnelPacketContents
type TunnelPacketContents struct {
	Rand1      []byte // Random padding at start (traffic analysis resistance)
	Flags      uint32 // Bit flags indicating which optional fields are present
	FromIP     uint32 // Source IP (if flags & 1)
	FromPort   uint16 // Source port (if flags & 1)
	Message    []byte // The actual payload (if flags & 2)
	Statistics []byte // Statistics data (if flags & 4)
	Payment    []byte // Payment data (if flags & 8)
	Rand2      []byte // Random padding at end (traffic analysis resistance)
}

const (
	FlagHasSourceAddr = 1 << 0 // Has FromIP and FromPort
	FlagHasMessage    = 1 << 1 // Has Message payload
	FlagHasStatistics = 1 << 2 // Has Statistics
	FlagHasPayment    = 1 << 3 // Has Payment
)

// TL constructor ID for adnl.tunnelPacketContents
// CRC32 of "adnl.tunnelPacketContents rand1:bytes flags:# from_ip:flags.0?int from_port:flags.0?int message:flags.1?bytes statistics:flags.2?bytes payment:flags.3?bytes rand2:bytes = adnl.TunnelPacketContents"
const TunnelPacketContentsTLID uint32 = 0xc59138b4

// Default random padding sizes
const (
	MinRandPadding = 7
	MaxRandPadding = 15
)

// generateRandomPadding creates random bytes for traffic obfuscation
func generateRandomPadding(minSize, maxSize int) []byte {
	// Random size between min and max
	sizeRange := maxSize - minSize + 1
	var sizeByte [1]byte
	rand.Read(sizeByte[:])
	size := minSize + int(sizeByte[0])%sizeRange

	padding := make([]byte, size)
	rand.Read(padding)
	return padding
}

// Serialize converts the packet contents to bytes (TL boxed format with constructor ID)
func (p *TunnelPacketContents) Serialize() ([]byte, error) {
	// Generate random padding if not set
	if p.Rand1 == nil {
		p.Rand1 = generateRandomPadding(MinRandPadding, MaxRandPadding)
	}
	if p.Rand2 == nil {
		p.Rand2 = generateRandomPadding(MinRandPadding, MaxRandPadding)
	}

	// Calculate size
	size := 4 // TL constructor ID

	// rand1: length prefix (4 bytes) + data + alignment
	rand1Aligned := alignedLen(len(p.Rand1))
	size += 4 + rand1Aligned

	// flags
	size += 4

	if p.Flags&FlagHasSourceAddr != 0 {
		size += 4 + 4 // IP (int) + Port (int in TL, but we use 2 bytes effectively)
	}

	if p.Flags&FlagHasMessage != 0 {
		size += 4 + alignedLen(len(p.Message))
	}

	if p.Flags&FlagHasStatistics != 0 {
		size += 4 + alignedLen(len(p.Statistics))
	}

	if p.Flags&FlagHasPayment != 0 {
		size += 4 + alignedLen(len(p.Payment))
	}

	// rand2
	rand2Aligned := alignedLen(len(p.Rand2))
	size += 4 + rand2Aligned

	buf := make([]byte, size)
	offset := 0

	// Write TL constructor ID
	binary.LittleEndian.PutUint32(buf[offset:], TunnelPacketContentsTLID)
	offset += 4

	// Write rand1 (TL bytes format)
	offset += writeBytes(buf[offset:], p.Rand1)

	// Write flags
	binary.LittleEndian.PutUint32(buf[offset:], p.Flags)
	offset += 4

	// Write source address if present
	if p.Flags&FlagHasSourceAddr != 0 {
		binary.LittleEndian.PutUint32(buf[offset:], p.FromIP)
		offset += 4
		// Port is stored as int32 in TL
		binary.LittleEndian.PutUint32(buf[offset:], uint32(p.FromPort))
		offset += 4
	}

	// Write message if present
	if p.Flags&FlagHasMessage != 0 {
		offset += writeBytes(buf[offset:], p.Message)
	}

	// Write statistics if present
	if p.Flags&FlagHasStatistics != 0 {
		offset += writeBytes(buf[offset:], p.Statistics)
	}

	// Write payment if present
	if p.Flags&FlagHasPayment != 0 {
		offset += writeBytes(buf[offset:], p.Payment)
	}

	// Write rand2
	writeBytes(buf[offset:], p.Rand2)

	return buf, nil
}

// Parse deserializes packet contents from bytes (TL boxed format with constructor ID)
func (p *TunnelPacketContents) Parse(data []byte) error {
	if len(data) < 12 { // minimum: TL ID + rand1 length + flags
		return ErrPacketTooShort
	}

	offset := 0

	// Verify TL constructor ID
	tlID := binary.LittleEndian.Uint32(data[offset:])
	if tlID != TunnelPacketContentsTLID {
		return fmt.Errorf("invalid TL ID: got 0x%08x, expected 0x%08x", tlID, TunnelPacketContentsTLID)
	}
	offset += 4

	// Read rand1
	rand1, n, err := readBytes(data[offset:])
	if err != nil {
		return fmt.Errorf("read rand1: %w", err)
	}
	p.Rand1 = rand1
	offset += n

	if len(data) < offset+4 {
		return ErrPacketTooShort
	}

	// Read flags
	p.Flags = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	// Read source address if present
	if p.Flags&FlagHasSourceAddr != 0 {
		if len(data) < offset+8 {
			return ErrPacketTooShort
		}
		p.FromIP = binary.LittleEndian.Uint32(data[offset:])
		offset += 4
		p.FromPort = uint16(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
	}

	// Read message if present
	if p.Flags&FlagHasMessage != 0 {
		msg, n, err := readBytes(data[offset:])
		if err != nil {
			return fmt.Errorf("read message: %w", err)
		}
		p.Message = msg
		offset += n
	}

	// Read statistics if present
	if p.Flags&FlagHasStatistics != 0 {
		stats, n, err := readBytes(data[offset:])
		if err != nil {
			return fmt.Errorf("read statistics: %w", err)
		}
		p.Statistics = stats
		offset += n
	}

	// Read payment if present
	if p.Flags&FlagHasPayment != 0 {
		payment, n, err := readBytes(data[offset:])
		if err != nil {
			return fmt.Errorf("read payment: %w", err)
		}
		p.Payment = payment
		offset += n
	}

	// Read rand2
	rand2, _, err := readBytes(data[offset:])
	if err != nil {
		return fmt.Errorf("read rand2: %w", err)
	}
	p.Rand2 = rand2

	return nil
}

// NewTunnelPacket creates a new tunnel packet with message
func NewTunnelPacket(message []byte, srcAddr net.Addr) *TunnelPacketContents {
	p := &TunnelPacketContents{
		Flags:   FlagHasMessage,
		Message: message,
		Rand1:   generateRandomPadding(MinRandPadding, MaxRandPadding),
		Rand2:   generateRandomPadding(MinRandPadding, MaxRandPadding),
	}

	// Add source address if available
	if udpAddr, ok := srcAddr.(*net.UDPAddr); ok && udpAddr != nil {
		p.Flags |= FlagHasSourceAddr
		p.FromIP = ipToUint32(udpAddr.IP)
		p.FromPort = uint16(udpAddr.Port)
	}

	return p
}

// NewTunnelPacketWithStats creates a tunnel packet with statistics
func NewTunnelPacketWithStats(message []byte, srcAddr net.Addr, stats []byte) *TunnelPacketContents {
	p := NewTunnelPacket(message, srcAddr)
	if len(stats) > 0 {
		p.Flags |= FlagHasStatistics
		p.Statistics = stats
	}
	return p
}

// NewTunnelPacketWithPayment creates a tunnel packet with payment data
func NewTunnelPacketWithPayment(message []byte, srcAddr net.Addr, payment []byte) *TunnelPacketContents {
	p := NewTunnelPacket(message, srcAddr)
	if len(payment) > 0 {
		p.Flags |= FlagHasPayment
		p.Payment = payment
	}
	return p
}

// GetSourceAddr returns the source address as net.Addr
func (p *TunnelPacketContents) GetSourceAddr() net.Addr {
	if p.Flags&FlagHasSourceAddr == 0 {
		return nil
	}

	ip := uint32ToIP(p.FromIP)
	return &net.UDPAddr{
		IP:   ip,
		Port: int(p.FromPort),
	}
}

// ProxyPacketHeader represents the header for proxy packets
// Based on adnl.proxyPacketHeader from TON TL schema
type ProxyPacketHeader struct {
	ProxyID       [32]byte
	Flags         uint32
	IP            uint32 // if flags & 1
	Port          uint16 // if flags & 1
	ADNLStartTime int32  // if flags & 2
	Seqno         int64  // if flags & 4
	Date          int32  // if flags & 8
	Signature     [32]byte
}

const (
	ProxyFlagHasAddr      = 1 << 0
	ProxyFlagHasStartTime = 1 << 1
	ProxyFlagHasSeqno     = 1 << 2
	ProxyFlagHasDate      = 1 << 3
	// Flags 16-17 are used for control packets
	ProxyFlagIsControl    = 1 << 16 // Marks packet as control packet
	ProxyFlagHasControlTL = 1 << 17 // Data contains TL-serialized control packet
)

// TL constructor ID for adnl.proxyPacketHeader
// CRC32 of "adnl.proxyPacketHeader proxy_id:int256 flags:# ip:flags.0?int port:flags.0?int adnl_start_time:flags.1?int seqno:flags.2?long date:flags.3?int signature:int256 = adnl.ProxyPacketHeader"
const ProxyPacketHeaderTLID uint32 = 0x08693c78

// Serialize converts the proxy header to bytes (TL boxed format with constructor ID)
func (h *ProxyPacketHeader) Serialize() ([]byte, error) {
	size := 4 + 32 + 4 + 32 // TL ID + ProxyID + Flags + Signature (minimum)

	if h.Flags&ProxyFlagHasAddr != 0 {
		size += 4 + 4 // IP + Port (as int32)
	}
	if h.Flags&ProxyFlagHasStartTime != 0 {
		size += 4
	}
	if h.Flags&ProxyFlagHasSeqno != 0 {
		size += 8
	}
	if h.Flags&ProxyFlagHasDate != 0 {
		size += 4
	}

	buf := make([]byte, size)
	offset := 0

	// TL constructor ID (boxed format)
	binary.LittleEndian.PutUint32(buf[offset:], ProxyPacketHeaderTLID)
	offset += 4

	copy(buf[offset:], h.ProxyID[:])
	offset += 32

	binary.LittleEndian.PutUint32(buf[offset:], h.Flags)
	offset += 4

	if h.Flags&ProxyFlagHasAddr != 0 {
		binary.LittleEndian.PutUint32(buf[offset:], h.IP)
		offset += 4
		binary.LittleEndian.PutUint32(buf[offset:], uint32(h.Port))
		offset += 4
	}

	if h.Flags&ProxyFlagHasStartTime != 0 {
		binary.LittleEndian.PutUint32(buf[offset:], uint32(h.ADNLStartTime))
		offset += 4
	}

	if h.Flags&ProxyFlagHasSeqno != 0 {
		binary.LittleEndian.PutUint64(buf[offset:], uint64(h.Seqno))
		offset += 8
	}

	if h.Flags&ProxyFlagHasDate != 0 {
		binary.LittleEndian.PutUint32(buf[offset:], uint32(h.Date))
		offset += 4
	}

	copy(buf[offset:], h.Signature[:])

	return buf, nil
}

// SerializeForSigning returns the header bytes without signature (for signing)
func (h *ProxyPacketHeader) SerializeForSigning() ([]byte, error) {
	size := 32 + 4 // ProxyID + Flags

	if h.Flags&ProxyFlagHasAddr != 0 {
		size += 4 + 4
	}
	if h.Flags&ProxyFlagHasStartTime != 0 {
		size += 4
	}
	if h.Flags&ProxyFlagHasSeqno != 0 {
		size += 8
	}
	if h.Flags&ProxyFlagHasDate != 0 {
		size += 4
	}

	buf := make([]byte, size)
	offset := 0

	copy(buf[offset:], h.ProxyID[:])
	offset += 32

	binary.LittleEndian.PutUint32(buf[offset:], h.Flags)
	offset += 4

	if h.Flags&ProxyFlagHasAddr != 0 {
		binary.LittleEndian.PutUint32(buf[offset:], h.IP)
		offset += 4
		binary.LittleEndian.PutUint32(buf[offset:], uint32(h.Port))
		offset += 4
	}

	if h.Flags&ProxyFlagHasStartTime != 0 {
		binary.LittleEndian.PutUint32(buf[offset:], uint32(h.ADNLStartTime))
		offset += 4
	}

	if h.Flags&ProxyFlagHasSeqno != 0 {
		binary.LittleEndian.PutUint64(buf[offset:], uint64(h.Seqno))
		offset += 8
	}

	if h.Flags&ProxyFlagHasDate != 0 {
		binary.LittleEndian.PutUint32(buf[offset:], uint32(h.Date))
	}

	return buf, nil
}

// Parse deserializes proxy header from bytes (TL boxed format with constructor ID)
func (h *ProxyPacketHeader) Parse(data []byte) error {
	if len(data) < 72 { // Minimum: 4 (TL ID) + 32 + 4 + 32
		return ErrPacketTooShort
	}

	offset := 0

	// Verify TL constructor ID
	tlID := binary.LittleEndian.Uint32(data[offset:])
	if tlID != ProxyPacketHeaderTLID {
		return fmt.Errorf("invalid TL ID: got 0x%08x, expected 0x%08x", tlID, ProxyPacketHeaderTLID)
	}
	offset += 4

	copy(h.ProxyID[:], data[offset:offset+32])
	offset += 32

	h.Flags = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	if h.Flags&ProxyFlagHasAddr != 0 {
		if len(data) < offset+8 {
			return ErrPacketTooShort
		}
		h.IP = binary.LittleEndian.Uint32(data[offset:])
		offset += 4
		h.Port = uint16(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
	}

	if h.Flags&ProxyFlagHasStartTime != 0 {
		if len(data) < offset+4 {
			return ErrPacketTooShort
		}
		h.ADNLStartTime = int32(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
	}

	if h.Flags&ProxyFlagHasSeqno != 0 {
		if len(data) < offset+8 {
			return ErrPacketTooShort
		}
		h.Seqno = int64(binary.LittleEndian.Uint64(data[offset:]))
		offset += 8
	}

	if h.Flags&ProxyFlagHasDate != 0 {
		if len(data) < offset+4 {
			return ErrPacketTooShort
		}
		h.Date = int32(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
	}

	if len(data) < offset+32 {
		return ErrPacketTooShort
	}
	copy(h.Signature[:], data[offset:offset+32])

	return nil
}

// HeaderSize returns the size of the parsed header (including TL ID)
func (h *ProxyPacketHeader) HeaderSize() int {
	size := 4 + 32 + 4 + 32 // TL ID + ProxyID + Flags + Signature

	if h.Flags&ProxyFlagHasAddr != 0 {
		size += 8
	}
	if h.Flags&ProxyFlagHasStartTime != 0 {
		size += 4
	}
	if h.Flags&ProxyFlagHasSeqno != 0 {
		size += 8
	}
	if h.Flags&ProxyFlagHasDate != 0 {
		size += 4
	}

	return size
}

// Helper functions

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

// alignedLen returns length aligned to 4 bytes
func alignedLen(n int) int {
	return (n + 3) &^ 3
}

// writeBytes writes TL bytes format (length prefix + data + padding)
func writeBytes(buf []byte, data []byte) int {
	n := len(data)
	offset := 0

	if n < 254 {
		buf[0] = byte(n)
		offset = 1
	} else {
		buf[0] = 254
		buf[1] = byte(n)
		buf[2] = byte(n >> 8)
		buf[3] = byte(n >> 16)
		offset = 4
	}

	copy(buf[offset:], data)
	offset += n

	// Padding to 4-byte alignment
	padding := (4 - (offset % 4)) % 4
	for i := 0; i < padding; i++ {
		buf[offset+i] = 0
	}

	return offset + padding
}

// readBytes reads TL bytes format
func readBytes(data []byte) ([]byte, int, error) {
	if len(data) < 1 {
		return nil, 0, ErrPacketTooShort
	}

	var n int
	var offset int

	if data[0] < 254 {
		n = int(data[0])
		offset = 1
	} else {
		if len(data) < 4 {
			return nil, 0, ErrPacketTooShort
		}
		n = int(data[1]) | int(data[2])<<8 | int(data[3])<<16
		offset = 4
	}

	if len(data) < offset+n {
		return nil, 0, ErrPacketTooShort
	}

	result := make([]byte, n)
	copy(result, data[offset:offset+n])

	// Skip padding
	totalLen := offset + n
	padding := (4 - (totalLen % 4)) % 4
	totalLen += padding

	return result, totalLen, nil
}

// BuildTunnelDatagram creates a complete tunnel datagram ready for sending
// Format: [key_hash(32)] + [encrypted_packet]
func BuildTunnelDatagram(keyHash [32]byte, encryptedData []byte) []byte {
	result := make([]byte, 32+len(encryptedData))
	copy(result[:32], keyHash[:])
	copy(result[32:], encryptedData)
	return result
}

// ParseTunnelDatagram extracts key hash and encrypted data from a datagram
func ParseTunnelDatagram(data []byte) (keyHash [32]byte, encrypted []byte, err error) {
	if len(data) < 33 { // 32 key hash + at least 1 byte of data
		return [32]byte{}, nil, fmt.Errorf("datagram too short: %d bytes", len(data))
	}

	copy(keyHash[:], data[:32])
	encrypted = data[32:]
	return keyHash, encrypted, nil
}
