package tunnel

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
	"time"
)

// Proxy interface for different proxy types
type Proxy interface {
	// Encrypt encrypts a packet for sending through the proxy
	Encrypt(packet *ProxyPacket) ([]byte, error)
	// Decrypt decrypts a packet received from the proxy
	Decrypt(data []byte) (*ProxyPacket, error)
	// GetID returns the proxy ID
	GetID() [32]byte
}

// ProxyPacket represents a decrypted proxy packet
type ProxyPacket struct {
	IP       uint32
	Port     uint16
	Seqno    int64
	Date     int32
	Flags    uint32 // Header flags (includes control packet indicators)
	Data     []byte
	FromAddr net.Addr
}

// IsControl returns true if this is a control packet (flag 17 set)
func (p *ProxyPacket) IsControl() bool {
	return p.Flags&ProxyFlagHasControlTL != 0
}

// ProxyNoneImpl implements the adnl.proxy.none type
// No encryption, just ID verification
type ProxyNoneImpl struct {
	ID [32]byte
}

// NewProxyNone creates a new ProxyNone instance
func NewProxyNone(id [32]byte) *ProxyNoneImpl {
	return &ProxyNoneImpl{ID: id}
}

// GetID returns the proxy ID
func (p *ProxyNoneImpl) GetID() [32]byte {
	return p.ID
}

// Encrypt for ProxyNone just prepends the ID
func (p *ProxyNoneImpl) Encrypt(packet *ProxyPacket) ([]byte, error) {
	result := make([]byte, 32+len(packet.Data))
	copy(result[:32], p.ID[:])
	copy(result[32:], packet.Data)
	return result, nil
}

// Decrypt for ProxyNone just verifies the ID
func (p *ProxyNoneImpl) Decrypt(data []byte) (*ProxyPacket, error) {
	if len(data) < 32 {
		return nil, ErrPacketTooShort
	}

	// Verify ID
	var id [32]byte
	copy(id[:], data[:32])
	if id != p.ID {
		return nil, ErrInvalidProxyID
	}

	return &ProxyPacket{
		Data: data[32:],
	}, nil
}

// ProxyFastImpl implements the adnl.proxy.fast type
// Uses shared secret for HMAC-style signature verification
// Compatible with TON's adnl-proxy-types.cpp implementation
type ProxyFastImpl struct {
	ID           [32]byte
	SharedSecret [32]byte // MUST be exactly 32 bytes

	// Security state
	mu            sync.Mutex
	seqnoTracker  *SeqnoTracker
	adnlStartTime int32
}

// NewProxyFast creates a new ProxyFast instance
// sharedSecret MUST be exactly 32 bytes
func NewProxyFast(id [32]byte, sharedSecret []byte) *ProxyFastImpl {
	var secret [32]byte
	if len(sharedSecret) >= 32 {
		copy(secret[:], sharedSecret[:32])
	} else {
		copy(secret[:], sharedSecret)
	}

	return &ProxyFastImpl{
		ID:            id,
		SharedSecret:  secret,
		seqnoTracker:  NewSeqnoTracker(),
		adnlStartTime: int32(time.Now().Unix()),
	}
}

// GetID returns the proxy ID
func (p *ProxyFastImpl) GetID() [32]byte {
	return p.ID
}

// Encrypt encrypts a packet using the ProxyFast protocol
// Algorithm (matching TON C++ implementation):
// 1. Create header with signature = SHA256(payload)
// 2. Serialize full header (including data hash in signature field)
// 3. Compute headerHash = SHA256(serialized header)
// 4. Compute final signature = SHA256(headerHash + sharedSecret)
// 5. Replace signature field with final signature
func (p *ProxyFastImpl) Encrypt(packet *ProxyPacket) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Build header with data hash as temporary signature
	dataHash := sha256.Sum256(packet.Data)

	header := &ProxyPacketHeader{
		ProxyID:   p.ID,
		Flags:     0,
		Signature: dataHash, // Step 1: Put data hash in signature field
	}

	// Set date
	if packet.Date == 0 {
		header.Date = int32(time.Now().Unix())
	} else {
		header.Date = packet.Date
	}
	header.Flags |= ProxyFlagHasDate

	// Set seqno
	header.Seqno = packet.Seqno
	header.Flags |= ProxyFlagHasSeqno

	// Add address if provided
	if packet.IP != 0 || packet.Port != 0 {
		header.Flags |= ProxyFlagHasAddr
		header.IP = packet.IP
		header.Port = packet.Port
	}

	// Add start time
	header.Flags |= ProxyFlagHasStartTime
	header.ADNLStartTime = p.adnlStartTime

	// Step 2: Serialize header with data hash as signature
	headerWithDataHash, err := header.Serialize()
	if err != nil {
		return nil, fmt.Errorf("serialize header: %w", err)
	}

	// Step 3: Compute hash of the full serialized header
	headerHash := sha256.Sum256(headerWithDataHash)

	// Step 4: Compute final signature = SHA256(headerHash + sharedSecret)
	// Exactly 64 bytes as in the C++ implementation
	var signatureInput [64]byte
	copy(signatureInput[:32], headerHash[:])
	copy(signatureInput[32:], p.SharedSecret[:])
	header.Signature = sha256.Sum256(signatureInput[:])

	// Step 5: Serialize with final signature
	fullHeader, err := header.Serialize()
	if err != nil {
		return nil, fmt.Errorf("serialize full header: %w", err)
	}

	result := make([]byte, len(fullHeader)+len(packet.Data))
	copy(result, fullHeader)
	copy(result[len(fullHeader):], packet.Data)

	return result, nil
}

// Decrypt decrypts a packet using the ProxyFast protocol
// Algorithm (matching TON C++ implementation):
// 1. Parse header, save received signature
// 2. Replace signature with SHA256(payload)
// 3. Serialize header, compute headerHash
// 4. Compute expected signature = SHA256(headerHash + sharedSecret)
// 5. Compare with received signature
func (p *ProxyFastImpl) Decrypt(data []byte) (*ProxyPacket, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Parse header
	header := &ProxyPacketHeader{}
	if err := header.Parse(data); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	// Verify proxy ID
	if header.ProxyID != p.ID {
		return nil, ErrInvalidProxyID
	}

	// Step 1: Save received signature
	receivedSignature := header.Signature

	// Extract payload
	headerSize := header.HeaderSize()
	if len(data) < headerSize {
		return nil, ErrPacketTooShort
	}
	payload := data[headerSize:]

	// Step 2: Replace signature with SHA256(payload)
	header.Signature = sha256.Sum256(payload)

	// Step 3: Serialize header and compute hash
	headerWithDataHash, err := header.Serialize()
	if err != nil {
		return nil, fmt.Errorf("serialize for verification: %w", err)
	}
	headerHash := sha256.Sum256(headerWithDataHash)

	// Step 4: Compute expected signature = SHA256(headerHash + sharedSecret)
	var signatureInput [64]byte
	copy(signatureInput[:32], headerHash[:])
	copy(signatureInput[32:], p.SharedSecret[:])
	expectedSignature := sha256.Sum256(signatureInput[:])

	// Step 5: Compare signatures
	if receivedSignature != expectedSignature {
		return nil, ErrInvalidSignature
	}

	// Validate timestamp (±60 seconds)
	if header.Flags&ProxyFlagHasDate != 0 {
		now := int32(time.Now().Unix())
		if header.Date < now-TimestampTolerance || header.Date > now+TimestampTolerance {
			return nil, ErrTimestampExpired
		}
	}

	// Check sequence number for replay protection
	if header.Flags&ProxyFlagHasSeqno != 0 {
		if !p.seqnoTracker.Check(header.Seqno) {
			return nil, ErrReplayDetected
		}
	}

	return &ProxyPacket{
		IP:    header.IP,
		Port:  header.Port,
		Seqno: header.Seqno,
		Date:  header.Date,
		Flags: header.Flags,
		Data:  payload,
	}, nil
}

// SetStartTime sets the ADNL start time
func (p *ProxyFastImpl) SetStartTime(t int32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.adnlStartTime = t
}

// EncryptControlPacket encrypts a control packet with proper flags
// Control packets have flags (ProxyFlagHasStartTime | ProxyFlagHasSeqno | ProxyFlagIsControl | ProxyFlagHasControlTL)
func (p *ProxyFastImpl) EncryptControlPacket(controlData []byte, seqno int64, srcIP uint32, srcPort uint16) ([]byte, error) {
	packet := &ProxyPacket{
		Data:  controlData,
		Seqno: seqno,
		Date:  int32(time.Now().Unix()),
		IP:    srcIP,
		Port:  srcPort,
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Build header with data hash as temporary signature
	dataHash := sha256.Sum256(packet.Data)

	// Control packets use: starttime + seqno + control flags + optional address
	flags := uint32(ProxyFlagHasStartTime | ProxyFlagHasSeqno | ProxyFlagHasDate | ProxyFlagIsControl | ProxyFlagHasControlTL)
	if packet.IP != 0 || packet.Port != 0 {
		flags |= ProxyFlagHasAddr
	}

	header := &ProxyPacketHeader{
		ProxyID:       p.ID,
		Flags:         flags,
		Signature:     dataHash,
		ADNLStartTime: p.adnlStartTime,
		Seqno:         seqno,
		Date:          packet.Date,
		IP:            packet.IP,
		Port:          packet.Port,
	}

	// Serialize header with data hash as signature
	headerWithDataHash, err := header.Serialize()
	if err != nil {
		return nil, fmt.Errorf("serialize header: %w", err)
	}

	// Compute hash of the full serialized header
	headerHash := sha256.Sum256(headerWithDataHash)

	// Compute final signature = SHA256(headerHash + sharedSecret)
	var signatureInput [64]byte
	copy(signatureInput[:32], headerHash[:])
	copy(signatureInput[32:], p.SharedSecret[:])
	header.Signature = sha256.Sum256(signatureInput[:])

	// Serialize with final signature
	fullHeader, err := header.Serialize()
	if err != nil {
		return nil, fmt.Errorf("serialize full header: %w", err)
	}

	result := make([]byte, len(fullHeader)+len(packet.Data))
	copy(result, fullHeader)
	copy(result[len(fullHeader):], packet.Data)

	return result, nil
}

// IsControlPacket checks if the flags indicate a control packet
func IsProxyControlPacket(flags uint32) bool {
	return flags&ProxyFlagHasControlTL != 0
}

// Timestamp tolerance in seconds (±60 seconds as per TON spec)
const TimestampTolerance = 60

// SeqnoTracker tracks sequence numbers for replay protection
// Uses a sliding window approach similar to TON's AdnlReceivedMaskVersion
type SeqnoTracker struct {
	mu          sync.Mutex
	maxSeqno    int64
	windowSize  int
	receivedMap map[int64]bool
}

// NewSeqnoTracker creates a new sequence number tracker
func NewSeqnoTracker() *SeqnoTracker {
	return &SeqnoTracker{
		windowSize:  1024, // Track last 1024 sequence numbers
		receivedMap: make(map[int64]bool),
	}
}

// Check verifies if a sequence number is valid (not replayed)
// Returns true if valid, false if replay detected
func (s *SeqnoTracker) Check(seqno int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If seqno is too old (outside window), reject
	if seqno <= s.maxSeqno-int64(s.windowSize) {
		return false
	}

	// If already received, it's a replay
	if s.receivedMap[seqno] {
		return false
	}

	// Mark as received
	s.receivedMap[seqno] = true

	// Update max if needed
	if seqno > s.maxSeqno {
		s.maxSeqno = seqno

		// Clean up old entries outside window
		for oldSeqno := range s.receivedMap {
			if oldSeqno <= s.maxSeqno-int64(s.windowSize) {
				delete(s.receivedMap, oldSeqno)
			}
		}
	}

	return true
}

// Reset clears the tracker state
func (s *SeqnoTracker) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxSeqno = 0
	s.receivedMap = make(map[int64]bool)
}

// ValidateTimestamp checks if a timestamp is within acceptable range
func ValidateTimestamp(timestamp int32) error {
	now := int32(time.Now().Unix())
	if timestamp < now-TimestampTolerance {
		return ErrTimestampExpired
	}
	if timestamp > now+TimestampTolerance {
		return fmt.Errorf("timestamp too far in future")
	}
	return nil
}

// ProxyToFastHash represents adnl.proxyToFastHash
// Used for fast proxy destination addressing with hash verification
type ProxyToFastHash struct {
	IP           uint32
	Port         int32
	Date         int32
	DataHash     [32]byte
	SharedSecret [32]byte
}

// ProxyToFast represents adnl.proxyToFast
// Used for signed proxy destination addressing
type ProxyToFast struct {
	IP        uint32
	Port      int32
	Date      int32
	Signature [32]byte
}

// ComputeHash computes the hash for ProxyToFastHash
func (p *ProxyToFastHash) ComputeHash() [32]byte {
	// Serialize the fields
	data := make([]byte, 4+4+4+32+32)
	offset := 0

	// IP
	data[offset] = byte(p.IP)
	data[offset+1] = byte(p.IP >> 8)
	data[offset+2] = byte(p.IP >> 16)
	data[offset+3] = byte(p.IP >> 24)
	offset += 4

	// Port
	data[offset] = byte(p.Port)
	data[offset+1] = byte(p.Port >> 8)
	data[offset+2] = byte(p.Port >> 16)
	data[offset+3] = byte(p.Port >> 24)
	offset += 4

	// Date
	data[offset] = byte(p.Date)
	data[offset+1] = byte(p.Date >> 8)
	data[offset+2] = byte(p.Date >> 16)
	data[offset+3] = byte(p.Date >> 24)
	offset += 4

	// DataHash
	copy(data[offset:], p.DataHash[:])
	offset += 32

	// SharedSecret
	copy(data[offset:], p.SharedSecret[:])

	return sha256.Sum256(data)
}
