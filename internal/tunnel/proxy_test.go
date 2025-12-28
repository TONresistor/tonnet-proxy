package tunnel

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestProxyNone(t *testing.T) {
	var id [32]byte
	rand.Read(id[:])

	proxy := NewProxyNone(id)

	// Test encrypt
	data := []byte("test message")
	packet := &ProxyPacket{Data: data}

	encrypted, err := proxy.Encrypt(packet)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Should be: id(32) + data
	if len(encrypted) != 32+len(data) {
		t.Errorf("wrong encrypted length: got %d, want %d", len(encrypted), 32+len(data))
	}

	// Verify ID is prepended
	if !bytes.Equal(encrypted[:32], id[:]) {
		t.Error("ID not correctly prepended")
	}

	// Test decrypt
	decrypted, err := proxy.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted.Data, data) {
		t.Errorf("data mismatch: got %x, want %x", decrypted.Data, data)
	}
}

func TestProxyNoneInvalidID(t *testing.T) {
	var id [32]byte
	rand.Read(id[:])

	proxy := NewProxyNone(id)

	// Create packet with wrong ID
	var wrongID [32]byte
	rand.Read(wrongID[:])
	wrongPacket := make([]byte, 32+10)
	copy(wrongPacket[:32], wrongID[:])

	_, err := proxy.Decrypt(wrongPacket)
	if err != ErrInvalidProxyID {
		t.Errorf("expected ErrInvalidProxyID, got %v", err)
	}
}

func TestProxyFast(t *testing.T) {
	var id [32]byte
	rand.Read(id[:])

	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	proxy := NewProxyFast(id, sharedSecret)

	// Test encrypt/decrypt
	data := []byte("test message for fast proxy")
	packet := &ProxyPacket{
		Data:  data,
		Seqno: 1,
		Date:  int32(time.Now().Unix()),
	}

	encrypted, err := proxy.Encrypt(packet)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	t.Logf("Encrypted packet: %d bytes", len(encrypted))

	// Decrypt
	decrypted, err := proxy.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted.Data, data) {
		t.Errorf("data mismatch: got %x, want %x", decrypted.Data, data)
	}

	if decrypted.Seqno != packet.Seqno {
		t.Errorf("seqno mismatch: got %d, want %d", decrypted.Seqno, packet.Seqno)
	}
}

func TestProxyFastInvalidSignature(t *testing.T) {
	var id [32]byte
	rand.Read(id[:])

	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	proxy := NewProxyFast(id, sharedSecret)

	// Create a valid encrypted packet
	data := []byte("test message")
	packet := &ProxyPacket{Data: data, Seqno: 1}

	encrypted, err := proxy.Encrypt(packet)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Corrupt the signature (last 32 bytes of header, before data)
	// The header is variable size, but signature is at end of header
	// Let's corrupt a byte in the middle which should affect the signature
	encrypted[40] ^= 0xFF

	_, err = proxy.Decrypt(encrypted)
	if err == nil {
		t.Error("expected error for corrupted signature")
	}
}

func TestProxyFastTimestampValidation(t *testing.T) {
	var id [32]byte
	rand.Read(id[:])

	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	proxy := NewProxyFast(id, sharedSecret)

	// Create packet with old timestamp
	data := []byte("test message")
	packet := &ProxyPacket{
		Data:  data,
		Seqno: 1,
		Date:  int32(time.Now().Unix()) - 120, // 2 minutes ago
	}

	encrypted, err := proxy.Encrypt(packet)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = proxy.Decrypt(encrypted)
	if err != ErrTimestampExpired {
		t.Errorf("expected ErrTimestampExpired, got %v", err)
	}
}

func TestProxyFastReplayProtection(t *testing.T) {
	var id [32]byte
	rand.Read(id[:])

	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	proxy := NewProxyFast(id, sharedSecret)

	// Create and process first packet
	data := []byte("test message")
	packet := &ProxyPacket{Data: data, Seqno: 100}

	encrypted, err := proxy.Encrypt(packet)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = proxy.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("First decrypt failed: %v", err)
	}

	// Create another proxy with same config (simulating replay)
	proxy2 := NewProxyFast(id, sharedSecret)

	// Pre-populate the seqno tracker with seqno 100
	proxy2.seqnoTracker.Check(100)

	// Try to decrypt same packet (replay)
	_, err = proxy2.Decrypt(encrypted)
	if err != ErrReplayDetected {
		t.Errorf("expected ErrReplayDetected, got %v", err)
	}
}

func TestSeqnoTracker(t *testing.T) {
	tracker := NewSeqnoTracker()

	// First seqno should be valid
	if !tracker.Check(1) {
		t.Error("seqno 1 should be valid")
	}

	// Replay should fail
	if tracker.Check(1) {
		t.Error("replay of seqno 1 should fail")
	}

	// Higher seqno should be valid
	if !tracker.Check(100) {
		t.Error("seqno 100 should be valid")
	}

	// Seqno within window should be valid
	if !tracker.Check(50) {
		t.Error("seqno 50 should be valid")
	}

	// Replay of 50 should fail
	if tracker.Check(50) {
		t.Error("replay of seqno 50 should fail")
	}
}

func TestSeqnoTrackerWindow(t *testing.T) {
	tracker := NewSeqnoTracker()
	tracker.windowSize = 10 // Small window for testing

	// Fill up the window
	for i := int64(1); i <= 15; i++ {
		tracker.Check(i)
	}

	// Old seqno (outside window) should fail
	if tracker.Check(1) {
		t.Error("seqno 1 should be outside window and fail")
	}

	// Recent seqno (inside window) should fail (replay)
	if tracker.Check(10) {
		t.Error("seqno 10 replay should fail")
	}

	// New seqno should work
	if !tracker.Check(20) {
		t.Error("seqno 20 should be valid")
	}
}

func TestValidateTimestamp(t *testing.T) {
	// Valid timestamp (now)
	if err := ValidateTimestamp(int32(time.Now().Unix())); err != nil {
		t.Errorf("current timestamp should be valid: %v", err)
	}

	// Valid timestamp (30 seconds ago)
	if err := ValidateTimestamp(int32(time.Now().Unix()) - 30); err != nil {
		t.Errorf("timestamp 30s ago should be valid: %v", err)
	}

	// Invalid timestamp (too old)
	if err := ValidateTimestamp(int32(time.Now().Unix()) - 120); err == nil {
		t.Error("timestamp 2min ago should be invalid")
	}

	// Invalid timestamp (too far in future)
	if err := ValidateTimestamp(int32(time.Now().Unix()) + 120); err == nil {
		t.Error("timestamp 2min in future should be invalid")
	}
}

func BenchmarkProxyFastEncrypt(b *testing.B) {
	var id [32]byte
	rand.Read(id[:])

	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	proxy := NewProxyFast(id, sharedSecret)

	data := make([]byte, 1024)
	rand.Read(data)

	packet := &ProxyPacket{Data: data, Seqno: 1}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		packet.Seqno = int64(i)
		proxy.Encrypt(packet)
	}
}

func BenchmarkProxyFastDecrypt(b *testing.B) {
	var id [32]byte
	rand.Read(id[:])

	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	proxy := NewProxyFast(id, sharedSecret)

	data := make([]byte, 1024)
	rand.Read(data)

	packet := &ProxyPacket{Data: data, Seqno: 1}
	encrypted, _ := proxy.Encrypt(packet)

	// Reset seqno tracker for benchmark
	proxy.seqnoTracker = NewSeqnoTracker()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		proxy.seqnoTracker.Reset() // Allow same packet to be decrypted
		proxy.Decrypt(encrypted)
	}
}

func TestProxyFastControlPacket(t *testing.T) {
	var id [32]byte
	rand.Read(id[:])

	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	proxy := NewProxyFast(id, sharedSecret)

	// Create a ping control packet
	var pingID [32]byte
	rand.Read(pingID[:])
	ping := &ControlPacketPing{ID: pingID}
	controlData := ping.Serialize()

	// Encrypt as control packet
	encrypted, err := proxy.EncryptControlPacket(controlData, 1, 0x7F000001, 8080)
	if err != nil {
		t.Fatalf("EncryptControlPacket failed: %v", err)
	}

	t.Logf("Control packet encrypted: %d bytes", len(encrypted))

	// Decrypt
	decrypted, err := proxy.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt control packet failed: %v", err)
	}

	// Verify it's a control packet
	if !decrypted.IsControl() {
		t.Error("decrypted packet should be marked as control")
	}

	// Verify flags have control bits set
	if decrypted.Flags&ProxyFlagIsControl == 0 {
		t.Error("ProxyFlagIsControl should be set")
	}
	if decrypted.Flags&ProxyFlagHasControlTL == 0 {
		t.Error("ProxyFlagHasControlTL should be set")
	}

	// Parse the control packet
	parsed, err := ParseControlPacket(decrypted.Data)
	if err != nil {
		t.Fatalf("ParseControlPacket failed: %v", err)
	}

	parsedPing, ok := parsed.(*ControlPacketPing)
	if !ok {
		t.Fatalf("expected *ControlPacketPing, got %T", parsed)
	}

	if parsedPing.ID != pingID {
		t.Errorf("ping ID mismatch: got %x, want %x", parsedPing.ID, pingID)
	}
}

func TestProxyPacketIsControl(t *testing.T) {
	// Regular packet
	regular := &ProxyPacket{Flags: ProxyFlagHasSeqno | ProxyFlagHasDate}
	if regular.IsControl() {
		t.Error("regular packet should not be control")
	}

	// Control packet
	control := &ProxyPacket{Flags: ProxyFlagHasSeqno | ProxyFlagIsControl | ProxyFlagHasControlTL}
	if !control.IsControl() {
		t.Error("control packet should be control")
	}
}
