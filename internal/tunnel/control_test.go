package tunnel

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

func TestControlPacketPing(t *testing.T) {
	var id [32]byte
	rand.Read(id[:])

	ping := &ControlPacketPing{ID: id}
	data := ping.Serialize()

	// Parse it back
	parsed := &ControlPacketPing{}
	if err := parsed.Parse(data); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsed.ID != id {
		t.Errorf("ID mismatch: got %x, want %x", parsed.ID, id)
	}
}

func TestControlPacketPong(t *testing.T) {
	var id [32]byte
	rand.Read(id[:])

	pong := &ControlPacketPong{ID: id}
	data := pong.Serialize()

	// Parse it back
	parsed := &ControlPacketPong{}
	if err := parsed.Parse(data); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsed.ID != id {
		t.Errorf("ID mismatch: got %x, want %x", parsed.ID, id)
	}
}

func TestControlPacketRegister(t *testing.T) {
	reg := &ControlPacketRegister{
		IP:   0x7F000001, // 127.0.0.1
		Port: 8080,
	}
	data := reg.Serialize()

	// Parse it back
	parsed := &ControlPacketRegister{}
	if err := parsed.Parse(data); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsed.IP != reg.IP {
		t.Errorf("IP mismatch: got %x, want %x", parsed.IP, reg.IP)
	}

	if parsed.Port != reg.Port {
		t.Errorf("Port mismatch: got %d, want %d", parsed.Port, reg.Port)
	}
}

func TestParseControlPacket(t *testing.T) {
	tests := []struct {
		name   string
		create func() []byte
		check  func(interface{}) bool
	}{
		{
			name: "ping",
			create: func() []byte {
				var id [32]byte
				rand.Read(id[:])
				return (&ControlPacketPing{ID: id}).Serialize()
			},
			check: func(p interface{}) bool {
				_, ok := p.(*ControlPacketPing)
				return ok
			},
		},
		{
			name: "pong",
			create: func() []byte {
				var id [32]byte
				rand.Read(id[:])
				return (&ControlPacketPong{ID: id}).Serialize()
			},
			check: func(p interface{}) bool {
				_, ok := p.(*ControlPacketPong)
				return ok
			},
		},
		{
			name: "register",
			create: func() []byte {
				return (&ControlPacketRegister{IP: 0x7F000001, Port: 8080}).Serialize()
			},
			check: func(p interface{}) bool {
				_, ok := p.(*ControlPacketRegister)
				return ok
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.create()
			packet, err := ParseControlPacket(data)
			if err != nil {
				t.Fatalf("ParseControlPacket failed: %v", err)
			}

			if !tt.check(packet) {
				t.Errorf("wrong packet type: %T", packet)
			}
		})
	}
}

func TestIsControlPacket(t *testing.T) {
	// Test ping
	var id [32]byte
	rand.Read(id[:])
	pingData := (&ControlPacketPing{ID: id}).Serialize()
	if !IsControlPacket(pingData) {
		t.Error("ping should be recognized as control packet")
	}

	// Test pong
	pongData := (&ControlPacketPong{ID: id}).Serialize()
	if !IsControlPacket(pongData) {
		t.Error("pong should be recognized as control packet")
	}

	// Test register
	regData := (&ControlPacketRegister{IP: 0, Port: 0}).Serialize()
	if !IsControlPacket(regData) {
		t.Error("register should be recognized as control packet")
	}

	// Test non-control packet
	randomData := make([]byte, 100)
	rand.Read(randomData)
	if IsControlPacket(randomData) {
		t.Error("random data should not be recognized as control packet")
	}
}

func TestControlHandler(t *testing.T) {
	var responses [][]byte
	var responseAddrs []net.Addr

	sendFunc := func(data []byte, addr net.Addr) error {
		responses = append(responses, data)
		responseAddrs = append(responseAddrs, addr)
		return nil
	}

	handler := NewControlHandler(sendFunc)

	// Test ping handling
	var pingID [32]byte
	rand.Read(pingID[:])
	ping := &ControlPacketPing{ID: pingID}
	srcAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

	if err := handler.HandlePacket(ping.Serialize(), srcAddr); err != nil {
		t.Fatalf("HandlePacket ping failed: %v", err)
	}

	// Should have sent a pong response
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	// Parse the response as pong
	pong := &ControlPacketPong{}
	if err := pong.Parse(responses[0]); err != nil {
		t.Fatalf("Parse pong response failed: %v", err)
	}

	if pong.ID != pingID {
		t.Errorf("pong ID mismatch: got %x, want %x", pong.ID, pingID)
	}
}

func TestControlHandlerRegister(t *testing.T) {
	handler := NewControlHandler(nil)

	reg := &ControlPacketRegister{
		IP:   int32(ipToUint32(net.ParseIP("192.168.1.100"))),
		Port: 54321,
	}
	srcAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

	if err := handler.HandlePacket(reg.Serialize(), srcAddr); err != nil {
		t.Fatalf("HandlePacket register failed: %v", err)
	}

	// Check registered address
	clientAddr := handler.GetClientAddr()
	if clientAddr == nil {
		t.Fatal("client address not registered")
	}

	udpAddr, ok := clientAddr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("wrong address type: %T", clientAddr)
	}

	if udpAddr.Port != 54321 {
		t.Errorf("wrong port: got %d, want 54321", udpAddr.Port)
	}
}

func TestControlHandlerIsAlive(t *testing.T) {
	handler := NewControlHandler(nil)
	handler.SetPingTimeout(100 * time.Millisecond)

	// Should be alive initially (no ping sent)
	if !handler.IsAlive() {
		t.Error("should be alive initially")
	}

	// Simulate sending a ping
	handler.mu.Lock()
	handler.lastPingSent = time.Now()
	handler.mu.Unlock()

	// Should still be alive (within timeout)
	if !handler.IsAlive() {
		t.Error("should be alive right after ping")
	}

	// Simulate receiving a pong
	handler.mu.Lock()
	handler.lastPongReceived = time.Now()
	handler.mu.Unlock()

	// Should be alive
	if !handler.IsAlive() {
		t.Error("should be alive after pong")
	}

	// Wait for timeout
	time.Sleep(150 * time.Millisecond)

	// Should be dead
	if handler.IsAlive() {
		t.Error("should be dead after timeout")
	}
}

func TestControlHandlerNeedsPing(t *testing.T) {
	handler := NewControlHandler(nil)
	handler.SetPingInterval(50 * time.Millisecond)

	// Should need ping initially
	if !handler.NeedsPing() {
		t.Error("should need ping initially")
	}

	// Simulate sending a ping
	handler.mu.Lock()
	handler.lastPingSent = time.Now()
	handler.mu.Unlock()

	// Should not need ping immediately
	if handler.NeedsPing() {
		t.Error("should not need ping immediately after sending")
	}

	// Wait for interval
	time.Sleep(60 * time.Millisecond)

	// Should need ping again
	if !handler.NeedsPing() {
		t.Error("should need ping after interval")
	}
}

func TestPingPongRoundtrip(t *testing.T) {
	// Simulate client and server handlers
	var clientReceived [][]byte
	var serverReceived [][]byte

	clientSend := func(data []byte, addr net.Addr) error {
		serverReceived = append(serverReceived, data)
		return nil
	}

	serverSend := func(data []byte, addr net.Addr) error {
		clientReceived = append(clientReceived, data)
		return nil
	}

	clientHandler := NewControlHandler(clientSend)
	serverHandler := NewControlHandler(serverSend)

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

	// Client sends ping
	var pingID [32]byte
	rand.Read(pingID[:])
	clientHandler.SendPing(pingID, addr)

	// Server receives and responds
	if len(serverReceived) != 1 {
		t.Fatalf("server should receive 1 packet, got %d", len(serverReceived))
	}

	if err := serverHandler.HandlePacket(serverReceived[0], addr); err != nil {
		t.Fatalf("server handle failed: %v", err)
	}

	// Client receives pong
	if len(clientReceived) != 1 {
		t.Fatalf("client should receive 1 packet, got %d", len(clientReceived))
	}

	if err := clientHandler.HandlePacket(clientReceived[0], addr); err != nil {
		t.Fatalf("client handle failed: %v", err)
	}

	// Client should have received pong timestamp updated
	if clientHandler.lastPongReceived.IsZero() {
		t.Error("client should have received pong")
	}
}

func BenchmarkControlPacketParse(b *testing.B) {
	var id [32]byte
	rand.Read(id[:])
	data := (&ControlPacketPing{ID: id}).Serialize()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ParseControlPacket(data)
	}
}

func BenchmarkIsControlPacket(b *testing.B) {
	var id [32]byte
	rand.Read(id[:])
	data := (&ControlPacketPing{ID: id}).Serialize()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		IsControlPacket(data)
	}
}

func TestControlPacketWrongType(t *testing.T) {
	ping := &ControlPacketPing{}
	pongData := (&ControlPacketPong{}).Serialize()

	err := ping.Parse(pongData)
	if err == nil {
		t.Error("should fail to parse pong as ping")
	}
}

func TestControlPacketTooShort(t *testing.T) {
	ping := &ControlPacketPing{}
	shortData := make([]byte, 10)

	err := ping.Parse(shortData)
	if err != ErrPacketTooShort {
		t.Errorf("expected ErrPacketTooShort, got %v", err)
	}
}

func TestPacketRoundtripWithRandomPadding(t *testing.T) {
	// Create a tunnel packet with message
	original := NewTunnelPacket([]byte("Hello, garlic routing!"), nil)

	// Serialize
	data, err := original.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	t.Logf("Serialized packet: %d bytes (with random padding)", len(data))

	// Parse
	parsed := &TunnelPacketContents{}
	if err := parsed.Parse(data); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Verify message
	if !bytes.Equal(parsed.Message, original.Message) {
		t.Errorf("message mismatch: got %s, want %s", parsed.Message, original.Message)
	}

	// Verify random padding was preserved
	if len(parsed.Rand1) < MinRandPadding || len(parsed.Rand1) > MaxRandPadding {
		t.Errorf("rand1 size out of range: %d", len(parsed.Rand1))
	}

	if len(parsed.Rand2) < MinRandPadding || len(parsed.Rand2) > MaxRandPadding {
		t.Errorf("rand2 size out of range: %d", len(parsed.Rand2))
	}
}

func TestPacketWithStatisticsAndPayment(t *testing.T) {
	stats := []byte("bandwidth:1024,packets:100")
	payment := []byte("payment_proof_data_here")

	// Create packet with stats
	p := NewTunnelPacketWithStats([]byte("message"), nil, stats)
	p.Flags |= FlagHasPayment
	p.Payment = payment

	// Serialize
	data, err := p.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	// Parse
	parsed := &TunnelPacketContents{}
	if err := parsed.Parse(data); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if !bytes.Equal(parsed.Statistics, stats) {
		t.Errorf("statistics mismatch: got %s, want %s", parsed.Statistics, stats)
	}

	if !bytes.Equal(parsed.Payment, payment) {
		t.Errorf("payment mismatch: got %s, want %s", parsed.Payment, payment)
	}
}
