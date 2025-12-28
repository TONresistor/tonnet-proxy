package tunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net"
	"testing"
)

func TestNewHop(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	hop := NewHop(pub, addr)

	if !bytes.Equal(hop.PublicKey, pub) {
		t.Error("public key mismatch")
	}

	expectedHash := sha256.Sum256(pub)
	if hop.KeyHash != expectedHash {
		t.Error("key hash mismatch")
	}

	if hop.IsDummy {
		t.Error("hop should not be dummy")
	}
}

func TestKeyring(t *testing.T) {
	kr := NewKeyring()

	// Generate key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	keyHash := sha256.Sum256(pub)

	// Key should not exist initially
	if _, ok := kr.GetPrivateKey(keyHash); ok {
		t.Error("key should not exist")
	}

	// Add key
	kr.AddKey(priv)

	// Key should now exist
	retrieved, ok := kr.GetPrivateKey(keyHash)
	if !ok {
		t.Error("key should exist")
	}

	if !bytes.Equal(retrieved, priv) {
		t.Error("retrieved key mismatch")
	}

	// Remove key
	kr.RemoveKey(keyHash)

	if _, ok := kr.GetPrivateKey(keyHash); ok {
		t.Error("key should be removed")
	}
}

func TestTunnelPacketContents(t *testing.T) {
	msg := []byte("Hello, Tunnel!")

	// Create packet with message only
	pkt := &TunnelPacketContents{
		Flags:   FlagHasMessage,
		Message: msg,
	}

	// Serialize
	data, err := pkt.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Parse
	var parsed TunnelPacketContents
	if err := parsed.Parse(data); err != nil {
		t.Fatal(err)
	}

	if parsed.Flags != pkt.Flags {
		t.Errorf("flags mismatch: got %d, want %d", parsed.Flags, pkt.Flags)
	}

	if !bytes.Equal(parsed.Message, msg) {
		t.Error("message mismatch")
	}
}

func TestTunnelPacketWithSourceAddr(t *testing.T) {
	msg := []byte("Hello with addr!")
	srcAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}

	pkt := NewTunnelPacket(msg, srcAddr)

	// Serialize and parse
	data, err := pkt.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	var parsed TunnelPacketContents
	if err := parsed.Parse(data); err != nil {
		t.Fatal(err)
	}

	if parsed.Flags&FlagHasSourceAddr == 0 {
		t.Error("should have source addr flag")
	}

	if parsed.FromPort != 12345 {
		t.Errorf("port mismatch: got %d, want 12345", parsed.FromPort)
	}
}

func TestBuildAndParseTunnelDatagram(t *testing.T) {
	var keyHash [32]byte
	rand.Read(keyHash[:])

	encrypted := []byte("encrypted data here")

	datagram := BuildTunnelDatagram(keyHash, encrypted)

	parsedHash, parsedEncrypted, err := ParseTunnelDatagram(datagram)
	if err != nil {
		t.Fatal(err)
	}

	if parsedHash != keyHash {
		t.Error("key hash mismatch")
	}

	if !bytes.Equal(parsedEncrypted, encrypted) {
		t.Error("encrypted data mismatch")
	}
}

func TestRoute(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	pub3, _, _ := ed25519.GenerateKey(rand.Reader)

	addr1 := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1001}
	addr2 := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 1002}
	addr3 := &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 1003}

	hop1 := NewHop(pub1, addr1)
	hop2 := NewHop(pub2, addr2)
	hop3 := NewHop(pub3, addr3)

	route := NewRoute(hop1, hop2, hop3)

	if route.Len() != 3 {
		t.Errorf("route length: got %d, want 3", route.Len())
	}

	if err := ValidateRoute(route); err != nil {
		t.Errorf("route validation failed: %v", err)
	}
}

func TestReverseRoute(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	addr1 := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1001}
	addr2 := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 1002}

	route := NewRoute(NewHop(pub1, addr1), NewHop(pub2, addr2))
	reversed := ReverseRoute(route)

	if !bytes.Equal(reversed.Hops[0].PublicKey, pub2) {
		t.Error("first hop of reversed route should be pub2")
	}

	if !bytes.Equal(reversed.Hops[1].PublicKey, pub1) {
		t.Error("second hop of reversed route should be pub1")
	}
}

func TestStaticRouteBuilder(t *testing.T) {
	relay1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	relay2Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	destPub, _, _ := ed25519.GenerateKey(rand.Reader)

	relays := []RelayNode{
		{PublicKey: relay1Pub, Address: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1001}},
		{PublicKey: relay2Pub, Address: &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 1002}},
	}

	builder := NewStaticRouteBuilder(relays)
	destAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.99"), Port: 9999}

	route, err := builder.BuildRoute(destPub, destAddr)
	if err != nil {
		t.Fatal(err)
	}

	if route.Len() != 3 {
		t.Errorf("route length: got %d, want 3", route.Len())
	}

	// Last hop should be destination
	lastHop := route.Hops[route.Len()-1]
	if !bytes.Equal(lastHop.PublicKey, destPub) {
		t.Error("last hop should be destination")
	}
}

func TestValidateRoute(t *testing.T) {
	// Nil route
	if err := ValidateRoute(nil); err == nil {
		t.Error("nil route should fail validation")
	}

	// Empty route
	if err := ValidateRoute(&Route{}); err == nil {
		t.Error("empty route should fail validation")
	}

	// Valid route
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1001}
	route := NewRoute(NewHop(pub, addr))

	if err := ValidateRoute(route); err != nil {
		t.Errorf("valid route failed: %v", err)
	}
}

// Benchmark tests

func BenchmarkKeyring(b *testing.B) {
	kr := NewKeyring()

	// Pre-generate keys
	keys := make([]ed25519.PrivateKey, 100)
	hashes := make([][32]byte, 100)
	for i := 0; i < 100; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		keys[i] = priv
		hashes[i] = sha256.Sum256(pub)
		kr.AddKey(priv)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		kr.GetPrivateKey(hashes[i%100])
	}
}

func BenchmarkTunnelPacketSerialize(b *testing.B) {
	msg := make([]byte, 1024)
	rand.Read(msg)

	pkt := &TunnelPacketContents{
		Flags:    FlagHasMessage | FlagHasSourceAddr,
		FromIP:   0x0A000001,
		FromPort: 12345,
		Message:  msg,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pkt.Serialize()
	}
}

func BenchmarkBuildRoute(b *testing.B) {
	// Pre-generate keys
	keys := make([]ed25519.PublicKey, 5)
	for i := 0; i < 5; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		keys[i] = pub
	}

	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1001}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hops := make([]Hop, len(keys))
		for j, key := range keys {
			hops[j] = NewHop(key, addr)
		}
		NewRoute(hops...)
	}
}
