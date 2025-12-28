package tunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/xssnick/tonutils-go/adnl"
)

func TestSharedKeySymmetry(t *testing.T) {
	// Generate two key pairs
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Both parties should derive the same shared key
	sharedAB, err := adnl.SharedKey(privA, pubB)
	if err != nil {
		t.Fatalf("SharedKey A->B: %v", err)
	}

	sharedBA, err := adnl.SharedKey(privB, pubA)
	if err != nil {
		t.Fatalf("SharedKey B->A: %v", err)
	}

	// Shared keys must be identical (ECDH property)
	if !bytes.Equal(sharedAB, sharedBA) {
		t.Errorf("shared keys differ:\nA->B: %x\nB->A: %x", sharedAB, sharedBA)
	}

	t.Logf("Shared key (32 bytes): %x", sharedAB)
}

func TestEncryptDecryptLayer(t *testing.T) {
	// Generate two key pairs
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("Secret message for garlic routing!")

	// A encrypts for B
	encrypted, err := EncryptLayer(payload, pubB, privA)
	if err != nil {
		t.Fatalf("EncryptLayer: %v", err)
	}

	t.Logf("Payload: %d bytes, Encrypted: %d bytes (overhead: %d)",
		len(payload), len(encrypted), len(encrypted)-len(payload))

	// B decrypts using A's public key
	decrypted, err := DecryptLayer(encrypted, privB, pubA)
	if err != nil {
		t.Fatalf("DecryptLayer: %v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("decrypted mismatch:\ngot:  %s\nwant: %s", decrypted, payload)
	}

	// Verify that wrong key fails
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, err = DecryptLayer(encrypted, wrongPriv, pubA)
	if err == nil {
		t.Error("decryption with wrong key should fail")
	}
}

func TestEncryptDecryptLargePayload(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)

	// Test with larger payload
	payload := make([]byte, 4096)
	rand.Read(payload)

	encrypted, err := EncryptLayer(payload, pubB, privA)
	if err != nil {
		t.Fatalf("EncryptLayer: %v", err)
	}

	decrypted, err := DecryptLayer(encrypted, privB, pubA)
	if err != nil {
		t.Fatalf("DecryptLayer: %v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Error("large payload decryption failed")
	}
}

func TestBuildOnionPacket(t *testing.T) {
	// Create 3 hops with their key pairs
	numHops := 3
	hopKeys := make([]struct {
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	}, numHops)

	for i := 0; i < numHops; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		hopKeys[i].pub = pub
		hopKeys[i].priv = priv
	}

	// Build route
	hops := make([]Hop, numHops)
	for i := 0; i < numHops; i++ {
		hops[i] = Hop{
			PublicKey: hopKeys[i].pub,
			KeyHash:   sha256.Sum256(hopKeys[i].pub),
		}
	}
	route := &Route{Hops: hops}

	// Sender's key
	senderPub, senderPriv, _ := ed25519.GenerateKey(rand.Reader)

	payload := []byte("Multi-layer encrypted message through garlic routing!")

	// Build onion packet
	packet, err := BuildOnionPacket(payload, route, senderPriv)
	if err != nil {
		t.Fatalf("BuildOnionPacket: %v", err)
	}

	t.Logf("Payload: %d bytes", len(payload))
	t.Logf("Onion packet: %d bytes (3 layers)", len(packet))
	t.Logf("Overhead per layer: ~%d bytes", (len(packet)-len(payload))/numHops)

	// Now decrypt layer by layer (simulating each hop)
	current := packet

	for i := 0; i < numHops; i++ {
		// Verify key hash matches
		var keyHash [32]byte
		copy(keyHash[:], current[:32])

		if keyHash != hops[i].KeyHash {
			t.Errorf("hop %d: key hash mismatch", i)
		}

		// Decrypt this layer
		decrypted, err := DecryptLayer(current[32:], hopKeys[i].priv, senderPub)
		if err != nil {
			t.Fatalf("hop %d: decrypt failed: %v", i, err)
		}

		current = decrypted
		t.Logf("Hop %d decrypted: %d bytes remaining", i, len(current))
	}

	// Final result should be the original payload
	if !bytes.Equal(current, payload) {
		t.Errorf("final payload mismatch:\ngot:  %s\nwant: %s", current, payload)
	}

	t.Log("Successfully decrypted all 3 layers!")
}

func TestUnwrapLayer(t *testing.T) {
	// Setup
	senderPub, senderPriv, _ := ed25519.GenerateKey(rand.Reader)
	hopPub, hopPriv, _ := ed25519.GenerateKey(rand.Reader)

	keyring := NewKeyring()
	keyring.AddKey(hopPriv)

	payload := []byte("Test message")

	// Build single-layer packet
	route := NewRoute(NewHop(hopPub, nil))
	packet, err := BuildOnionPacket(payload, route, senderPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Unwrap using keyring
	decrypted, keyHash, err := UnwrapLayer(packet, keyring, senderPub)
	if err != nil {
		t.Fatalf("UnwrapLayer: %v", err)
	}

	expectedHash := sha256.Sum256(hopPub)
	if keyHash != expectedHash {
		t.Error("key hash mismatch")
	}

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("payload mismatch: got %s, want %s", decrypted, payload)
	}
}

func TestUnwrapAllLayers(t *testing.T) {
	// Setup sender
	senderPub, senderPriv, _ := ed25519.GenerateKey(rand.Reader)

	// Create keyring with 3 hop keys
	keyring := NewKeyring()
	hops := make([]Hop, 3)

	for i := 0; i < 3; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		keyring.AddKey(priv)
		hops[i] = NewHop(pub, nil)
	}

	route := &Route{Hops: hops}
	payload := []byte("Secret payload through 3 hops")

	// Build packet
	packet, err := BuildOnionPacket(payload, route, senderPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Unwrap all layers at once
	decrypted, err := UnwrapAllLayers(packet, keyring, senderPub)
	if err != nil {
		t.Fatalf("UnwrapAllLayers: %v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("payload mismatch: got %s, want %s", decrypted, payload)
	}
}

func TestCreateLayeredKeys(t *testing.T) {
	privKeys, keyHashes, err := CreateLayeredKeys(5)
	if err != nil {
		t.Fatal(err)
	}

	if len(privKeys) != 5 {
		t.Errorf("expected 5 private keys, got %d", len(privKeys))
	}

	if len(keyHashes) != 5 {
		t.Errorf("expected 5 key hashes, got %d", len(keyHashes))
	}

	// Verify hashes match public keys
	for i, priv := range privKeys {
		pub := priv.Public().(ed25519.PublicKey)
		expectedHash := sha256.Sum256(pub)
		if keyHashes[i] != expectedHash {
			t.Errorf("key %d: hash mismatch", i)
		}
	}
}

func TestDecryptAtHop(t *testing.T) {
	senderPub, senderPriv, _ := ed25519.GenerateKey(rand.Reader)
	hopPub, hopPriv, _ := ed25519.GenerateKey(rand.Reader)

	payload := []byte("Message for single hop")

	// Build single-layer packet
	route := NewRoute(NewHop(hopPub, nil))
	packet, _ := BuildOnionPacket(payload, route, senderPriv)

	// Decrypt at hop (skipping key hash check)
	decrypted, err := DecryptAtHop(packet, hopPriv, senderPub)
	if err != nil {
		t.Fatalf("DecryptAtHop: %v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("payload mismatch: got %s, want %s", decrypted, payload)
	}
}

// Benchmarks

func BenchmarkEncryptLayer(b *testing.B) {
	_, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)

	payload := make([]byte, 1024)
	rand.Read(payload)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		EncryptLayer(payload, pubB, privA)
	}
}

func BenchmarkDecryptLayer(b *testing.B) {
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)

	payload := make([]byte, 1024)
	rand.Read(payload)

	encrypted, _ := EncryptLayer(payload, pubB, privA)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		DecryptLayer(encrypted, privB, pubA)
	}
}

func BenchmarkBuildOnionPacket3Hops(b *testing.B) {
	_, senderPriv, _ := ed25519.GenerateKey(rand.Reader)

	hops := make([]Hop, 3)
	for i := 0; i < 3; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		hops[i] = NewHop(pub, nil)
	}
	route := &Route{Hops: hops}

	payload := make([]byte, 256)
	rand.Read(payload)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		BuildOnionPacket(payload, route, senderPriv)
	}
}

func BenchmarkBuildOnionPacket5Hops(b *testing.B) {
	_, senderPriv, _ := ed25519.GenerateKey(rand.Reader)

	hops := make([]Hop, 5)
	for i := 0; i < 5; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		hops[i] = NewHop(pub, nil)
	}
	route := &Route{Hops: hops}

	payload := make([]byte, 256)
	rand.Read(payload)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		BuildOnionPacket(payload, route, senderPriv)
	}
}
