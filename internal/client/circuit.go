package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TONresistor/tonnet-proxy/internal/protocol"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/tl"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// RelayInfo contains the address and public key of a relay
type RelayInfo struct {
	Address   string
	PublicKey ed25519.PublicKey
}

// ClientCircuit manages a multi-hop garlic circuit
type ClientCircuit struct {
	ID         []byte
	SharedKeys [][]byte  // One key per hop (entry, middle, exit)
	entryPeer  adnl.Peer // Connection to the first relay

	streams    sync.Map
	nextStream uint32

	// Pending responses by stream ID
	pending sync.Map // streamID -> chan []byte

	// Chunk reassembly by stream ID
	chunksMu sync.Mutex
	chunks   map[int]*chunkAssembler // streamID -> assembler
}

// chunkAssembler collects and reassembles chunked responses
type chunkAssembler struct {
	totalChunks int
	received    map[int][]byte // chunkIndex -> decrypted data
}

// NewClientCircuit creates a circuit through 3 relays
func NewClientCircuit(ctx context.Context, gate *adnl.Gateway, relays []RelayInfo) (*ClientCircuit, error) {
	if len(relays) != 3 {
		return nil, fmt.Errorf("need exactly 3 relays, got %d", len(relays))
	}

	// Generate circuit ID
	circuitID := make([]byte, 32)
	if _, err := rand.Read(circuitID); err != nil {
		return nil, fmt.Errorf("generate circuit ID: %w", err)
	}

	circuit := &ClientCircuit{
		ID:         circuitID,
		SharedKeys: make([][]byte, 3),
		chunks:     make(map[int]*chunkAssembler),
	}

	// Step 1: Connect to entry relay
	entryPeer, err := gate.RegisterClient(relays[0].Address, relays[0].PublicKey)
	if err != nil {
		return nil, fmt.Errorf("connect to entry relay: %w", err)
	}
	circuit.entryPeer = entryPeer

	// Register handler for incoming Data and DataChunk messages (responses from circuit)
	entryPeer.SetCustomMessageHandler(func(msg *adnl.MessageCustom) error {
		// Try to handle as DataChunk first (for large responses)
		switch d := msg.Data.(type) {
		case protocol.DataChunk:
			return circuit.handleChunk(&d)
		case *protocol.DataChunk:
			return circuit.handleChunk(d)
		}

		// Handle as regular Data message
		var data protocol.Data
		switch d := msg.Data.(type) {
		case protocol.Data:
			data = d
		case *protocol.Data:
			data = *d
		case []byte:
			// Try parsing as DataChunk first
			var chunk protocol.DataChunk
			if _, err := tl.Parse(&chunk, d, true); err == nil {
				return circuit.handleChunk(&chunk)
			}
			// Then try as Data
			if _, err := tl.Parse(&data, d, true); err != nil {
				return nil
			}
		default:
			return nil
		}

		return circuit.HandleResponse(data.Data)
	})

	// Step 2: Create circuit to entry relay
	key1, err := circuit.createCircuit(ctx, relays[0])
	if err != nil {
		return nil, fmt.Errorf("create circuit to entry: %w", err)
	}
	circuit.SharedKeys[0] = key1

	// Step 3: Extend to middle relay (via entry)
	key2, err := circuit.extendCircuit(ctx, relays[1])
	if err != nil {
		return nil, fmt.Errorf("extend to middle: %w", err)
	}
	circuit.SharedKeys[1] = key2

	// Step 4: Extend to exit relay (via entry + middle)
	key3, err := circuit.extendCircuitViaRelay(ctx, relays[2])
	if err != nil {
		return nil, fmt.Errorf("extend to exit: %w", err)
	}
	circuit.SharedKeys[2] = key3

	return circuit, nil
}

// createCircuit creates initial circuit to entry relay
func (c *ClientCircuit) createCircuit(ctx context.Context, relay RelayInfo) ([]byte, error) {
	// Generate X25519 keypair for key exchange
	clientPriv, clientPub := generateX25519Keypair()

	// Send CircuitCreate
	req := &protocol.CircuitCreate{
		CircuitID: c.ID,
		ClientKey: clientPub,
	}

	var resp protocol.CircuitCreated
	if err := c.entryPeer.Query(ctx, req, &resp); err != nil {
		return nil, fmt.Errorf("circuit create query: %w", err)
	}

	// Compute shared key
	sharedKey := computeSharedKey(clientPriv, resp.RelayKey)

	return sharedKey, nil
}

// extendCircuit extends the circuit to another relay
func (c *ClientCircuit) extendCircuit(ctx context.Context, relay RelayInfo) ([]byte, error) {
	// Generate new X25519 keypair for this hop
	clientPriv, clientPub := generateX25519Keypair()

	// Build ExtendPayload: addr_len(2) + addr + client_key(32)
	addrBytes := []byte(relay.Address)
	payload := make([]byte, 2+len(addrBytes)+32)
	payload[0] = byte(len(addrBytes) >> 8)
	payload[1] = byte(len(addrBytes))
	copy(payload[2:], addrBytes)
	copy(payload[2+len(addrBytes):], clientPub)

	// Encrypt with entry relay's shared key
	encrypted, err := encryptPayload(payload, c.SharedKeys[0])
	if err != nil {
		return nil, fmt.Errorf("encrypt extend payload: %w", err)
	}

	// Send CircuitExtend
	req := &protocol.CircuitExtend{
		CircuitID: c.ID,
		NextRelay: relay.PublicKey[:32], // Use first 32 bytes of ed25519 pubkey as ADNL ID
		Encrypted: encrypted,
	}

	var resp protocol.CircuitExtended
	if err := c.entryPeer.Query(ctx, req, &resp); err != nil {
		return nil, fmt.Errorf("circuit extend query: %w", err)
	}

	// Compute shared key with middle relay
	sharedKey := computeSharedKey(clientPriv, resp.RelayKey)

	return sharedKey, nil
}

// extendCircuitViaRelay extends to a third hop via the existing circuit
func (c *ClientCircuit) extendCircuitViaRelay(ctx context.Context, relay RelayInfo) ([]byte, error) {
	// Generate new X25519 keypair for this hop
	clientPriv, clientPub := generateX25519Keypair()

	// Build ExtendPayload: addr_len(2) + addr + client_key(32)
	addrBytes := []byte(relay.Address)
	payload := make([]byte, 2+len(addrBytes)+32)
	payload[0] = byte(len(addrBytes) >> 8)
	payload[1] = byte(len(addrBytes))
	copy(payload[2:], addrBytes)
	copy(payload[2+len(addrBytes):], clientPub)

	// Encrypt with middle relay's shared key
	encrypted, err := encryptPayload(payload, c.SharedKeys[1])
	if err != nil {
		return nil, fmt.Errorf("encrypt extend payload: %w", err)
	}

	// Create inner CircuitExtend message
	innerExtend := &protocol.CircuitExtend{
		CircuitID: c.ID,
		NextRelay: relay.PublicKey[:32],
		Encrypted: encrypted,
	}

	// Serialize inner message
	innerData, err := tl.Serialize(innerExtend, true)
	if err != nil {
		return nil, fmt.Errorf("serialize inner extend: %w", err)
	}

	// Encrypt with entry relay's key for CircuitRelay
	relayEncrypted, err := encryptPayload(innerData, c.SharedKeys[0])
	if err != nil {
		return nil, fmt.Errorf("encrypt relay payload: %w", err)
	}

	// Send CircuitRelay (relay through entry to middle)
	req := &protocol.CircuitRelay{
		CircuitID: c.ID,
		Encrypted: relayEncrypted,
	}

	var resp protocol.CircuitRelayResponse
	if err := c.entryPeer.Query(ctx, req, &resp); err != nil {
		return nil, fmt.Errorf("circuit relay query: %w", err)
	}

	// Decrypt the response (encrypted by entry relay)
	decrypted, err := decryptPayload(resp.Encrypted, c.SharedKeys[0])
	if err != nil {
		return nil, fmt.Errorf("decrypt relay response: %w", err)
	}

	// Parse CircuitExtended from decrypted response
	var extendedResp protocol.CircuitExtended
	if _, err := tl.Parse(&extendedResp, decrypted, true); err != nil {
		return nil, fmt.Errorf("parse extended response: %w", err)
	}

	// Compute shared key with exit relay
	sharedKey := computeSharedKey(clientPriv, extendedResp.RelayKey)

	return sharedKey, nil
}

// OpenStream opens a new stream to the specified host:port
func (c *ClientCircuit) OpenStream(ctx context.Context, host string, port int) (int, error) {
	streamID := int(atomic.AddUint32(&c.nextStream, 1))

	// Create StreamConnect message
	connect := &protocol.StreamConnect{
		StreamID: streamID,
		Host:     host,
		Port:     port,
	}

	// Serialize
	payload, err := tl.Serialize(connect, true)
	if err != nil {
		return 0, fmt.Errorf("serialize stream connect: %w", err)
	}

	// Encrypt in layers (reverse order: exit, middle, entry)
	encrypted := c.encryptLayers(payload)

	// Create response channel
	respChan := make(chan []byte, 1)
	c.pending.Store(streamID, respChan)

	// Send via circuit
	err = c.entryPeer.SendCustomMessage(ctx, &protocol.Data{
		CircuitID: c.ID,
		StreamID:  0, // Control stream
		Data:      encrypted,
	})
	if err != nil {
		c.pending.Delete(streamID)
		return 0, fmt.Errorf("send stream connect: %w", err)
	}

	// Wait for confirmation
	select {
	case resp := <-respChan:
		var connected protocol.StreamConnected
		if _, err := tl.Parse(&connected, resp, true); err != nil {
			return 0, fmt.Errorf("parse stream connected: %w", err)
		}
		if !connected.Success {
			return 0, fmt.Errorf("stream connect failed: %s", connected.Error)
		}
		return streamID, nil

	case <-time.After(30 * time.Second):
		c.pending.Delete(streamID)
		return 0, fmt.Errorf("timeout waiting for stream connect response")

	case <-ctx.Done():
		c.pending.Delete(streamID)
		return 0, ctx.Err()
	}
}

// SendData sends data on a stream
func (c *ClientCircuit) SendData(ctx context.Context, streamID int, data []byte) error {
	msg := &protocol.StreamData{
		StreamID: streamID,
		Data:     data,
	}

	payload, err := tl.Serialize(msg, true)
	if err != nil {
		return fmt.Errorf("serialize stream data: %w", err)
	}

	encrypted := c.encryptLayers(payload)

	return c.entryPeer.SendCustomMessage(ctx, &protocol.Data{
		CircuitID: c.ID,
		StreamID:  streamID,
		Data:      encrypted,
	})
}

// RecvData waits for and returns data from a stream
func (c *ClientCircuit) RecvData(ctx context.Context, streamID int) ([]byte, error) {
	respChanI, ok := c.pending.Load(streamID)
	if !ok {
		respChan := make(chan []byte, 10)
		c.pending.Store(streamID, respChan)
		respChanI = respChan
	}

	respChan := respChanI.(chan []byte)

	select {
	case data := <-respChan:
		return data, nil

	case <-time.After(60 * time.Second):
		return nil, fmt.Errorf("timeout waiting for stream data")

	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// encryptLayers encrypts data with all layers (garlic encryption)
// Order: exit key first, then middle, then entry (reverse path order)
func (c *ClientCircuit) encryptLayers(data []byte) []byte {
	encrypted := data

	// Encrypt in reverse order: exit, middle, entry
	for i := len(c.SharedKeys) - 1; i >= 0; i-- {
		var err error
		encrypted, err = encryptPayload(encrypted, c.SharedKeys[i])
		if err != nil {
			// In production, handle this error properly
			panic(fmt.Sprintf("encrypt layer %d: %v", i, err))
		}
	}

	return encrypted
}

// decryptLayers decrypts all garlic layers
// Order: entry key first, then middle, then exit (path order)
func (c *ClientCircuit) decryptLayers(data []byte) ([]byte, error) {
	decrypted := data

	// Decrypt in path order: entry, middle, exit
	for i := 0; i < len(c.SharedKeys); i++ {
		var err error
		decrypted, err = decryptPayload(decrypted, c.SharedKeys[i])
		if err != nil {
			return nil, fmt.Errorf("decrypt layer %d: %w", i, err)
		}
	}

	return decrypted, nil
}

// HandleResponse processes a response received from the circuit
func (c *ClientCircuit) HandleResponse(data []byte) error {
	// Responses are encrypted with exit key only (relays forward without re-encrypting)
	// So we only need to decrypt with the exit (last) key
	decrypted, err := decryptPayload(data, c.SharedKeys[len(c.SharedKeys)-1])
	if err != nil {
		return fmt.Errorf("decrypt response: %w", err)
	}

	// Parse the message
	var msg any
	if _, err := tl.Parse(&msg, decrypted, true); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	switch m := msg.(type) {
	case *protocol.StreamConnected:
		if ch, ok := c.pending.Load(m.StreamID); ok {
			select {
			case ch.(chan []byte) <- decrypted:
			default:
			}
		}

	case protocol.StreamConnected:
		if ch, ok := c.pending.Load(m.StreamID); ok {
			select {
			case ch.(chan []byte) <- decrypted:
			default:
			}
		}

	case *protocol.StreamData:
		if ch, ok := c.pending.Load(m.StreamID); ok {
			select {
			case ch.(chan []byte) <- m.Data:
			default:
			}
		}

	case protocol.StreamData:
		if ch, ok := c.pending.Load(m.StreamID); ok {
			select {
			case ch.(chan []byte) <- m.Data:
			default:
			}
		}
	}

	return nil
}

// handleChunk processes a chunked response from the circuit
// Chunks are used for large responses that exceed ADNL's ~8KB limit
func (c *ClientCircuit) handleChunk(chunk *protocol.DataChunk) error {
	// Decrypt this chunk with exit key
	decrypted, err := decryptPayload(chunk.Data, c.SharedKeys[len(c.SharedKeys)-1])
	if err != nil {
		return fmt.Errorf("decrypt chunk %d: %w", chunk.ChunkIndex, err)
	}

	c.chunksMu.Lock()
	defer c.chunksMu.Unlock()

	// Get or create assembler for this stream
	assembler, ok := c.chunks[chunk.StreamID]
	if !ok {
		assembler = &chunkAssembler{
			totalChunks: chunk.TotalChunks,
			received:    make(map[int][]byte),
		}
		c.chunks[chunk.StreamID] = assembler
	}

	// Store this chunk
	assembler.received[chunk.ChunkIndex] = decrypted

	// Check if all chunks received
	if len(assembler.received) < assembler.totalChunks {
		return nil // Still waiting for more chunks
	}

	// All chunks received - reassemble in order
	totalSize := 0
	for _, data := range assembler.received {
		totalSize += len(data)
	}

	reassembled := make([]byte, 0, totalSize)
	for i := 0; i < assembler.totalChunks; i++ {
		data, ok := assembler.received[i]
		if !ok {
			return fmt.Errorf("missing chunk %d", i)
		}
		reassembled = append(reassembled, data...)
	}

	// Clean up
	delete(c.chunks, chunk.StreamID)

	// Parse and dispatch the reassembled message (already decrypted)
	var msg any
	if _, err := tl.Parse(&msg, reassembled, true); err != nil {
		return fmt.Errorf("parse reassembled response: %w", err)
	}

	switch m := msg.(type) {
	case *protocol.StreamData:
		if ch, ok := c.pending.Load(m.StreamID); ok {
			select {
			case ch.(chan []byte) <- m.Data:
			default:
			}
		}
	case protocol.StreamData:
		if ch, ok := c.pending.Load(m.StreamID); ok {
			select {
			case ch.(chan []byte) <- m.Data:
			default:
			}
		}
	}

	return nil
}

// CloseStream closes a specific stream
func (c *ClientCircuit) CloseStream(streamID int) {
	c.pending.Delete(streamID)
}

// Close closes the circuit
func (c *ClientCircuit) Close() error {
	if c.entryPeer != nil {
		return c.entryPeer.SendCustomMessage(context.Background(), &protocol.CircuitDestroy{
			CircuitID: c.ID,
		})
	}
	return nil
}

// --- Crypto helpers (same pattern as internal/exit/crypto.go) ---

// generateX25519Keypair generates an X25519 keypair for key exchange
func generateX25519Keypair() ([]byte, []byte) {
	var priv, pub [32]byte

	if _, err := rand.Read(priv[:]); err != nil {
		panic(err)
	}

	// Clamp private key for X25519
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)

	return priv[:], pub[:]
}

// computeSharedKey computes the shared secret from X25519 key exchange
func computeSharedKey(privKey, peerPubKey []byte) []byte {
	var priv, peerPub, shared [32]byte

	copy(priv[:], privKey)
	copy(peerPub[:], peerPubKey)

	curve25519.ScalarMult(&shared, &priv, &peerPub)

	// Derive symmetric key from shared secret using SHA256
	h := sha256.New()
	h.Write(shared[:])
	return h.Sum(nil)
}

// encryptPayload encrypts data with ChaCha20-Poly1305 (nonce prepended)
func encryptPayload(data, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: %d", len(key))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, data, nil)

	// Prepend nonce
	result := make([]byte, 12+len(ciphertext))
	copy(result, nonce)
	copy(result[12:], ciphertext)

	return result, nil
}

// decryptPayload decrypts data with ChaCha20-Poly1305 (nonce prepended)
func decryptPayload(data, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: %d", len(key))
	}

	if len(data) < 12+16 { // nonce(12) + auth_tag(16)
		return nil, fmt.Errorf("data too short")
	}

	nonce := data[:12]
	ciphertext := data[12:]

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ciphertext, nil)
}
