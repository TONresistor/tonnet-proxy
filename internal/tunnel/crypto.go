package tunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/xssnick/tonutils-go/adnl"
)

// EncryptLayer encrypts a single layer of the onion packet
// Uses the same crypto as ADNL: X25519 ECDH + AES-CTR
func EncryptLayer(data []byte, recipientPubKey ed25519.PublicKey, senderPrivKey ed25519.PrivateKey) ([]byte, error) {
	// 1. Derive shared key via ECDH (using tonutils-go adnl package)
	sharedKey, err := adnl.SharedKey(senderPrivKey, recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("derive shared key: %w", err)
	}

	// 2. Compute checksum of plaintext
	checksum := sha256.Sum256(data)

	// 3. Build cipher using tonutils-go implementation
	cipherStream, err := adnl.BuildSharedCipher(sharedKey, checksum[:])
	if err != nil {
		return nil, fmt.Errorf("build cipher: %w", err)
	}

	// 4. Encrypt
	encrypted := make([]byte, len(data))
	cipherStream.XORKeyStream(encrypted, data)

	// 5. Format: [checksum(32)] + [encrypted_data]
	result := make([]byte, 32+len(encrypted))
	copy(result[:32], checksum[:])
	copy(result[32:], encrypted)

	return result, nil
}

// DecryptLayer decrypts a single layer of the onion packet
func DecryptLayer(data []byte, recipientPrivKey ed25519.PrivateKey, senderPubKey ed25519.PublicKey) ([]byte, error) {
	if len(data) < 32 {
		return nil, ErrPacketTooShort
	}

	// 1. Extract checksum
	checksum := data[:32]
	encrypted := data[32:]

	// 2. Derive shared key using tonutils-go
	sharedKey, err := adnl.SharedKey(recipientPrivKey, senderPubKey)
	if err != nil {
		return nil, fmt.Errorf("derive shared key: %w", err)
	}

	// 3. Build cipher and decrypt
	cipherStream, err := adnl.BuildSharedCipher(sharedKey, checksum)
	if err != nil {
		return nil, fmt.Errorf("build cipher: %w", err)
	}

	decrypted := make([]byte, len(encrypted))
	cipherStream.XORKeyStream(decrypted, encrypted)

	// 4. Verify checksum
	actualChecksum := sha256.Sum256(decrypted)
	if !bytes.Equal(actualChecksum[:], checksum) {
		return nil, ErrInvalidChecksum
	}

	return decrypted, nil
}

// BuildOnionPacket constructs a multi-layer encrypted packet
// Hops are processed in reverse order (last hop encrypted first)
// This is the garlic routing implementation - each layer can only be
// decrypted by its intended recipient
func BuildOnionPacket(payload []byte, route *Route, senderPrivKey ed25519.PrivateKey) ([]byte, error) {
	if route == nil || len(route.Hops) == 0 {
		return nil, fmt.Errorf("empty route")
	}

	result := payload

	// Encrypt in reverse order (onion/garlic layers)
	// Last hop sees the original payload
	// Each preceding hop sees encrypted data for the next hop
	for i := len(route.Hops) - 1; i >= 0; i-- {
		hop := route.Hops[i]

		// Skip dummy hops (they're just for obfuscation metadata)
		if hop.IsDummy {
			continue
		}

		// Encrypt this layer for this hop's public key
		encrypted, err := EncryptLayer(result, hop.PublicKey, senderPrivKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt layer %d: %w", i, err)
		}

		// Prepend key hash so the hop knows which key to use for decryption
		result = make([]byte, 32+len(encrypted))
		copy(result[:32], hop.KeyHash[:])
		copy(result[32:], encrypted)
	}

	return result, nil
}

// UnwrapLayer removes one encryption layer from the packet
// Returns the inner data and the key hash that was used
func UnwrapLayer(data []byte, keyring Keyring, senderPubKey ed25519.PublicKey) ([]byte, [32]byte, error) {
	if len(data) < 64 { // 32 key hash + 32 checksum minimum
		return nil, [32]byte{}, ErrPacketTooShort
	}

	// Extract key hash
	var keyHash [32]byte
	copy(keyHash[:], data[:32])

	// Get private key from keyring
	privKey, ok := keyring.GetPrivateKey(keyHash)
	if !ok {
		return nil, keyHash, ErrKeyNotFound
	}

	// Decrypt this layer
	decrypted, err := DecryptLayer(data[32:], privKey, senderPubKey)
	if err != nil {
		return nil, keyHash, fmt.Errorf("decrypt layer: %w", err)
	}

	return decrypted, keyHash, nil
}

// UnwrapAllLayers decrypts all layers of an onion packet
// Useful for the final recipient who has all the keys
func UnwrapAllLayers(data []byte, keyring Keyring, senderPubKey ed25519.PublicKey) ([]byte, error) {
	current := data

	for {
		if len(current) < 64 {
			// No more layers, return what we have
			return current, nil
		}

		// Try to unwrap a layer
		decrypted, _, err := UnwrapLayer(current, keyring, senderPubKey)
		if err != nil {
			// If we can't find the key, we've reached the payload
			if err == ErrKeyNotFound {
				return current, nil
			}
			return nil, err
		}

		current = decrypted
	}
}

// EncryptForRoute encrypts data for a complete route
// This is the main function to use for sending data through a tunnel
func EncryptForRoute(payload []byte, route *Route, senderPrivKey ed25519.PrivateKey) ([]byte, error) {
	return BuildOnionPacket(payload, route, senderPrivKey)
}

// DecryptAtHop decrypts one layer at a specific hop
// Returns the data to forward to the next hop
func DecryptAtHop(data []byte, hopPrivKey ed25519.PrivateKey, senderPubKey ed25519.PublicKey) ([]byte, error) {
	if len(data) < 32 {
		return nil, ErrPacketTooShort
	}

	// Skip the key hash prefix (it was used to identify this hop)
	encrypted := data[32:]

	return DecryptLayer(encrypted, hopPrivKey, senderPubKey)
}

// CreateLayeredKeys generates a set of ephemeral keys for a multi-hop route
// Returns private keys (to give to each hop) and the corresponding key hashes
func CreateLayeredKeys(numHops int) ([]ed25519.PrivateKey, [][32]byte, error) {
	if numHops < 1 {
		return nil, nil, fmt.Errorf("need at least 1 hop")
	}

	privKeys := make([]ed25519.PrivateKey, numHops)
	keyHashes := make([][32]byte, numHops)

	for i := 0; i < numHops; i++ {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, nil, fmt.Errorf("generate key %d: %w", i, err)
		}

		privKeys[i] = priv
		keyHashes[i] = sha256.Sum256(pub)
	}

	return privKeys, keyHashes, nil
}
