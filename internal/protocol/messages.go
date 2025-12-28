package protocol

import "github.com/xssnick/tonutils-go/tl"

// Protocol version
const Version = 1

// Register TL types
func init() {
	tl.Register(Hello{}, "relay.hello node_id:int256 version:int capabilities:int = relay.Hello")
	tl.Register(HelloAck{}, "relay.helloAck node_id:int256 version:int = relay.HelloAck")
	tl.Register(CircuitCreate{}, "relay.circuitCreate circuit_id:int256 client_key:int256 = relay.CircuitCreate")
	tl.Register(CircuitCreated{}, "relay.circuitCreated circuit_id:int256 relay_key:int256 key_hash:int256 = relay.CircuitCreated")
	tl.Register(CircuitExtend{}, "relay.circuitExtend circuit_id:int256 next_relay:int256 encrypted:bytes = relay.CircuitExtend")
	tl.Register(ExtendPayload{}, "relay.extendPayload next_addr:string client_key:int256 = relay.ExtendPayload")
	tl.Register(CircuitExtended{}, "relay.circuitExtended circuit_id:int256 relay_key:int256 key_hash:int256 = relay.CircuitExtended")
	tl.Register(CircuitDestroy{}, "relay.circuitDestroy circuit_id:int256 = relay.CircuitDestroy")
	tl.Register(CircuitRelay{}, "relay.circuitRelay circuit_id:int256 encrypted:bytes = relay.CircuitRelay")
	tl.Register(CircuitRelayResponse{}, "relay.circuitRelayResponse circuit_id:int256 encrypted:bytes = relay.CircuitRelayResponse")
	tl.Register(Data{}, "relay.data circuit_id:int256 stream_id:int data:bytes = relay.Data")
	tl.Register(DataAck{}, "relay.dataAck circuit_id:int256 stream_id:int bytes_received:long = relay.DataAck")
	tl.Register(Ping{}, "relay.ping nonce:long = relay.Ping")
	tl.Register(Pong{}, "relay.pong nonce:long = relay.Pong")
	tl.Register(Error{}, "relay.error code:int message:string = relay.Error")
	tl.Register(GetPeers{}, "relay.getPeers max_count:int = relay.GetPeers")
	tl.Register(Peers{}, "relay.peers peers:vector<relay.peerInfo> = relay.Peers")
	tl.Register(PeerInfo{}, "relay.peerInfo adnl_id:int256 ip:string port:int capacity:int = relay.PeerInfo")
	tl.Register(StreamConnect{}, "relay.streamConnect stream_id:int host:string port:int = relay.StreamConnect")
	tl.Register(StreamConnected{}, "relay.streamConnected stream_id:int success:Bool error:string = relay.StreamConnected")
	tl.Register(StreamData{}, "relay.streamData stream_id:int data:bytes = relay.StreamData")
	tl.Register(StreamClose{}, "relay.streamClose stream_id:int = relay.StreamClose")
	tl.Register(DataChunk{}, "relay.dataChunk circuit_id:int256 stream_id:int chunk_index:int total_chunks:int data:bytes = relay.DataChunk")
}

// Hello is the initial handshake message
type Hello struct {
	NodeID       []byte `tl:"int256"`
	Version      int    `tl:"int"`
	Capabilities int    `tl:"int"`
}

// HelloAck is the response to Hello
type HelloAck struct {
	NodeID  []byte `tl:"int256"`
	Version int    `tl:"int"`
}

// CircuitCreate requests creation of a new circuit
type CircuitCreate struct {
	CircuitID []byte `tl:"int256"`
	ClientKey []byte `tl:"int256"`
}

// CircuitCreated confirms circuit creation
type CircuitCreated struct {
	CircuitID []byte `tl:"int256"`
	RelayKey  []byte `tl:"int256"`
	KeyHash   []byte `tl:"int256"`
}

// CircuitExtend requests extending the circuit to another relay
type CircuitExtend struct {
	CircuitID []byte `tl:"int256"`
	NextRelay []byte `tl:"int256"` // ADNL ID of next relay
	Encrypted []byte `tl:"bytes"`  // Encrypted ExtendPayload
}

// ExtendPayload is the encrypted content of CircuitExtend
// Contains: next relay address + CircuitCreate for next relay
type ExtendPayload struct {
	NextAddr  string `tl:"string"`  // ip:port of next relay
	ClientKey []byte `tl:"int256"`  // X25519 public key for next hop
}

// CircuitExtended confirms circuit extension
type CircuitExtended struct {
	CircuitID []byte `tl:"int256"`
	RelayKey  []byte `tl:"int256"` // Next relay's X25519 public key
	KeyHash   []byte `tl:"int256"` // Hash of shared key with next relay
}

// CircuitDestroy requests circuit teardown
type CircuitDestroy struct {
	CircuitID []byte `tl:"int256"`
}

// CircuitRelay forwards an encrypted command through the circuit
// Used for multi-hop (3+) circuit operations
// The encrypted payload is decrypted by this hop, then forwarded to the next hop
type CircuitRelay struct {
	CircuitID []byte `tl:"int256"`
	Encrypted []byte `tl:"bytes"` // Decrypted by this hop, inner content forwarded
}

// CircuitRelayResponse carries the response back through the circuit
type CircuitRelayResponse struct {
	CircuitID []byte `tl:"int256"`
	Encrypted []byte `tl:"bytes"` // Encrypted response from deeper hop
}

// Data carries encrypted payload through the circuit
type Data struct {
	CircuitID []byte `tl:"int256"`
	StreamID  int    `tl:"int"`
	Data      []byte `tl:"bytes"`
}

// DataAck acknowledges received data
type DataAck struct {
	CircuitID     []byte `tl:"int256"`
	StreamID      int    `tl:"int"`
	BytesReceived int64  `tl:"long"`
}

// Ping is a keepalive message
type Ping struct {
	Nonce int64 `tl:"long"`
}

// Pong is the response to Ping
type Pong struct {
	Nonce int64 `tl:"long"`
}

// Error indicates a protocol error
type Error struct {
	Code    int    `tl:"int"`
	Message string `tl:"string"`
}

// GetPeers requests a list of known peers
type GetPeers struct {
	MaxCount int `tl:"int"`
}

// Peers contains a list of peer information
type Peers struct {
	Peers []*PeerInfo `tl:"vector struct"`
}

// PeerInfo contains information about a peer
type PeerInfo struct {
	ADNLID   []byte `tl:"int256"`
	IP       string `tl:"string"`
	Port     int    `tl:"int"`
	Capacity int    `tl:"int"`
}

// StreamConnect - Client requests connection to a destination
type StreamConnect struct {
	StreamID int    `tl:"int"`
	Host     string `tl:"string"`
	Port     int    `tl:"int"`
}

// StreamConnected - Exit confirms the connection
type StreamConnected struct {
	StreamID int    `tl:"int"`
	Success  bool   `tl:"bool"`
	Error    string `tl:"string"`
}

// StreamData - Data on a stream (HTTP request/response)
type StreamData struct {
	StreamID int    `tl:"int"`
	Data     []byte `tl:"bytes"`
}

// StreamClose - Close a stream
type StreamClose struct {
	StreamID int `tl:"int"`
}

// DataChunk - Chunked data for large responses (ADNL has ~8KB limit)
type DataChunk struct {
	CircuitID   []byte `tl:"int256"`
	StreamID    int    `tl:"int"`
	ChunkIndex  int    `tl:"int"`  // 0-indexed chunk number
	TotalChunks int    `tl:"int"`  // Total number of chunks
	Data        []byte `tl:"bytes"` // Chunk payload (encrypted)
}
