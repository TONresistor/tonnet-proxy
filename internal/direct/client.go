package direct

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TONresistor/tonnet-proxy/internal/client"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/dht"
	rldphttp "github.com/xssnick/tonutils-go/adnl/rldp/http"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/dns"
)

const (
	defaultConfigURL = "https://ton.org/global.config.json"
)

// DirectClient connects directly to TON sites without garlic routing
type DirectClient struct {
	gate       *adnl.Gateway
	dht        *dht.Client
	dnsClient  *dns.Client
	liteClient ton.APIClientWrapped
	transport  *rldphttp.Transport
	privateKey ed25519.PrivateKey

	streams    sync.Map // streamID -> *stream
	nextStream uint32
}

// stream represents an active connection to a TON site
type stream struct {
	host     string
	port     int
	request  []byte
	response []byte
	respChan chan []byte
	closed   bool
	mu       sync.Mutex
}

// Ensure DirectClient implements ProxyClient interface
var _ client.ProxyClient = (*DirectClient)(nil)

// NewDirectClient creates a new direct client
func NewDirectClient(ctx context.Context, configPath string) (*DirectClient, error) {
	// Use default config URL if not provided
	if configPath == "" {
		configPath = defaultConfigURL
	}

	// Generate private key for ADNL
	seed := make([]byte, ed25519.SeedSize)
	if _, err := cryptorand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)

	// Create ADNL gateway
	gate := adnl.NewGateway(privateKey)
	if err := gate.StartClient(); err != nil {
		return nil, fmt.Errorf("start ADNL gateway: %w", err)
	}

	// Create DHT client from config
	dhtClient, err := dht.NewClientFromConfigUrl(ctx, gate, configPath)
	if err != nil {
		return nil, fmt.Errorf("create DHT client: %w", err)
	}

	// Create lite client connection pool
	cfg, err := liteclient.GetConfigFromUrl(ctx, configPath)
	if err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}

	pool := liteclient.NewConnectionPool()
	if err := pool.AddConnectionsFromConfig(ctx, cfg); err != nil {
		return nil, fmt.Errorf("connect to liteservers: %w", err)
	}

	// Create TON API client
	api := ton.NewAPIClient(pool, ton.ProofCheckPolicyFast).WithRetry()

	// Create DNS client for .ton domain resolution
	root, err := dns.GetRootContractAddr(ctx, api)
	if err != nil {
		return nil, fmt.Errorf("get DNS root: %w", err)
	}
	dnsClient := dns.NewDNSClient(api, root)

	// Create RLDP HTTP transport
	transport := rldphttp.NewTransport(dhtClient, dnsClient, privateKey)

	return &DirectClient{
		gate:       gate,
		dht:        dhtClient,
		dnsClient:  dnsClient,
		liteClient: api,
		transport:  transport,
		privateKey: privateKey,
	}, nil
}

// OpenStream opens a connection to the specified host:port
func (c *DirectClient) OpenStream(ctx context.Context, host string, port int) (int, error) {
	streamID := int(atomic.AddUint32(&c.nextStream, 1))

	s := &stream{
		host:     host,
		port:     port,
		respChan: make(chan []byte, 1),
	}

	c.streams.Store(streamID, s)
	return streamID, nil
}

// SendData sends data on a stream (HTTP request)
func (c *DirectClient) SendData(ctx context.Context, streamID int, data []byte) error {
	si, ok := c.streams.Load(streamID)
	if !ok {
		return fmt.Errorf("stream %d not found", streamID)
	}
	s := si.(*stream)

	s.mu.Lock()
	s.request = data
	s.mu.Unlock()

	// Process the HTTP request asynchronously
	go c.processRequest(ctx, s)

	return nil
}

// processRequest handles the actual HTTP request to the TON site
func (c *DirectClient) processRequest(ctx context.Context, s *stream) {
	// Parse the HTTP request
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(s.request)))
	if err != nil {
		s.sendError(fmt.Sprintf("parse request: %v", err))
		return
	}

	// Validate domain
	host := s.host
	if !strings.HasSuffix(host, ".ton") && !strings.HasSuffix(host, ".adnl") && !strings.HasSuffix(host, ".t.me") {
		s.sendError(fmt.Sprintf("unsupported domain: %s", host))
		return
	}

	// Create HTTP client with RLDP transport
	httpClient := &http.Client{
		Transport: c.transport,
		Timeout:   60 * time.Second,
	}

	// Build the full URL
	url := fmt.Sprintf("http://%s%s", host, req.URL.String())

	// Create new request with context
	newReq, err := http.NewRequestWithContext(ctx, req.Method, url, req.Body)
	if err != nil {
		s.sendError(fmt.Sprintf("create request: %v", err))
		return
	}

	// Copy headers
	for k, vv := range req.Header {
		for _, v := range vv {
			newReq.Header.Add(k, v)
		}
	}
	newReq.Host = host

	// Execute request via RLDP
	resp, err := httpClient.Do(newReq)
	if err != nil {
		s.sendError(fmt.Sprintf("request failed: %v", err))
		return
	}
	defer resp.Body.Close()

	// Read full body to fix Content-Length mismatch from tonutils-go bug
	// (tonutils copies request Content-Length to response Content-Length)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.sendError(fmt.Sprintf("read response body: %v", err))
		return
	}

	// Reset response metadata and set correct Content-Length
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.TransferEncoding = nil
	resp.Header.Del("Content-Length")
	resp.Header.Del("Transfer-Encoding")
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	// Serialize response
	var respBuf bytes.Buffer
	if err := resp.Write(&respBuf); err != nil {
		s.sendError(fmt.Sprintf("serialize response: %v", err))
		return
	}

	s.mu.Lock()
	s.response = respBuf.Bytes()
	s.mu.Unlock()

	select {
	case s.respChan <- s.response:
	default:
	}
}

// sendError sends an HTTP 502 error response
func (s *stream) sendError(msg string) {
	resp := &http.Response{
		StatusCode: http.StatusBadGateway,
		Status:     "502 Bad Gateway",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(msg)),
	}
	resp.Header.Set("Content-Type", "text/plain")

	var buf bytes.Buffer
	resp.Write(&buf)

	s.mu.Lock()
	s.response = buf.Bytes()
	s.mu.Unlock()

	select {
	case s.respChan <- s.response:
	default:
	}
}

// RecvData receives data from a stream
func (c *DirectClient) RecvData(ctx context.Context, streamID int) ([]byte, error) {
	si, ok := c.streams.Load(streamID)
	if !ok {
		return nil, fmt.Errorf("stream %d not found", streamID)
	}
	s := si.(*stream)

	select {
	case data := <-s.respChan:
		return data, nil
	case <-time.After(60 * time.Second):
		return nil, fmt.Errorf("timeout waiting for response")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// CloseStream closes a specific stream
func (c *DirectClient) CloseStream(streamID int) {
	c.streams.Delete(streamID)
}

// Close closes the client
func (c *DirectClient) Close() error {
	if c.dht != nil {
		c.dht.Close()
	}
	return nil
}
