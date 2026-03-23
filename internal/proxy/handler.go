// Package proxy provides the HTTP handler that forwards requests through
// a TON proxy backend (circuit or direct).
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/adnl-network/adnl-proxy/internal/client"
	"github.com/adnl-network/adnl-proxy/internal/directory"
	"github.com/adnl-network/adnl-proxy/internal/resolver"
	"github.com/xssnick/tonutils-go/adnl"
)

const (
	// requestTimeout is the maximum duration for proxying a single HTTP request.
	requestTimeout = 60 * time.Second

	// defaultBackendPort is the port used when connecting to a TON site backend.
	defaultBackendPort = 80

	// circuitIDPrefixLen is the number of hex characters printed when logging circuit IDs.
	circuitIDPrefixLen = 8

	// jitterPercent controls the ±percentage applied to rotation intervals.
	jitterPercent = 30
)

// Supported TON-native TLD suffixes. Requests for other TLDs are routed
// through the multi-chain resolver (if available).
var tonNativeSuffixes = []string{".ton", ".adnl", ".t.me"}

// hopByHopHeaders lists HTTP hop-by-hop headers that must be stripped by proxies
// per RFC 2616 §13.5.1.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// CircuitBuilder is the function signature for building a circuit with retries.
// It is injected into ProxyHandler to avoid coupling the proxy package to
// circuit-construction logic.
type CircuitBuilder func(ctx context.Context, gate *adnl.Gateway, dir *directory.Directory, maxRetries int) (*client.ClientCircuit, error)

// ProxyHandler handles HTTP requests and forwards them through the proxy backend.
type ProxyHandler struct {
	backend   client.ProxyClient
	backendMu sync.RWMutex

	// backendWg counts requests currently using the active backend.
	// RotateCircuit swaps it together with backend so that only the old
	// WaitGroup is drained before closing the old backend.
	backendWg *sync.WaitGroup

	// Circuit-mode fields (unused in direct mode).
	gate           *adnl.Gateway
	dir            *directory.Directory
	rotateInterval time.Duration
	retries        int
	directMode     bool

	// multiResolver routes non-TON-native domains (.eth, .sol, etc.)
	// to their chain-specific resolvers.
	multiResolver *resolver.MultiResolver

	// buildCircuit is injected by the caller (cmd/main.go) to build
	// circuits without coupling this package to relay selection logic.
	buildCircuit CircuitBuilder
}

// HandlerConfig holds the parameters needed to construct a ProxyHandler.
type HandlerConfig struct {
	Backend        client.ProxyClient
	Gate           *adnl.Gateway
	Dir            *directory.Directory
	RotateInterval time.Duration
	Retries        int
	DirectMode     bool
	MultiResolver  *resolver.MultiResolver
	BuildCircuit   CircuitBuilder
}

// NewProxyHandler creates a ProxyHandler from the given configuration.
// All fields in cfg are captured by value; the caller must not modify cfg
// after calling this function.
func NewProxyHandler(cfg HandlerConfig) *ProxyHandler {
	return &ProxyHandler{
		backend:        cfg.Backend,
		backendWg:      &sync.WaitGroup{},
		gate:           cfg.Gate,
		dir:            cfg.Dir,
		rotateInterval: cfg.RotateInterval,
		retries:        cfg.Retries,
		directMode:     cfg.DirectMode,
		multiResolver:  cfg.MultiResolver,
		buildCircuit:   cfg.BuildCircuit,
	}
}

// Backend returns the current backend (thread-safe).
func (h *ProxyHandler) Backend() client.ProxyClient {
	h.backendMu.RLock()
	defer h.backendMu.RUnlock()
	return h.backend
}

// isTONNative reports whether the hostname belongs to a TON-native TLD.
func isTONNative(host string) bool {
	for _, suffix := range tonNativeSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// logRequest prints a compact one-line request log to stderr.
func logRequest(method, path string, status int, elapsed time.Duration, err error) {
	ts := time.Now().Format("15:04:05")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] %s %s - %d (%.1fs) %v\n", ts, method, path, status, elapsed.Seconds(), err)
	} else {
		fmt.Fprintf(os.Stderr, "[%s] %s %s - %d (%.1fs)\n", ts, method, path, status, elapsed.Seconds())
	}
}

// ServeHTTP handles incoming HTTP requests by forwarding them through the
// configured proxy backend.
func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Extract the hostname (strip port if present) before checking the TLD
	// to prevent bypass via host values like "evil.com:.ton".
	host := r.Host
	if hostname, _, err := net.SplitHostPort(r.Host); err == nil {
		host = hostname
	}

	native := isTONNative(host)
	multiChain := h.multiResolver != nil && h.multiResolver.Supports(host)
	if !native && !multiChain {
		http.Error(w, fmt.Sprintf("Unsupported domain: %s", host), http.StatusBadRequest)
		return
	}

	// For multi-chain domains, resolve to ADNL address and rewrite the host
	// before passing to the backend. Circuit relays only understand
	// .ton/.adnl/.t.me domains.
	if multiChain {
		newHost, err := h.multiResolver.ResolveToADNL(host)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to resolve %s: %v", host, err), http.StatusBadGateway)
			return
		}
		slog.Debug("resolved", "domain", host, "adnl", newHost)
		r.Host = newHost
		r.URL.Host = newHost
	}

	// Reject CONNECT method (no HTTPS support yet).
	if r.Method == "CONNECT" {
		http.Error(w, "HTTPS not supported yet", http.StatusNotImplemented)
		return
	}

	// Capture backend reference for this request (rotation-safe).
	// Register as in-flight before releasing the lock so that RotateCircuit
	// waits for this request to finish before closing the old backend.
	h.backendMu.RLock()
	backend := h.backend
	wg := h.backendWg
	wg.Add(1)
	h.backendMu.RUnlock()
	defer wg.Done()

	if backend == nil {
		http.Error(w, "Proxy backend not ready", http.StatusServiceUnavailable)
		return
	}

	// Build request path for logging.
	reqPath := r.Host + r.URL.Path
	if r.URL.RawQuery != "" {
		reqPath += "?" + r.URL.RawQuery
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	// 1. Open stream to the destination.
	streamID, err := backend.OpenStream(ctx, r.Host, defaultBackendPort)
	if err != nil {
		logRequest(r.Method, reqPath, 502, time.Since(start), err)
		http.Error(w, "Failed to connect to site", http.StatusBadGateway)
		return
	}
	defer backend.CloseStream(streamID)

	// 2. Clean hop-by-hop headers.
	cleanRequestHeaders(r)

	// 3. Serialize the HTTP request.
	var reqBuf bytes.Buffer
	if err := r.Write(&reqBuf); err != nil {
		logRequest(r.Method, reqPath, 500, time.Since(start), err)
		http.Error(w, "Failed to serialize request", http.StatusInternalServerError)
		return
	}

	// 4. Send via backend.
	if err := backend.SendData(ctx, streamID, reqBuf.Bytes()); err != nil {
		logRequest(r.Method, reqPath, 502, time.Since(start), err)
		http.Error(w, "Failed to send request", http.StatusBadGateway)
		return
	}

	// 5. Receive response.
	respData, err := backend.RecvData(ctx, streamID)
	if err != nil {
		logRequest(r.Method, reqPath, 502, time.Since(start), err)
		http.Error(w, "Failed to receive response", http.StatusBadGateway)
		return
	}

	// 6. Parse HTTP response.
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(respData)), r)
	if err != nil {
		logRequest(r.Method, reqPath, 502, time.Since(start), err)
		http.Error(w, "Invalid response from site", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 7. Clean response headers and copy to client.
	cleanResponseHeaders(resp)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// 8. Write status code and body.
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		return
	}

	logRequest(r.Method, reqPath, resp.StatusCode, time.Since(start), nil)
}

// cleanRequestHeaders removes hop-by-hop headers from the request.
func cleanRequestHeaders(r *http.Request) {
	for _, h := range hopByHopHeaders {
		r.Header.Del(h)
	}
}

// cleanResponseHeaders removes hop-by-hop headers from the response.
func cleanResponseHeaders(r *http.Response) {
	for _, h := range hopByHopHeaders {
		r.Header.Del(h)
	}
}

// StartRotation runs the circuit rotation loop with randomized intervals.
// It blocks until ctx is cancelled.
func (h *ProxyHandler) StartRotation(ctx context.Context) {
	if h.rotateInterval <= 0 {
		return
	}

	for {
		// Add ±jitterPercent% jitter to prevent timing attacks.
		jitterRange := int64(h.rotateInterval) * 2 * jitterPercent / 100
		jitter := time.Duration(rand.Int63n(jitterRange))
		delay := h.rotateInterval - (h.rotateInterval * jitterPercent / 100) + jitter

		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
			h.RotateCircuit(ctx)
		case <-ctx.Done():
			timer.Stop()
			return
		}
	}
}

// RotateCircuit builds a new circuit and atomically swaps it in.
// It is a no-op in direct mode or if no circuit builder was configured.
func (h *ProxyHandler) RotateCircuit(ctx context.Context) {
	if h.directMode || h.buildCircuit == nil {
		return
	}

	slog.Info("rotating circuit")
	newCircuit, err := h.buildCircuit(ctx, h.gate, h.dir, h.retries)
	if err != nil {
		slog.Error("rotation failed, keeping current circuit", "error", err)
		return
	}

	h.backendMu.Lock()
	oldBackend := h.backend
	oldWg := h.backendWg
	h.backend = newCircuit
	h.backendWg = &sync.WaitGroup{}
	h.backendMu.Unlock()

	if oldBackend != nil {
		go func() {
			done := make(chan struct{})
			go func() {
				oldWg.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Minute):
				slog.Warn("timed out waiting for in-flight requests during rotation")
			}
			oldBackend.Close()
		}()
	}

	slog.Info("circuit ready", "id", hex.EncodeToString(newCircuit.ID)[:circuitIDPrefixLen])
}
