package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/TONresistor/tonnet-proxy/internal/client"
	"github.com/TONresistor/tonnet-proxy/internal/direct"
	"github.com/TONresistor/tonnet-proxy/internal/directory"
	"github.com/spf13/cobra"
	"github.com/xssnick/tonutils-go/adnl"
)

var version = "dev"

const banner = `
▗▄▄▄▖▗▄▖ ▗▖  ▗▖▗▖  ▗▖▗▄▄▄▖▗▄▄▄▖    ▗▄▄▖ ▗▄▄▖  ▗▄▖ ▗▖  ▗▖▗▖  ▗▖
  █ ▐▌ ▐▌▐▛▚▖▐▌▐▛▚▖▐▌▐▌     █      ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌ ▝▚▞▘  ▝▚▞▘
  █ ▐▌ ▐▌▐▌ ▝▜▌▐▌ ▝▜▌▐▛▀▀▘  █      ▐▛▀▘ ▐▛▀▚▖▐▌ ▐▌  ▐▌    ▐▌
  █ ▝▚▄▞▘▐▌  ▐▌▐▌  ▐▌▐▙▄▄▖  █      ▐▌   ▐▌ ▐▌▝▚▄▞▘▗▞▘▝▚▖  ▐▌

               Private Gateway to TON Sites
`

// ProxyHandler handles HTTP requests and forwards them through the proxy backend
type ProxyHandler struct {
	backend   client.ProxyClient
	backendMu sync.RWMutex

	// Only used in circuit mode
	gate           *adnl.Gateway
	dir            *directory.Directory
	rotateInterval time.Duration
	retries        int
	directMode     bool
}

// ServeHTTP handles incoming HTTP requests
func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Validate domain - only .ton, .adnl, .t.me supported
	if !strings.HasSuffix(r.Host, ".ton") &&
		!strings.HasSuffix(r.Host, ".adnl") &&
		!strings.HasSuffix(r.Host, ".t.me") {
		http.Error(w, "Only .ton, .adnl, .t.me domains supported", http.StatusBadRequest)
		return
	}

	// Reject CONNECT method (no HTTPS support yet)
	if r.Method == "CONNECT" {
		http.Error(w, "HTTPS not supported yet", http.StatusNotImplemented)
		return
	}

	// Capture backend reference for this request (rotation-safe)
	h.backendMu.RLock()
	backend := h.backend
	h.backendMu.RUnlock()

	// Build request path for logging
	reqPath := r.Host + r.URL.Path
	if r.URL.RawQuery != "" {
		reqPath += "?" + r.URL.RawQuery
	}

	// Add timeout
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	// 1. Open stream to the destination
	streamID, err := backend.OpenStream(ctx, r.Host, 80)
	if err != nil {
		elapsed := time.Since(start)
		fmt.Printf("[%s] %s %s - 502 (%.1fs) %v\n", time.Now().Format("15:04:05"), r.Method, reqPath, elapsed.Seconds(), err)
		http.Error(w, "Failed to connect to site", http.StatusBadGateway)
		return
	}

	// Ensure stream is closed on exit
	defer backend.CloseStream(streamID)

	// 2. Clean hop-by-hop headers
	cleanRequestHeaders(r)

	// 3. Serialize the HTTP request
	var reqBuf bytes.Buffer
	if err := r.Write(&reqBuf); err != nil {
		elapsed := time.Since(start)
		fmt.Printf("[%s] %s %s - 500 (%.1fs) %v\n", time.Now().Format("15:04:05"), r.Method, reqPath, elapsed.Seconds(), err)
		http.Error(w, "Failed to serialize request", http.StatusInternalServerError)
		return
	}

	// 4. Send via backend
	if err := backend.SendData(ctx, streamID, reqBuf.Bytes()); err != nil {
		elapsed := time.Since(start)
		fmt.Printf("[%s] %s %s - 502 (%.1fs) %v\n", time.Now().Format("15:04:05"), r.Method, reqPath, elapsed.Seconds(), err)
		http.Error(w, "Failed to send request", http.StatusBadGateway)
		return
	}

	// 5. Receive response
	respData, err := backend.RecvData(ctx, streamID)
	if err != nil {
		elapsed := time.Since(start)
		fmt.Printf("[%s] %s %s - 502 (%.1fs) %v\n", time.Now().Format("15:04:05"), r.Method, reqPath, elapsed.Seconds(), err)
		http.Error(w, "Failed to receive response", http.StatusBadGateway)
		return
	}

	// 6. Parse HTTP response
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(respData)), r)
	if err != nil {
		elapsed := time.Since(start)
		fmt.Printf("[%s] %s %s - 502 (%.1fs) %v\n", time.Now().Format("15:04:05"), r.Method, reqPath, elapsed.Seconds(), err)
		http.Error(w, "Invalid response from site", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 7. Clean response headers and copy to client
	cleanResponseHeaders(resp)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// 8. Write status code and body
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	// Log request
	elapsed := time.Since(start)
	fmt.Printf("[%s] %s %s - %d (%.1fs)\n",
		time.Now().Format("15:04:05"),
		r.Method,
		reqPath,
		resp.StatusCode,
		elapsed.Seconds(),
	)
}

// cleanRequestHeaders removes hop-by-hop headers from request
func cleanRequestHeaders(r *http.Request) {
	hopByHop := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	for _, h := range hopByHop {
		r.Header.Del(h)
	}
}

// cleanResponseHeaders removes hop-by-hop headers from response
func cleanResponseHeaders(r *http.Response) {
	hopByHop := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	for _, h := range hopByHop {
		r.Header.Del(h)
	}
}

// parseRelay parses a relay specification "address,pubkey_hex"
func parseRelay(spec string) (client.RelayInfo, error) {
	parts := strings.Split(spec, ",")
	if len(parts) != 2 {
		return client.RelayInfo{}, fmt.Errorf("invalid relay format, expected 'address,pubkey_hex', got: %s", spec)
	}

	address := strings.TrimSpace(parts[0])
	pubkeyHex := strings.TrimSpace(parts[1])

	pubkeyBytes, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return client.RelayInfo{}, fmt.Errorf("invalid public key hex: %w", err)
	}

	if len(pubkeyBytes) != ed25519.PublicKeySize {
		return client.RelayInfo{}, fmt.Errorf("invalid public key length: expected %d, got %d",
			ed25519.PublicKeySize, len(pubkeyBytes))
	}

	return client.RelayInfo{
		Address:   address,
		PublicKey: ed25519.PublicKey(pubkeyBytes),
	}, nil
}

// generatePrivateKey generates a new ed25519 private key
func generatePrivateKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := cryptorand.Read(seed); err != nil {
		panic(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// buildCircuitWithRetry attempts to build a circuit with retries
func buildCircuitWithRetry(ctx context.Context, gate *adnl.Gateway, dir *directory.Directory, maxRetries int) (*client.ClientCircuit, error) {
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		relays, err := dir.SelectCircuitRelays()
		if err != nil {
			lastErr = err
			continue
		}

		fmt.Printf("Building circuit (attempt %d/%d)...\n", attempt, maxRetries)
		fmt.Printf("  Entry:  %s (%s)\n", dir.GetRelayName(relays[0].Address), relays[0].Address)
		fmt.Printf("  Middle: %s (%s)\n", dir.GetRelayName(relays[1].Address), relays[1].Address)
		fmt.Printf("  Exit:   %s (%s)\n", dir.GetRelayName(relays[2].Address), relays[2].Address)

		circuit, err := client.NewClientCircuit(ctx, gate, relays)
		if err == nil {
			return circuit, nil
		}

		lastErr = err
		fmt.Printf("  Failed: %v\n", err)
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", maxRetries, lastErr)
}

// startRotation runs the circuit rotation loop with randomized intervals
func (h *ProxyHandler) startRotation(ctx context.Context) {
	if h.rotateInterval <= 0 {
		return
	}

	for {
		// Add ±30% jitter to prevent timing attacks
		jitter := time.Duration(rand.Int63n(int64(h.rotateInterval) * 6 / 10)) // 0 to 60%
		delay := h.rotateInterval - (h.rotateInterval * 3 / 10) + jitter       // base - 30% + jitter

		select {
		case <-time.After(delay):
			h.rotateCircuit(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// rotateCircuit builds a new circuit and swaps it (only for circuit mode)
func (h *ProxyHandler) rotateCircuit(ctx context.Context) {
	if h.directMode {
		return // No rotation in direct mode
	}

	fmt.Println()
	newCircuit, err := buildCircuitWithRetry(ctx, h.gate, h.dir, h.retries)
	if err != nil {
		fmt.Printf("Rotation failed: %v (keeping current circuit)\n", err)
		return
	}

	h.backendMu.Lock()
	oldBackend := h.backend
	h.backend = newCircuit
	h.backendMu.Unlock()

	if oldBackend != nil {
		oldBackend.Close()
	}

	fmt.Printf("Circuit ready [%s]\n", hex.EncodeToString(newCircuit.ID)[:8])
	fmt.Println()
}

func run(cmd *cobra.Command, args []string) {
	// Get flags
	relay1, _ := cmd.Flags().GetString("relay1")
	relay2, _ := cmd.Flags().GetString("relay2")
	relay3, _ := cmd.Flags().GetString("relay3")
	listen, _ := cmd.Flags().GetString("listen")
	auto, _ := cmd.Flags().GetBool("auto")
	directMode, _ := cmd.Flags().GetBool("direct")
	configPath, _ := cmd.Flags().GetString("config")
	directoryURL, _ := cmd.Flags().GetString("directory")
	retries, _ := cmd.Flags().GetInt("retries")
	rotateStr, _ := cmd.Flags().GetString("rotate")

	// Parse rotation interval
	var rotateInterval time.Duration
	if rotateStr != "" {
		var err error
		rotateInterval, err = time.ParseDuration(rotateStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid --rotate value: %s\n", rotateStr)
			os.Exit(1)
		}
	}

	// Validate rotation requires auto mode (and not direct mode)
	if rotateInterval > 0 && !auto {
		fmt.Fprintln(os.Stderr, "Error: --rotate requires --auto mode")
		os.Exit(1)
	}
	if rotateInterval > 0 && directMode {
		fmt.Fprintln(os.Stderr, "Error: --rotate is not supported in --direct mode")
		os.Exit(1)
	}

	// Print banner
	fmt.Println(banner)
	fmt.Printf("  Version: %s\n\n", version)

	ctx := context.Background()
	var backend client.ProxyClient
	var gate *adnl.Gateway
	var dir *directory.Directory

	if directMode {
		// Direct mode: connect directly to TON sites (no anonymity)
		fmt.Print("Connecting to TON network... ")

		directClient, err := direct.NewDirectClient(ctx, configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nError: failed to create direct client: %v\n", err)
			os.Exit(1)
		}

		backend = directClient
		fmt.Println("OK")
		fmt.Println("Mode: Direct (no anonymity, faster)")
	} else {
		// Circuit mode: 3-hop garlic routing (anonymous)

		// Generate client private key
		privateKey := generatePrivateKey()

		// Create ADNL gateway
		gate = adnl.NewGateway(privateKey)
		if err := gate.StartClient(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to start ADNL gateway: %v\n", err)
			os.Exit(1)
		}

		var circuit *client.ClientCircuit

		if auto {
			// Auto mode: fetch directory and build circuit with retry
			fmt.Print("Loading community relays... ")

			var err error
			dir, err = directory.Fetch(directoryURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "\nError: failed to fetch directory: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("%d found\n", len(dir.Relays))

			circuit, err = buildCircuitWithRetry(ctx, gate, dir, retries)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		} else {
			// Manual mode: use provided relay flags
			if relay1 == "" || relay2 == "" || relay3 == "" {
				fmt.Fprintln(os.Stderr, "Error: use --auto, --direct, or provide --relay1, --relay2, --relay3")
				os.Exit(1)
			}

			r1, err := parseRelay(relay1)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid relay1: %v\n", err)
				os.Exit(1)
			}

			r2, err := parseRelay(relay2)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid relay2: %v\n", err)
				os.Exit(1)
			}

			r3, err := parseRelay(relay3)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid relay3: %v\n", err)
				os.Exit(1)
			}

			relays := []client.RelayInfo{r1, r2, r3}

			fmt.Println("Building circuit...")
			fmt.Printf("  Entry:  %s\n", r1.Address)
			fmt.Printf("  Middle: %s\n", r2.Address)
			fmt.Printf("  Exit:   %s\n", r3.Address)

			circuit, err = client.NewClientCircuit(ctx, gate, relays)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to create circuit: %v\n", err)
				os.Exit(1)
			}
		}

		backend = circuit
		fmt.Printf("Circuit ready [%s]\n", hex.EncodeToString(circuit.ID)[:8])
		fmt.Println("Mode: Anonymous (3-hop garlic circuit)")
	}

	fmt.Println()

	// Show rotation status
	if rotateInterval > 0 {
		fmt.Printf("Circuit rotation: every %s\n", rotateInterval)
	}

	fmt.Printf("Proxy listening on http://localhost%s\n", listen)
	fmt.Println()

	// Create proxy handler
	handler := &ProxyHandler{
		backend:        backend,
		gate:           gate,
		dir:            dir,
		rotateInterval: rotateInterval,
		retries:        retries,
		directMode:     directMode,
	}

	// Start rotation goroutine if enabled
	if rotateInterval > 0 && !directMode {
		go handler.startRotation(ctx)
	}

	// Start HTTP proxy server
	server := &http.Server{
		Addr:    listen,
		Handler: handler,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "Error: HTTP server error: %v\n", err)
		os.Exit(1)
	}
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "tonnet-proxy",
		Short: "TON Sites HTTP proxy with optional 3-hop garlic circuit",
		Long: `tonnet-proxy provides a local HTTP proxy for .ton, .adnl, and .t.me domains.

Two modes available:

  --direct     Fast direct connection (no anonymity, like tonutils-proxy)
  --auto       Anonymous 3-hop garlic circuit with auto-selected relays

Examples:
  # Direct mode (fast, no anonymity)
  tonnet-proxy --direct --listen :8080

  # Anonymous mode with auto-selected relays
  tonnet-proxy --auto --listen :8080

  # Anonymous mode with manual relays
  tonnet-proxy \
    --relay1 "127.0.0.1:9001,<pubkey1_hex>" \
    --relay2 "127.0.0.1:9002,<pubkey2_hex>" \
    --relay3 "127.0.0.1:9003,<pubkey3_hex>" \
    --listen :8080

Then configure your browser to use http://localhost:8080 as HTTP proxy.`,
		Run: run,
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Show version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("tonnet-proxy %s\n", version)
		},
	}
	rootCmd.AddCommand(versionCmd)

	rootCmd.Flags().String("relay1", "", "Entry relay (format: ip:port,pubkey_hex)")
	rootCmd.Flags().String("relay2", "", "Middle relay (format: ip:port,pubkey_hex)")
	rootCmd.Flags().String("relay3", "", "Exit relay (format: ip:port,pubkey_hex)")
	rootCmd.Flags().String("listen", ":8080", "Local proxy listen address")
	rootCmd.Flags().Bool("auto", false, "Auto-select relays from community directory")
	rootCmd.Flags().Bool("direct", false, "Direct connection mode (no anonymity, faster)")
	rootCmd.Flags().String("config", "", "TON network config file or URL (default: auto-download)")
	rootCmd.Flags().String("directory", directory.DefaultURL, "Relay directory URL")
	rootCmd.Flags().Int("retries", 3, "Max circuit build attempts in auto mode")
	rootCmd.Flags().String("rotate", "", "Circuit rotation interval (default 10m)")
	rootCmd.Flags().Lookup("rotate").NoOptDefVal = "10m"

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
