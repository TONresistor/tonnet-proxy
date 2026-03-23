package main

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/adnl-network/adnl-proxy/internal/client"
	"github.com/adnl-network/adnl-proxy/internal/config"
	"github.com/adnl-network/adnl-proxy/internal/direct"
	"github.com/adnl-network/adnl-proxy/internal/directory"
	"github.com/adnl-network/adnl-proxy/internal/logger"
	"github.com/adnl-network/adnl-proxy/internal/proxy"
	"github.com/adnl-network/adnl-proxy/internal/resolver"
	"github.com/spf13/cobra"
	"github.com/xssnick/tonutils-go/adnl"
)

var version = "dev"

const banner = `
    ┌─────────────────────────────────────────────────────────────────┐
    │ ▗▄▄▄▖▗▄▖ ▗▖  ▗▖▗▖  ▗▖▗▄▄▄▖▗▄▄▄▖    ▗▄▄▖ ▗▄▄▖  ▗▄▖ ▗▖  ▗▖▗▖  ▗▖  │
    │   █ ▐▌ ▐▌▐▛▚▖▐▌▐▛▚▖▐▌▐▌     █      ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌ ▝▚▞▘  ▝▚▞▘   │
    │   █ ▐▌ ▐▌▐▌ ▝▜▌▐▌ ▝▜▌▐▛▀▀▘  █      ▐▛▀▘ ▐▛▀▚▖▐▌ ▐▌  ▐▌    ▐▌    │
    │   █ ▝▚▄▞▘▐▌  ▐▌▐▌  ▐▌▐▙▄▄▖  █      ▐▌   ▐▌ ▐▌▝▚▄▞▘▗▞▘▝▚▖  ▐▌    │
    │                                                                 │
    └───────────────────────@RESISTANCETOOLS──────────────────────────┘
`

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

		fmt.Fprintf(os.Stderr, "  Building circuit (attempt %d/%d)...\n", attempt, maxRetries)
		fmt.Fprintf(os.Stderr, "    Entry:  %s (%s)\n", dir.GetRelayName(relays[0].Address), relays[0].Address)
		fmt.Fprintf(os.Stderr, "    Middle: %s (%s)\n", dir.GetRelayName(relays[1].Address), relays[1].Address)
		fmt.Fprintf(os.Stderr, "    Exit:   %s (%s)\n", dir.GetRelayName(relays[2].Address), relays[2].Address)

		circuit, err := client.NewClientCircuit(ctx, gate, relays)
		if err == nil {
			return circuit, nil
		}

		lastErr = err
		fmt.Fprintf(os.Stderr, "    Failed: %v\n", err)
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", maxRetries, lastErr)
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
	ethRPC, _ := cmd.Flags().GetString("eth-rpc")
	solRPC, _ := cmd.Flags().GetString("sol-rpc")
	debug, _ := cmd.Flags().GetBool("debug")

	// Load YAML config file if provided; CLI flags override file values.
	configFile, _ := cmd.Flags().GetString("config-file")
	var fileCfg *config.ProxyConfig
	if configFile != "" {
		var err error
		fileCfg, err = config.Load(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
	if fileCfg != nil {
		if !cmd.Flags().Changed("listen") && fileCfg.Listen != "" {
			listen = fileCfg.Listen
		}
		if !cmd.Flags().Changed("auto") && !cmd.Flags().Changed("direct") && fileCfg.Mode != "" {
			switch fileCfg.Mode {
			case "auto":
				auto = true
			case "direct":
				directMode = true
			}
		}
		if !cmd.Flags().Changed("config") && fileCfg.TONConfig != "" {
			configPath = fileCfg.TONConfig
		}
		if !cmd.Flags().Changed("directory") && fileCfg.DirectoryURL != "" {
			directoryURL = fileCfg.DirectoryURL
		}
		if !cmd.Flags().Changed("retries") && fileCfg.Retries > 0 {
			retries = fileCfg.Retries
		}
		if !cmd.Flags().Changed("rotate") && fileCfg.Rotate != "" {
			rotateStr = fileCfg.Rotate
		}
		if !cmd.Flags().Changed("debug") && fileCfg.Debug {
			debug = true
		}
		if !cmd.Flags().Changed("eth-rpc") {
			if v, ok := fileCfg.RPC[".eth"]; ok {
				ethRPC = v
			}
		}
		if !cmd.Flags().Changed("sol-rpc") {
			if v, ok := fileCfg.RPC[".sol"]; ok {
				solRPC = v
			}
		}
	}

	// Initialize structured logger.
	logger.Init(debug)

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

	if rotateInterval > 0 && !auto {
		fmt.Fprintf(os.Stderr, "Error: --rotate requires --auto mode\n")
		os.Exit(1)
	}
	if rotateInterval > 0 && directMode {
		fmt.Fprintf(os.Stderr, "Error: --rotate is not supported in --direct mode\n")
		os.Exit(1)
	}

	// Print banner
	fmt.Print(banner)
	fmt.Printf("  Version: %s\n\n", version)

	// ctx is cancelled on SIGINT or SIGTERM, which triggers graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var backend client.ProxyClient
	var gate *adnl.Gateway
	var dir *directory.Directory

	// Initialize all registered chain resolvers.
	// Start with any RPC overrides from the config file, then let CLI flags win.
	rpcOverrides := make(map[string]string)
	if fileCfg != nil {
		for k, v := range fileCfg.RPC {
			rpcOverrides[k] = v
		}
	}

	polygonRPC, _ := cmd.Flags().GetString("polygon-rpc")
	bnbRPC, _ := cmd.Flags().GetString("bnb-rpc")
	btcRPC, _ := cmd.Flags().GetString("btc-rpc")

	if ethRPC != "" {
		rpcOverrides[".eth"] = ethRPC
	}
	if solRPC != "" {
		rpcOverrides[".sol"] = solRPC
	}
	if polygonRPC != "" {
		// Apply to all UD TLDs
		for _, tld := range []string{".crypto", ".x", ".wallet", ".nft", ".dao", ".blockchain", ".bitcoin", ".zil"} {
			rpcOverrides[tld] = polygonRPC
		}
	}
	if bnbRPC != "" {
		rpcOverrides[".bnb"] = bnbRPC
	}
	if btcRPC != "" {
		rpcOverrides[".btc"] = btcRPC
	}

	disabled := make(map[string]bool)
	// Apply disabled TLDs from config file first.
	if fileCfg != nil {
		for _, tld := range fileCfg.Disabled {
			disabled[tld] = true
		}
	}
	for _, cfg := range resolver.AllChains() {
		flag := "no-" + strings.TrimPrefix(cfg.TLD, ".")
		if val, _ := cmd.Flags().GetBool(flag); val {
			disabled[cfg.TLD] = true
		}
	}

	multiRes, warnings := resolver.InitAll(rpcOverrides, disabled)
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "  [!] %s\n", w)
	}
	// Display domains in a curated order: native TON first, then major chains, then the rest.
	priority := map[string]int{
		".ton": 0, ".t.me": 1, ".adnl": 2,
		".eth": 3, ".sol": 4, ".btc": 5, ".bnb": 6,
		".wallet": 7, ".nft": 8, ".crypto": 9,
	}
	tlds := append([]string{".ton", ".adnl", ".t.me"}, multiRes.EnabledTLDs()...)
	sort.Slice(tlds, func(i, j int) bool {
		pi, oki := priority[tlds[i]]
		pj, okj := priority[tlds[j]]
		if oki && okj {
			return pi < pj
		}
		if oki {
			return true
		}
		if okj {
			return false
		}
		return tlds[i] < tlds[j]
	})
	fmt.Fprintf(os.Stderr, "  Domains:  %s\n", strings.Join(tlds, " "))

	if directMode {
		fmt.Fprintf(os.Stderr, "  Connecting to TON network...\n")

		directClient, err := direct.NewDirectClient(ctx, configPath, multiRes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Error: %v\n", err)
			os.Exit(1)
		}

		backend = directClient
		fmt.Fprintf(os.Stderr, "  Mode: direct (no anonymity, faster)\n")
	} else {
		// Circuit mode: 3-hop garlic routing (anonymous)

		// Generate client private key
		privateKey := generatePrivateKey()

		// Create ADNL gateway
		gate = adnl.NewGateway(privateKey)
		if err := gate.StartClient(); err != nil {
			fmt.Fprintf(os.Stderr, "  Error: start ADNL gateway: %v\n", err)
			os.Exit(1)
		}

		var circuit *client.ClientCircuit

		if auto {
			fmt.Fprintf(os.Stderr, "  Loading community relays...\n")

			var err error
			dir, err = directory.Fetch(directoryURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Fprintf(os.Stderr, "  Relays: %d available\n", len(dir.Relays))

			circuit, err = buildCircuitWithRetry(ctx, gate, dir, retries)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Error: circuit build failed: %v\n", err)
				os.Exit(1)
			}
		} else {
			// Manual mode: use provided relay flags
			if relay1 == "" || relay2 == "" || relay3 == "" {
				fmt.Fprintf(os.Stderr, "  Error: use --auto, --direct, or provide --relay1, --relay2, --relay3\n")
				os.Exit(1)
			}

			r1, err := parseRelay(relay1)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Error: invalid relay1: %v\n", err)
				os.Exit(1)
			}

			r2, err := parseRelay(relay2)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Error: invalid relay2: %v\n", err)
				os.Exit(1)
			}

			r3, err := parseRelay(relay3)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Error: invalid relay3: %v\n", err)
				os.Exit(1)
			}

			relays := []client.RelayInfo{r1, r2, r3}

			fmt.Fprintf(os.Stderr, "  Building circuit: %s -> %s -> %s\n", r1.Address, r2.Address, r3.Address)

			circuit, err = client.NewClientCircuit(ctx, gate, relays)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Error: %v\n", err)
				os.Exit(1)
			}
		}

		backend = circuit
		fmt.Fprintf(os.Stderr, "  Circuit: %s (3-hop garlic)\n", hex.EncodeToString(circuit.ID)[:8])
		fmt.Fprintf(os.Stderr, "  Mode: anonymous\n")
	}

	if rotateInterval > 0 {
		fmt.Fprintf(os.Stderr, "  Rotation: every %s\n", rotateInterval)
	}

	fmt.Fprintf(os.Stderr, "\n  Listening on %s\n\n", listen)

	// Create proxy handler
	handler := proxy.NewProxyHandler(proxy.HandlerConfig{
		Backend:        backend,
		Gate:           gate,
		Dir:            dir,
		RotateInterval: rotateInterval,
		Retries:        retries,
		DirectMode:     directMode,
		MultiResolver:  multiRes,
		BuildCircuit:   buildCircuitWithRetry,
	})

	// Start rotation goroutine if enabled
	if rotateInterval > 0 && !directMode {
		go handler.StartRotation(ctx)
	}

	// Start HTTP proxy server
	server := &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Run server in background so we can handle shutdown signals.
	serverErr := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
		close(serverErr)
	}()

	// shutdown closes all backend resources in a deterministic order.
	shutdown := func() {
		if b := handler.Backend(); b != nil {
			b.Close()
		}
		if gate != nil {
			gate.Close()
		}
		multiRes.Close()
		resolver.CloseSharedUDClient()
	}

	// Block until a signal is received or the server exits with an error.
	select {
	case err := <-serverErr:
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			shutdown()
			os.Exit(1)
		}
	case <-ctx.Done():
		fmt.Fprintf(os.Stderr, "\n  Shutting down...\n")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "  Error: graceful shutdown: %v\n", err)
		}
		shutdown()
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

	rootCmd.Flags().Bool("debug", false, "Enable debug logging")
	rootCmd.Flags().String("config-file", "", "YAML config file (CLI flags override)")
	rootCmd.Flags().String("relay1", "", "Entry relay (format: ip:port,pubkey_hex)")
	rootCmd.Flags().String("relay2", "", "Middle relay (format: ip:port,pubkey_hex)")
	rootCmd.Flags().String("relay3", "", "Exit relay (format: ip:port,pubkey_hex)")
	rootCmd.Flags().String("listen", "127.0.0.1:8080", "Proxy listen address (use 0.0.0.0:PORT for network access)")
	rootCmd.Flags().Bool("auto", false, "Auto-select relays from community directory")
	rootCmd.Flags().Bool("direct", false, "Direct connection mode (no anonymity, faster)")
	rootCmd.Flags().String("config", "", "TON network config file or URL (default: auto-download)")
	rootCmd.Flags().String("directory", directory.DefaultURL, "Relay directory URL")
	rootCmd.Flags().Int("retries", 3, "Max circuit build attempts in auto mode")
	rootCmd.Flags().String("rotate", "", "Circuit rotation interval (default 10m)")
	rootCmd.Flags().Lookup("rotate").NoOptDefVal = "10m"

	// Multi-chain resolver flags
	rootCmd.Flags().String("eth-rpc", "", "Ethereum RPC (default: public)")
	rootCmd.Flags().String("sol-rpc", "", "Solana RPC (default: public)")
	rootCmd.Flags().String("polygon-rpc", "", "Polygon RPC for Unstoppable Domains (default: public)")
	rootCmd.Flags().String("bnb-rpc", "", "BNB Chain RPC for Space ID (default: public)")
	rootCmd.Flags().String("btc-rpc", "", "Stacks API for BNS (default: api.mainnet.hiro.so)")
	// Auto-generated disable flags for all registered chains
	for _, cfg := range resolver.AllChains() {
		tld := strings.TrimPrefix(cfg.TLD, ".")
		rootCmd.Flags().Bool("no-"+tld, false, fmt.Sprintf("Disable %s domain resolution", cfg.TLD))
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
