//go:build e2e

package e2e_test

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

const proxyAddr = "127.0.0.1:18080"

var (
	proxyClient *http.Client
	proxyCmd    *exec.Cmd
	startupLog  string // captured proxy stdout during startup
)

// ---------------------------------------------------------------------------
// ProxyResult — rich result for diagnostics
// ---------------------------------------------------------------------------

// ProxyResult carries everything a test needs to diagnose failures.
type ProxyResult struct {
	Status      int
	Body        []byte
	Headers     http.Header
	Latency     time.Duration
	ContentType string
	Err         error
}

// proxyGet makes a GET through the proxy and returns diagnostics.
func proxyGet(rawURL string) ProxyResult {
	start := time.Now()

	resp, err := proxyClient.Get(rawURL)
	lat := time.Since(start)
	if err != nil {
		return ProxyResult{Err: err, Latency: lat}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return ProxyResult{
		Status:      resp.StatusCode,
		Body:        body,
		Headers:     resp.Header,
		Latency:     lat,
		ContentType: resp.Header.Get("Content-Type"),
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "... [truncated]"
}

// assertHTML checks that body looks like a valid HTML page.
func assertHTML(t *testing.T, body []byte, label string) {
	t.Helper()
	s := strings.ToLower(string(body))
	if !strings.Contains(s, "<html") {
		t.Fatalf("FAIL [%s]: body does not contain <html tag\n"+
			"  Body length: %d bytes\n"+
			"  First 500 bytes: %s",
			label, len(body), truncate(body, 500))
	}
}

// requireProxy skips if the shared proxy client was not initialised.
func requireProxy(t *testing.T) {
	t.Helper()
	if proxyClient == nil {
		t.Skip("proxy client not available — TestMain setup failed")
	}
}

// percentile returns the p-th percentile from a sorted slice of durations.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// ---------------------------------------------------------------------------
// TestMain — build binary, start proxy, capture startup logs
// ---------------------------------------------------------------------------

func TestMain(m *testing.M) {
	// Build the binary from the project root.
	build := exec.Command("go", "build", "-o", "/tmp/tonnet-proxy-e2e", "./cmd/...")
	build.Dir = findProjectRoot()
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "BUILD FAILED: %s\n%s\n", err, out)
		os.Exit(1)
	}

	// Start the proxy, capturing stdout into a buffer.
	proxyCmd = exec.Command("/tmp/tonnet-proxy-e2e", "--auto", "--listen", proxyAddr)

	var stdoutBuf bytes.Buffer
	// Tee stdout so we can see it live AND capture it.
	stdoutPipe, err := proxyCmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create stdout pipe: %s\n", err)
		os.Exit(1)
	}
	proxyCmd.Stderr = os.Stderr

	if err := proxyCmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start proxy: %s\n", err)
		os.Exit(1)
	}

	// Read stdout in background, tee to os.Stdout and buffer.
	stdoutDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		buf := make([]byte, 4096)
		for {
			n, err := stdoutPipe.Read(buf)
			if n > 0 {
				os.Stdout.Write(buf[:n])
				stdoutBuf.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// Wait for the proxy to be listening (circuit build can take a while).
	ready := waitForPort(proxyAddr, 120*time.Second)
	if !ready {
		fmt.Fprintln(os.Stderr, "STARTUP TIMEOUT: proxy did not start within 120s")
		fmt.Fprintf(os.Stderr, "Captured stdout:\n%s\n", stdoutBuf.String())
		proxyCmd.Process.Kill()
		proxyCmd.Wait()
		os.Exit(1)
	}

	// Snapshot startup logs.
	startupLog = stdoutBuf.String()

	// Configure an HTTP client that routes through the proxy.
	// NOTE: we build the client first, then do a warm-up request below.
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	proxyClient = &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			MaxIdleConnsPerHost: 10,
		},
		Timeout: 60 * time.Second,
	}

	// Warm-up: the first request through a fresh circuit can take 30s+ due to
	// ADNL stream negotiation cold-start. Fire one throwaway request so that
	// actual tests start on a warm circuit.
	fmt.Println("Warming up circuit (first request may be slow)...")
	warmupStart := time.Now()
	warmResp, warmErr := proxyClient.Get("http://foundation.ton")
	if warmErr == nil {
		io.ReadAll(warmResp.Body)
		warmResp.Body.Close()
		fmt.Printf("Warm-up done in %.1fs (HTTP %d)\n\n", time.Since(warmupStart).Seconds(), warmResp.StatusCode)
	} else {
		fmt.Printf("Warm-up request failed (%.1fs): %v — tests may still work\n\n", time.Since(warmupStart).Seconds(), warmErr)
	}

	// Run all tests.
	code := m.Run()

	// Graceful shutdown of the shared proxy instance.
	proxyCmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- proxyCmd.Wait() }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		proxyCmd.Process.Kill()
	}

	os.Exit(code)
}

func findProjectRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(dir + "/go.mod"); err == nil {
			return dir
		}
		parent := dir[:strings.LastIndex(dir, "/")]
		if parent == dir {
			d, _ := os.Getwd()
			return d
		}
		dir = parent
	}
}

func waitForPort(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

// ---------------------------------------------------------------------------
// 1. TestE2E_CircuitBuild
// ---------------------------------------------------------------------------

func TestE2E_CircuitBuild(t *testing.T) {
	requireProxy(t)

	log := startupLog

	// Parse relay lines: "  Entry:  NAME (ADDRESS)"
	reEntry := regexp.MustCompile(`Entry:\s+(\S+)\s+\(([^)]+)\)`)
	reMiddle := regexp.MustCompile(`Middle:\s+(\S+)\s+\(([^)]+)\)`)
	reExit := regexp.MustCompile(`Exit:\s+(\S+)\s+\(([^)]+)\)`)
	reCircuitID := regexp.MustCompile(`Circuit ready \[([0-9a-f]+)\]`)
	reRelayCount := regexp.MustCompile(`(\d+) found`)

	// Step 1: relay discovery
	relayMatch := reRelayCount.FindStringSubmatch(log)
	if relayMatch == nil {
		t.Fatalf("FAIL: relay discovery — no 'N found' line in startup log\n"+
			"  Startup log:\n%s", truncate([]byte(log), 2000))
	}
	t.Logf("  Discovery: %s relays found", relayMatch[1])

	// Step 2: entry relay
	entryMatch := reEntry.FindStringSubmatch(log)
	if entryMatch == nil {
		t.Fatalf("FAIL: entry relay — no Entry line in startup log\n"+
			"  Startup log:\n%s", truncate([]byte(log), 2000))
	}
	entryName, entryAddr := entryMatch[1], entryMatch[2]
	t.Logf("  Entry:  %s (%s)", entryName, entryAddr)

	// Step 3: middle relay
	middleMatch := reMiddle.FindStringSubmatch(log)
	if middleMatch == nil {
		t.Fatalf("FAIL: middle relay — no Middle line in startup log\n"+
			"  Discovery OK, entry=%s\n"+
			"  Startup log:\n%s", entryName, truncate([]byte(log), 2000))
	}
	middleName, middleAddr := middleMatch[1], middleMatch[2]
	t.Logf("  Middle: %s (%s)", middleName, middleAddr)

	// Step 4: exit relay
	exitMatch := reExit.FindStringSubmatch(log)
	if exitMatch == nil {
		t.Fatalf("FAIL: exit relay — no Exit line in startup log\n"+
			"  Discovery OK, entry=%s, middle=%s\n"+
			"  Startup log:\n%s", entryName, middleName, truncate([]byte(log), 2000))
	}
	exitName, exitAddr := exitMatch[1], exitMatch[2]
	t.Logf("  Exit:   %s (%s)", exitName, exitAddr)

	// Assert all 3 relays are different
	addrs := map[string]string{
		entryAddr:  "entry",
		middleAddr: "middle",
		exitAddr:   "exit",
	}
	if len(addrs) != 3 {
		t.Fatalf("FAIL: relays are not all distinct\n"+
			"  Entry:  %s (%s)\n"+
			"  Middle: %s (%s)\n"+
			"  Exit:   %s (%s)",
			entryName, entryAddr, middleName, middleAddr, exitName, exitAddr)
	}

	// Step 5: circuit ID
	circuitMatch := reCircuitID.FindStringSubmatch(log)
	if circuitMatch == nil {
		t.Fatalf("FAIL: circuit ID — no 'Circuit ready [...]' in startup log\n"+
			"  Relays selected OK: entry=%s, middle=%s, exit=%s\n"+
			"  Startup log:\n%s",
			entryName, middleName, exitName, truncate([]byte(log), 2000))
	}
	circuitID := circuitMatch[1]
	if len(circuitID) != 8 {
		t.Fatalf("FAIL: circuit ID length — expected 8 hex chars, got %d (%q)", len(circuitID), circuitID)
	}

	t.Logf("PASS: 3-hop circuit built — entry=%s, middle=%s, exit=%s, circuit=%s",
		entryName, middleName, exitName, circuitID)
}

// ---------------------------------------------------------------------------
// 2. TestE2E_BasicPageLoad
// ---------------------------------------------------------------------------

func TestE2E_BasicPageLoad(t *testing.T) {
	requireProxy(t)

	r := proxyGet("http://foundation.ton")
	if r.Err != nil {
		t.Fatalf("FAIL: GET foundation.ton — transport error\n"+
			"  Error: %v\n"+
			"  Latency: %dms",
			r.Err, r.Latency.Milliseconds())
	}

	if r.Status != 200 {
		t.Fatalf("FAIL: foundation.ton returned HTTP %d (expected 200)\n"+
			"  Response headers: %v\n"+
			"  Body (first 500 bytes): %s\n"+
			"  Latency: %dms",
			r.Status, r.Headers, truncate(r.Body, 500), r.Latency.Milliseconds())
	}

	if len(r.Body) < 1024 {
		t.Fatalf("FAIL: foundation.ton body too small — %d bytes (expected >1KB)\n"+
			"  Content-Type: %s\n"+
			"  Body: %s",
			len(r.Body), r.ContentType, truncate(r.Body, 500))
	}

	assertHTML(t, r.Body, "foundation.ton")

	t.Logf("PASS: foundation.ton loaded in %dms, %d bytes, content-type=%s",
		r.Latency.Milliseconds(), len(r.Body), r.ContentType)
}

// ---------------------------------------------------------------------------
// 3. TestE2E_MultiSiteAccess
// ---------------------------------------------------------------------------

func TestE2E_MultiSiteAccess(t *testing.T) {
	requireProxy(t)

	sites := []struct {
		url   string
		label string
	}{
		{"http://foundation.ton", "foundation.ton"},
		{"http://piracy.ton", "piracy.ton"},
	}

	var results []ProxyResult
	for _, site := range sites {
		r := proxyGet(site.url)
		results = append(results, r)

		if r.Err != nil {
			t.Fatalf("FAIL: %s — transport error\n"+
				"  Error: %v\n"+
				"  Latency: %dms\n"+
				"  Other sites status: %s",
				site.label, r.Err, r.Latency.Milliseconds(), multiSiteSummary(sites, results))
		}

		if r.Status != 200 {
			t.Fatalf("FAIL: %s returned HTTP %d\n"+
				"  Headers: %v\n"+
				"  Body (first 500 bytes): %s\n"+
				"  Latency: %dms\n"+
				"  Other sites status: %s",
				site.label, r.Status, r.Headers, truncate(r.Body, 500),
				r.Latency.Milliseconds(), multiSiteSummary(sites, results))
		}

		assertHTML(t, r.Body, site.label)
	}

	t.Logf("PASS: multi-site access through same circuit")
	for i, site := range sites {
		t.Logf("  %s: %dms, %d bytes",
			site.label, results[i].Latency.Milliseconds(), len(results[i].Body))
	}
}

func multiSiteSummary(sites []struct {
	url   string
	label string
}, results []ProxyResult) string {
	var parts []string
	for i, r := range results {
		if r.Err != nil {
			parts = append(parts, fmt.Sprintf("%s=err(%v)", sites[i].label, r.Err))
		} else {
			parts = append(parts, fmt.Sprintf("%s=%d", sites[i].label, r.Status))
		}
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// 4. TestE2E_ConcurrentRequests
// ---------------------------------------------------------------------------

func TestE2E_ConcurrentRequests(t *testing.T) {
	requireProxy(t)

	const n = 5
	results := make([]ProxyResult, n)
	var wg sync.WaitGroup

	// Each goroutine gets its own http.Client to avoid shared transport
	// connection pool contention (which can cause artificial timeouts).
	makeClient := func() *http.Client {
		proxyURL, _ := url.Parse("http://" + proxyAddr)
		return &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
			Timeout:   60 * time.Second,
		}
	}

	totalStart := time.Now()

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c := makeClient()
			start := time.Now()
			resp, err := c.Get("http://foundation.ton")
			lat := time.Since(start)
			if err != nil {
				results[idx] = ProxyResult{Err: err, Latency: lat}
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			results[idx] = ProxyResult{
				Status:      resp.StatusCode,
				Body:        body,
				Headers:     resp.Header,
				Latency:     lat,
				ContentType: resp.Header.Get("Content-Type"),
			}
		}(i)
	}

	wg.Wait()
	totalDuration := time.Since(totalStart)

	// Collect failures and build report.
	var failures []string
	var latencies []time.Duration
	for i, r := range results {
		if r.Err != nil {
			failures = append(failures, fmt.Sprintf("  request %d: error=%v, latency=%dms", i, r.Err, r.Latency.Milliseconds()))
		} else if r.Status != 200 {
			failures = append(failures, fmt.Sprintf("  request %d: HTTP %d, latency=%dms, body=%s",
				i, r.Status, r.Latency.Milliseconds(), truncate(r.Body, 200)))
		} else {
			latencies = append(latencies, r.Latency)
		}
	}

	// Tolerate up to 1 transient failure — TON liteservers can temporarily
	// return 502 when a block is out of sync. This is a network issue,
	// not a proxy bug. We care that the proxy handles concurrent streams,
	// not that every liteserver is 100% available.
	const maxAllowedFailures = 1
	if len(failures) > maxAllowedFailures {
		t.Fatalf("FAIL: %d/%d concurrent requests failed (max allowed: %d)\n"+
			"  Total time: %dms\n"+
			"Failures:\n%s",
			len(failures), n, maxAllowedFailures, totalDuration.Milliseconds(), strings.Join(failures, "\n"))
	}
	if len(failures) > 0 {
		t.Logf("  WARNING: %d transient failure(s) (within tolerance):\n%s",
			len(failures), strings.Join(failures, "\n"))
	}

	// Timing histogram.
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	t.Logf("PASS: %d concurrent requests completed in %dms total", n, totalDuration.Milliseconds())
	for i, lat := range latencies {
		t.Logf("  request %d: %dms", i, lat.Milliseconds())
	}
	t.Logf("  min=%dms max=%dms", latencies[0].Milliseconds(), latencies[len(latencies)-1].Milliseconds())
}

// ---------------------------------------------------------------------------
// 5. TestE2E_ChunkReassembly
// ---------------------------------------------------------------------------

func TestE2E_ChunkReassembly(t *testing.T) {
	requireProxy(t)

	r := proxyGet("http://foundation.ton")
	if r.Err != nil {
		t.Fatalf("FAIL: chunk reassembly — transport error\n"+
			"  Error: %v", r.Err)
	}

	if r.Status != 200 {
		t.Fatalf("FAIL: chunk reassembly — HTTP %d\n"+
			"  Headers: %v\n"+
			"  Body (first 500 bytes): %s",
			r.Status, r.Headers, truncate(r.Body, 500))
	}

	const minExpected = 8 * 1024 // 8KB minimum to prove chunk reassembly
	if len(r.Body) < minExpected {
		t.Fatalf("FAIL: response too small for chunk reassembly test\n"+
			"  Received: %d bytes (need >%d)\n"+
			"  This means the page is too small to trigger chunking\n"+
			"  Body (first 500 bytes): %s",
			len(r.Body), minExpected, truncate(r.Body, 500))
	}

	// Check that the HTML is complete (not truncated mid-stream).
	bodyLower := strings.ToLower(string(r.Body))
	hasClosingHTML := strings.Contains(bodyLower, "</html>")
	if !hasClosingHTML {
		// Find last 200 bytes to show where truncation happened.
		tail := r.Body
		if len(tail) > 200 {
			tail = tail[len(tail)-200:]
		}
		t.Fatalf("FAIL: response appears truncated — no closing </html> tag\n"+
			"  Total bytes received: %d\n"+
			"  Last 200 bytes: %s\n"+
			"  Content-Type: %s",
			len(r.Body), string(tail), r.ContentType)
	}

	estimatedChunks := (len(r.Body) + 8191) / 8192 // 8KB chunk size
	t.Logf("PASS: chunk reassembly verified — %d bytes, ~%d chunks, complete HTML, %dms",
		len(r.Body), estimatedChunks, r.Latency.Milliseconds())
}

// ---------------------------------------------------------------------------
// 6. TestE2E_CircuitLatency
// ---------------------------------------------------------------------------

func TestE2E_CircuitLatency(t *testing.T) {
	requireProxy(t)

	const n = 10
	latencies := make([]time.Duration, 0, n)

	var transientFailures int
	for i := 0; i < n; i++ {
		r := proxyGet("http://foundation.ton")
		if r.Err != nil || r.Status != 200 {
			// Tolerate transient liteserver failures (block out of sync, etc.)
			transientFailures++
			if r.Err != nil {
				t.Logf("  request %2d: SKIP (transport error: %v)", i, r.Err)
			} else {
				t.Logf("  request %2d: SKIP (HTTP %d — transient)", i, r.Status)
			}
			if transientFailures > 2 {
				t.Fatalf("FAIL: too many transient failures (%d/%d) — network may be down", transientFailures, i+1)
			}
			continue
		}
		latencies = append(latencies, r.Latency)
		t.Logf("  request %2d: %5dms (%d bytes)", i, r.Latency.Milliseconds(), len(r.Body))
	}

	if len(latencies) < 5 {
		t.Fatalf("FAIL: only %d/%d requests succeeded — not enough data for benchmark", len(latencies), n)
	}

	// Compute stats.
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	var total time.Duration
	for _, l := range latencies {
		total += l
	}
	avg := total / time.Duration(n)

	minLat := latencies[0]
	maxLat := latencies[len(latencies)-1]
	p95 := percentile(latencies, 95)

	// Sanity: avg should be under 5s (very generous).
	if avg > 5*time.Second {
		t.Fatalf("FAIL: average latency too high — %dms (threshold 5000ms)\n"+
			"  min=%dms max=%dms p95=%dms",
			avg.Milliseconds(), minLat.Milliseconds(), maxLat.Milliseconds(), p95.Milliseconds())
	}

	t.Logf("PASS: latency benchmark (n=%d)", n)
	t.Logf("  min=%dms  avg=%dms  p95=%dms  max=%dms",
		minLat.Milliseconds(), avg.Milliseconds(), p95.Milliseconds(), maxLat.Milliseconds())
}

// ---------------------------------------------------------------------------
// 7. TestE2E_GracefulShutdown
// ---------------------------------------------------------------------------

func TestE2E_GracefulShutdown(t *testing.T) {
	// This test starts its OWN proxy instance — independent of the shared one.

	binPath := "/tmp/tonnet-proxy-e2e"
	shutdownAddr := "127.0.0.1:18081"

	cmd := exec.Command(binPath, "--auto", "--listen", shutdownAddr)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	cmd.Stdout = os.Stdout

	if err := cmd.Start(); err != nil {
		t.Fatalf("FAIL: could not start second proxy instance: %v", err)
	}

	// Wait for it to be listening.
	if !waitForPort(shutdownAddr, 120*time.Second) {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("FAIL: second proxy did not start within 120s\n"+
			"  stderr: %s", stderrBuf.String())
	}

	// Send one request to prove it works.
	shutdownProxyURL, _ := url.Parse("http://" + shutdownAddr)
	shutdownClient := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(shutdownProxyURL)},
		Timeout:   60 * time.Second,
	}
	resp, err := shutdownClient.Get("http://foundation.ton")
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("FAIL: pre-shutdown request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("FAIL: pre-shutdown request returned HTTP %d", resp.StatusCode)
	}

	// Send SIGTERM.
	t.Log("  Sending SIGTERM...")
	cmd.Process.Signal(syscall.SIGTERM)

	// Wait for exit with 15s timeout.
	exitCh := make(chan error, 1)
	go func() { exitCh <- cmd.Wait() }()

	select {
	case exitErr := <-exitCh:
		if exitErr != nil {
			// On Unix, SIGTERM results in a non-zero exit in Go by default,
			// but the proxy traps it for graceful shutdown and should exit 0.
			if exitStatus, ok := exitErr.(*exec.ExitError); ok {
				code := exitStatus.ExitCode()
				if code != 0 {
					t.Fatalf("FAIL: proxy exited with code %d after SIGTERM\n"+
						"  stderr: %s", code, stderrBuf.String())
				}
			} else {
				t.Fatalf("FAIL: proxy wait error: %v\n  stderr: %s", exitErr, stderrBuf.String())
			}
		}
		t.Logf("PASS: graceful shutdown — proxy exited cleanly after SIGTERM")

	case <-time.After(15 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("FAIL: proxy did not exit within 15s of SIGTERM\n"+
			"  stderr: %s", stderrBuf.String())
	}
}

// ---------------------------------------------------------------------------
// 8. TestE2E_DNSResolution
// ---------------------------------------------------------------------------

func TestE2E_DNSResolution(t *testing.T) {
	requireProxy(t)

	r := proxyGet("http://foundation.ton")

	if r.Err != nil {
		errStr := r.Err.Error()
		switch {
		case strings.Contains(errStr, "dns") || strings.Contains(errStr, "DNS") ||
			strings.Contains(errStr, "no such host") || strings.Contains(errStr, "resolve"):
			t.Fatalf("FAIL: DNS resolution failure\n"+
				"  Error: %v\n"+
				"  Diagnosis: .ton domain could not be resolved via TON DNS", r.Err)
		case strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "dial"):
			t.Fatalf("FAIL: connection failure (DNS may have resolved but host unreachable)\n"+
				"  Error: %v", r.Err)
		default:
			t.Fatalf("FAIL: request error during DNS test\n"+
				"  Error: %v", r.Err)
		}
	}

	if r.Status == 502 {
		t.Fatalf("FAIL: DNS resolution likely failed — got HTTP 502 (Bad Gateway)\n"+
			"  This typically means the proxy could not resolve or connect to the .ton domain\n"+
			"  Body: %s", truncate(r.Body, 500))
	}

	if r.Status != 200 {
		t.Fatalf("FAIL: unexpected status %d\n"+
			"  Headers: %v\n"+
			"  Body: %s",
			r.Status, r.Headers, truncate(r.Body, 500))
	}

	// The key proof is that we got a real page — DNS resolved to a real server.
	assertHTML(t, r.Body, "dns-resolution")

	serverHeader := r.Headers.Get("Server")
	t.Logf("PASS: DNS resolution verified — foundation.ton resolved and served HTML")
	t.Logf("  Server header: %q", serverHeader)
	t.Logf("  Content-Type: %s", r.ContentType)
	t.Logf("  Body size: %d bytes", len(r.Body))
}

// ---------------------------------------------------------------------------
// 9. TestE2E_ResponseIntegrity
// ---------------------------------------------------------------------------

func TestE2E_ResponseIntegrity(t *testing.T) {
	requireProxy(t)

	// Fetch the same page twice.
	r1 := proxyGet("http://foundation.ton")
	if r1.Err != nil {
		t.Fatalf("FAIL: first request error: %v", r1.Err)
	}
	if r1.Status != 200 {
		t.Fatalf("FAIL: first request returned HTTP %d", r1.Status)
	}

	r2 := proxyGet("http://foundation.ton")
	if r2.Err != nil {
		t.Fatalf("FAIL: second request error: %v", r2.Err)
	}
	if r2.Status != 200 {
		t.Fatalf("FAIL: second request returned HTTP %d", r2.Status)
	}

	// Assert byte-identical responses.
	if !bytes.Equal(r1.Body, r2.Body) {
		// Find where they diverge.
		minLen := len(r1.Body)
		if len(r2.Body) < minLen {
			minLen = len(r2.Body)
		}
		divergeAt := minLen // assume they diverge at length boundary
		for i := 0; i < minLen; i++ {
			if r1.Body[i] != r2.Body[i] {
				divergeAt = i
				break
			}
		}

		ctx1Start := divergeAt - 20
		if ctx1Start < 0 {
			ctx1Start = 0
		}
		ctx1End := divergeAt + 20
		if ctx1End > len(r1.Body) {
			ctx1End = len(r1.Body)
		}
		ctx2End := divergeAt + 20
		if ctx2End > len(r2.Body) {
			ctx2End = len(r2.Body)
		}

		t.Fatalf("FAIL: responses differ\n"+
			"  Response 1: %d bytes\n"+
			"  Response 2: %d bytes\n"+
			"  Diverge at byte %d\n"+
			"  R1 context: %q\n"+
			"  R2 context: %q",
			len(r1.Body), len(r2.Body), divergeAt,
			string(r1.Body[ctx1Start:ctx1End]),
			string(r2.Body[ctx1Start:ctx2End]))
	}

	// Assert Content-Length matches actual body length.
	clHeader := r1.Headers.Get("Content-Length")
	if clHeader != "" {
		var cl int
		fmt.Sscanf(clHeader, "%d", &cl)
		if cl != len(r1.Body) {
			t.Fatalf("FAIL: Content-Length mismatch\n"+
				"  Header says: %d\n"+
				"  Actual body: %d bytes",
				cl, len(r1.Body))
		}
		t.Logf("  Content-Length: %s (matches body)", clHeader)
	} else {
		t.Logf("  Content-Length: not present (chunked or unset)")
	}

	t.Logf("PASS: response integrity — 2 fetches byte-identical, %d bytes each", len(r1.Body))
}

// ---------------------------------------------------------------------------
// 10. TestE2E_ProxyAsHTTPClient
// ---------------------------------------------------------------------------

func TestE2E_ProxyAsHTTPClient(t *testing.T) {
	requireProxy(t)

	// Build a request with custom headers.
	req, err := http.NewRequest("GET", "http://foundation.ton", nil)
	if err != nil {
		t.Fatalf("FAIL: could not create request: %v", err)
	}
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", "TonnetE2ETest/1.0")
	req.Header.Set("X-Custom-Test", "e2e-header-forwarding")

	start := time.Now()
	resp, err := proxyClient.Do(req)
	latency := time.Since(start)

	if err != nil {
		t.Fatalf("FAIL: request with custom headers failed\n"+
			"  Error: %v\n"+
			"  Latency: %dms",
			err, latency.Milliseconds())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("FAIL: custom-header request returned HTTP %d\n"+
			"  Headers: %v\n"+
			"  Body: %s",
			resp.StatusCode, resp.Header, truncate(body, 500))
	}

	// The proxy is transparent if we get a valid HTML page back.
	// We cannot inspect what the backend received, but we can verify the
	// proxy didn't reject or mangle the request.
	assertHTML(t, body, "proxy-as-http-client")

	// Verify the proxy doesn't inject blocking headers that break the response.
	if ct := resp.Header.Get("Content-Type"); ct == "" {
		t.Fatalf("FAIL: Content-Type header missing from proxied response\n" +
			"  The proxy may be stripping essential response headers")
	}

	t.Logf("PASS: proxy works as transparent HTTP client")
	t.Logf("  Custom headers sent: Accept=text/html, User-Agent=TonnetE2ETest/1.0, X-Custom-Test=e2e-header-forwarding")
	t.Logf("  Response: HTTP %d, %d bytes, %dms", resp.StatusCode, len(body), latency.Milliseconds())
}
