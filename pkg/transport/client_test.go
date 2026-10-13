package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func readResponse(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestDirectIgnoresEnvironmentProxy(t *testing.T) {
	// A .invalid hostname would fail if the environment proxy were used.
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(name, "http://unused.invalid:8899")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "direct")
	}))
	defer target.Close()
	client, err := NewClient(Config{Timeout: time.Second, Family: "ipv4"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if client.Transport.(*requestTransport).base.Proxy != nil {
		t.Fatal("direct client must not install an environment proxy callback")
	}
	response, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	if body := readResponse(t, response); body != "direct" {
		t.Fatalf("body = %q", body)
	}
}

func TestHTTPProxyAuthRemoteDNSAndRedirect(t *testing.T) {
	const authorization = "Basic dXNlcjpzZWNyZXQ="
	var calls atomic.Int32
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Proxy-Authorization") != authorization {
			t.Errorf("incorrect proxy authorization")
			http.Error(w, "auth", http.StatusProxyAuthRequired)
			return
		}
		if !r.URL.IsAbs() {
			t.Errorf("HTTP proxy did not receive an absolute URL")
		}
		switch r.URL.Host {
		case "first.invalid":
			http.Redirect(w, r, "http://second.invalid/final", http.StatusFound)
		case "second.invalid":
			fmt.Fprint(w, "through-proxy")
		default:
			t.Errorf("unexpected target host %q", r.URL.Host)
		}
	}))
	defer proxyServer.Close()
	proxyURL := strings.Replace(proxyServer.URL, "http://", "http://user:secret@", 1)
	client, err := NewClient(Config{ProxyURL: proxyURL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	response, err := client.Get("http://first.invalid/start")
	if err != nil {
		t.Fatal(err)
	}
	if body := readResponse(t, response); body != "through-proxy" || calls.Load() != 2 {
		t.Fatalf("body = %q; proxy calls = %d", body, calls.Load())
	}
}

func TestHTTPSProxyConnectAuthDoesNotReachTarget(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credential reached the HTTPS target")
		}
		fmt.Fprint(w, "secure-target")
	}))
	defer target.Close()
	var connects atomic.Int32
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusBadRequest)
			return
		}
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:secret"))
		if r.Header.Get("Proxy-Authorization") != want {
			http.Error(w, "proxy auth", http.StatusProxyAuthRequired)
			return
		}
		connects.Add(1)
		upstream, err := net.DialTimeout("tcp", r.Host, time.Second)
		if err != nil {
			http.Error(w, "upstream", http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err = io.WriteString(rw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err = rw.Flush(); err != nil {
			return
		}
		go func() { _, _ = io.Copy(upstream, rw) }()
		_, _ = io.Copy(conn, upstream)
	}))
	defer proxyServer.Close()
	client, err := NewClient(Config{ProxyURL: strings.Replace(proxyServer.URL, "http://", "http://user:secret@", 1), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	// Trust only this local test server certificate; production TLS verification
	// remains enabled and has no InsecureSkipVerify override.
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	client.Transport.(*requestTransport).base.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	response, err := client.Get(target.URL + "/secure")
	if err != nil {
		t.Fatal(err)
	}
	if body := readResponse(t, response); body != "secure-target" || connects.Load() != 1 {
		t.Fatalf("body = %q; CONNECT calls = %d", body, connects.Load())
	}
}

func TestProxyFailureNeverFallsBackToDirect(t *testing.T) {
	var directRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		directRequests.Add(1)
		fmt.Fprint(w, "must-not-arrive")
	}))
	defer target.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	for _, scheme := range []string{"http", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			client, err := NewClient(Config{ProxyURL: scheme + "://user:secret@" + address, Timeout: 200 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			response, err := client.Get(target.URL)
			if response != nil {
				response.Body.Close()
			}
			if err == nil {
				t.Fatal("a failed proxy unexpectedly succeeded")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "user:") {
				t.Fatal("request error contains proxy credentials")
			}
		})
	}
	if directRequests.Load() != 0 {
		t.Fatalf("direct fallback requests = %d", directRequests.Load())
	}
}

func TestHTTPProxyConnectAuthenticationFailure(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Error("expected CONNECT authentication request")
		}
		w.Header().Set("Proxy-Authenticate", `Basic realm="local-test"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
	}))
	defer proxyServer.Close()
	client, err := NewClient(Config{ProxyURL: strings.Replace(proxyServer.URL, "http://", "http://user:secret@", 1), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	response, err := client.Get(target.URL)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || targetCalls.Load() != 0 {
		t.Fatal("CONNECT authentication failure must not reach the target")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("CONNECT authentication error exposed credentials")
	}
}

func TestHTTPProxyConnectCancellationClosesSocket(t *testing.T) {
	started := make(chan struct{})
	disconnected := make(chan struct{})
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusBadRequest)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		close(started)
		// Never send the CONNECT response; request cancellation must close TCP.
		_, _ = io.Copy(io.Discard, rw)
		close(disconnected)
	}))
	defer proxyServer.Close()
	client, err := NewClient(Config{ProxyURL: proxyServer.URL, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://unresolved.invalid", nil)
	result := make(chan error, 1)
	go func() {
		response, err := client.Do(request)
		if response != nil {
			response.Body.Close()
		}
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("CONNECT handshake did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("CONNECT cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CONNECT handshake ignored cancellation")
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("CONNECT handshake socket was not closed")
	}
}

func TestRedirectLimit(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		http.Redirect(w, r, "/"+strconv.Itoa(n+1), http.StatusFound)
	}))
	defer target.Close()
	client, err := NewClient(Config{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	response, err := client.Get(target.URL + "/0")
	if response != nil {
		response.Body.Close()
	}
	if err == nil || calls.Load() != 11 {
		t.Fatalf("expected ten followed redirects, calls=%d error=%v", calls.Load(), err)
	}
}

func TestRequestCancellation(t *testing.T) {
	started := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer target.Close()
	client, err := NewClient(Config{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	result := make(chan error, 1)
	go func() {
		response, err := client.Do(request)
		if response != nil {
			response.Body.Close()
		}
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not arrive")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("request was not canceled")
	}
}

func TestTimeoutIncludesBodyRead(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		fmt.Fprint(w, "partial")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer target.Close()
	client, err := NewClient(Config{Timeout: 150 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	response, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, err = io.ReadAll(response.Body)
	if err == nil {
		t.Fatal("incomplete body unexpectedly finished")
	}
	var timeoutError net.Error
	if !errors.As(err, &timeoutError) || !timeoutError.Timeout() {
		t.Fatalf("body read should time out, error=%v", err)
	}
}
