package transport

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func localSOCKS(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		handler(conn)
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("local SOCKS handler did not stop")
		}
	})
	return "socks5://" + listener.Addr().String()
}

func socksGreeting(t *testing.T, conn net.Conn, authenticated bool) bool {
	t.Helper()
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Errorf("SOCKS greeting: %v", err)
		return false
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		t.Errorf("SOCKS methods: %v", err)
		return false
	}
	method := byte(0)
	if authenticated {
		method = 2
	}
	if header[0] != 5 {
		t.Errorf("SOCKS version = %d", header[0])
		return false
	}
	found := false
	for _, available := range methods {
		found = found || available == method
	}
	if !found {
		t.Errorf("authentication method %d was not offered", method)
		return false
	}
	_, err := conn.Write([]byte{5, method})
	return err == nil
}

func readSOCKSAuth(conn net.Conn) (string, string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", "", err
	}
	if header[0] != 1 {
		return "", "", errors.New("incorrect SOCKS auth version")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return "", "", err
	}
	length := make([]byte, 1)
	if _, err := io.ReadFull(conn, length); err != nil {
		return "", "", err
	}
	password := make([]byte, int(length[0]))
	_, err := io.ReadFull(conn, password)
	return string(username), string(password), err
}

func TestSOCKS5UsesRemoteHostnameAndAuthentication(t *testing.T) {
	destination := make(chan string, 1)
	proxyURL := localSOCKS(t, func(conn net.Conn) {
		if !socksGreeting(t, conn, true) {
			return
		}
		username, password, err := readSOCKSAuth(conn)
		if err != nil || username != "user" || password != "secret" {
			t.Errorf("SOCKS proxy did not receive configured authentication")
			return
		}
		if _, err = conn.Write([]byte{1, 0}); err != nil {
			return
		}
		header := make([]byte, 5)
		if _, err = io.ReadFull(conn, header); err != nil {
			t.Error(err)
			return
		}
		if header[0] != 5 || header[1] != 1 || header[3] != 3 {
			t.Errorf("SOCKS must receive an unresolved target hostname, header=%v", header)
			return
		}
		host := make([]byte, int(header[4]))
		if _, err = io.ReadFull(conn, host); err != nil {
			t.Error(err)
			return
		}
		port := make([]byte, 2)
		if _, err = io.ReadFull(conn, port); err != nil {
			t.Error(err)
			return
		}
		destination <- fmt.Sprintf("%s:%d", host, binary.BigEndian.Uint16(port))
		if _, err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			t.Error(err)
			return
		}
		defer request.Body.Close()
		if request.Header.Get("Proxy-Authorization") != "" {
			t.Error("SOCKS credentials reached the HTTP target")
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nsocks")
	})
	proxyURL = strings.Replace(proxyURL, "socks5://", "socks5://user:secret@", 1)
	client, err := NewClient(Config{ProxyURL: proxyURL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	response, err := client.Get("http://remote-dns-only.invalid:8765/page")
	if err != nil {
		t.Fatal(err)
	}
	if body := readResponse(t, response); body != "socks" {
		t.Fatalf("body = %q", body)
	}
	select {
	case got := <-destination:
		if got != "remote-dns-only.invalid:8765" {
			t.Fatalf("destination = %q", got)
		}
	default:
		t.Fatal("SOCKS server did not observe the target hostname")
	}
}

func TestSOCKS5HandshakeCancellation(t *testing.T) {
	started := make(chan struct{})
	disconnected := make(chan struct{})
	proxyURL := localSOCKS(t, func(conn net.Conn) {
		if !socksGreeting(t, conn, false) {
			return
		}
		close(started)
		// Deliberately never answer CONNECT. Cancellation must close the socket.
		_, _ = io.Copy(io.Discard, conn)
		close(disconnected)
	})
	client, err := NewClient(Config{ProxyURL: proxyURL, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://cancel.invalid", nil)
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
		t.Fatal("SOCKS handshake did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("handshake cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS handshake ignored cancellation")
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("SOCKS handshake socket was not closed")
	}
}

func TestSOCKS5AuthenticationFailureNeverFallsBack(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()
	proxyURL := localSOCKS(t, func(conn net.Conn) {
		if !socksGreeting(t, conn, true) {
			return
		}
		_, _, err := readSOCKSAuth(conn)
		if err == nil {
			_, _ = conn.Write([]byte{1, 1})
		}
	})
	proxyURL = strings.Replace(proxyURL, "socks5://", "socks5://user:secret@", 1)
	client, err := NewClient(Config{ProxyURL: proxyURL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	response, err := client.Get(target.URL)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || targetCalls.Load() != 0 {
		t.Fatal("SOCKS authentication failure must not reach the target")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("SOCKS authentication failure exposed credentials")
	}
}
