package transport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const defaultTimeout = 5 * time.Second

// Config selects one request path. Family is auto, ipv4 or ipv6 (direct only).
// Timeout limits a complete request, including redirects and body reads.
type Config struct {
	ProxyURL string
	Timeout  time.Duration
	Family   string
}

// NewClient constructs an independent client that never inherits environment
// proxies and never falls back to direct access when an explicit proxy fails.
// SOCKS5 and HTTP proxies receive target hostnames for remote resolution.
func NewClient(config Config) (*http.Client, error) {
	family := strings.ToLower(strings.TrimSpace(config.Family))
	if family == "" {
		family = "auto"
	}
	if family != "auto" && family != "ipv4" && family != "ipv6" {
		return nil, errors.New("地址族必须为 auto、ipv4 或 ipv6")
	}
	if config.Timeout < 0 {
		return nil, errors.New("请求超时不能为负数")
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	proxyURL, err := parseProxy(config.ProxyURL)
	if err != nil {
		return nil, err
	}
	if proxyURL != nil && family != "auto" {
		return nil, errors.New("代理模式无法保证目标连接的 IPv4/IPv6 地址族，请使用 auto")
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	dial := dialer.DialContext
	tr := &http.Transport{
		// A nil Proxy deliberately means direct access, not ProxyFromEnvironment.
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   4,
		MaxConnsPerHost:       4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
	}
	if proxyURL == nil && family != "auto" {
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			if network == "tcp" {
				if family == "ipv4" {
					network = "tcp4"
				} else {
					network = "tcp6"
				}
			}
			return dialer.DialContext(ctx, network, address)
		}
	}
	if proxyURL != nil {
		if proxyURL.Scheme == "http" {
			// net/http sends Basic proxy authentication on forward requests and
			// CONNECT. It does not send it through the tunnel to the destination.
			tr.Proxy = http.ProxyURL(proxyURL)
		} else {
			var auth *proxy.Auth
			if proxyURL.User != nil {
				password, _ := proxyURL.User.Password()
				auth = &proxy.Auth{User: proxyURL.User.Username(), Password: password}
			}
			socksDialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, dialer)
			if err != nil {
				return nil, errors.New("无法初始化 SOCKS5 代理")
			}
			contextDialer, ok := socksDialer.(proxy.ContextDialer)
			if !ok {
				return nil, errors.New("SOCKS5 代理实现不支持请求取消")
			}
			dial = contextDialer.DialContext
		}
	}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		// Transport intentionally detaches the request cancellation while dialing
		// for connection reuse. Reattach it for bounded SOCKS/CONNECT handshakes.
		path, _ := ctx.Value(requestPathKey{}).(*requestPath)
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		if path != nil {
			if err := path.ctx.Err(); err != nil {
				return nil, err
			}
			stop := context.AfterFunc(path.ctx, cancel)
			defer stop()
		}
		conn, err := dial(dialCtx, network, address)
		if err != nil {
			return nil, err
		}
		if path != nil {
			path.watch(conn)
		}
		return conn, nil
	}
	return &http.Client{
		Transport: &requestTransport{base: tr},
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) > 10 {
				return errors.New("重定向次数超过 10")
			}
			return nil
		},
	}, nil
}

type requestPathKey struct{}

type requestPath struct {
	ctx      context.Context
	mu       sync.Mutex
	finished bool
	stops    []func() bool
}

func (p *requestPath) watch(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		if p.ctx.Err() != nil {
			_ = conn.Close()
		}
		return
	}
	p.stops = append(p.stops, context.AfterFunc(p.ctx, func() { _ = conn.Close() }))
}

func (p *requestPath) release() {
	p.mu.Lock()
	p.finished = true
	stops := p.stops
	p.stops = nil
	p.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
}

type requestTransport struct {
	base *http.Transport
}

func (t *requestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	path := &requestPath{ctx: request.Context()}
	defer path.release()
	ctx := context.WithValue(request.Context(), requestPathKey{}, path)
	return t.base.RoundTrip(request.WithContext(ctx))
}

func (t *requestTransport) CloseIdleConnections() {
	t.base.CloseIdleConnections()
}
