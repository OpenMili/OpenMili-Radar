package transport

import (
	"strings"
	"testing"
	"time"
)

func TestDescribeProxyRedactsCredentials(t *testing.T) {
	for _, raw := range []string{
		"http://private-user:private-password@127.0.0.1:8080",
		"socks5://private-user:private-password@[::1]:10808",
		"socks5h://private-user:private-password@localhost:10808",
	} {
		description, err := DescribeProxy(raw)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(description, "private-user") || strings.Contains(description, "private-password") {
			t.Fatal("description contains credentials")
		}
		if !strings.Contains(description, "已配置认证") || !strings.Contains(description, "代理解析") {
			t.Fatalf("description is incomplete: %q", description)
		}
	}
	description, err := DescribeProxy("")
	if err != nil || !strings.Contains(description, "直连") {
		t.Fatalf("direct description = %q, error=%v", description, err)
	}
}

func TestInvalidConfiguration(t *testing.T) {
	for _, config := range []Config{
		{Family: "unknown"},
		{Timeout: -time.Second},
		{ProxyURL: "127.0.0.1:10808"},
		{ProxyURL: "http://127.0.0.1"},
		{ProxyURL: "https://127.0.0.1:8080"},
		{ProxyURL: "socks5://127.0.0.1:0"},
		{ProxyURL: "socks5://127.0.0.1:65536"},
		{ProxyURL: "http://127.0.0.1:8080/path"},
		{ProxyURL: "http://127.0.0.1:8080?key=private"},
		{ProxyURL: "http://:password@127.0.0.1:8080"},
		{ProxyURL: "http://127.0.0.1:8080", Family: "ipv4"},
		{ProxyURL: "socks5://127.0.0.1:10808", Family: "ipv6"},
	} {
		if _, err := NewClient(config); err == nil {
			t.Fatalf("configuration should be rejected: %+v", config)
		}
	}
	for _, raw := range []string{"http://secret-user:secret-password@%zz:1234", "http://secret-user:secret-password@localhost:invalid"} {
		_, err := DescribeProxy(raw)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid proxy error must not expose raw input")
		}
	}
}
