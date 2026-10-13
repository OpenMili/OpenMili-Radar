// Package transport keeps all requests on the explicitly selected access path.
package transport

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

func parseProxy(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		// url.Parse errors may contain the raw credentials. Never return them.
		return nil, errors.New("代理地址格式无效，请使用 http://地址:端口 或 socks5://地址:端口")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "http", "socks5", "socks5h":
	default:
		return nil, errors.New("代理协议不支持，请使用 http、socks5 或 socks5h")
	}
	if u.Opaque != "" || u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("代理地址只能包含协议、认证信息、主机和端口")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" || strings.IndexFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return nil, errors.New("代理必须提供有效主机和端口；IPv6 地址需用方括号包围")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, errors.New("代理端口必须介于 1 到 65535")
	}
	if u.User != nil {
		username := u.User.Username()
		password, _ := u.User.Password()
		if username == "" {
			return nil, errors.New("代理认证用户名不能为空")
		}
		if u.Scheme != "http" && (len(username) > 255 || len(password) > 255) {
			return nil, errors.New("SOCKS5 用户名或口令不能超过 255 字节")
		}
	}
	u.Path = ""
	u.RawPath = ""
	return u, nil
}

// DescribeProxy describes the access path without exposing proxy credentials.
// An empty proxy URL means direct access; environment proxies are never used.
func DescribeProxy(raw string) (string, error) {
	u, err := parseProxy(raw)
	if err != nil {
		return "", err
	}
	if u == nil {
		return "直连（本机 DNS）", nil
	}
	protocol := "HTTP"
	if u.Scheme == "socks5" || u.Scheme == "socks5h" {
		protocol = "SOCKS5"
	}
	description := fmt.Sprintf("前置代理（%s / %s；目标域名由代理解析）", protocol, u.Host)
	if u.User != nil {
		description += " [已配置认证]"
	}
	return description, nil
}
