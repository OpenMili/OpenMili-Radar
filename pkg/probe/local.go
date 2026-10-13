package probe

// Local probes cover checklist items that describe the machine or its
// ordinary network path. They intentionally use portable Go APIs first and
// only use short, read-only OS commands as a fallback. A probe never changes
// system state, opens a listening socket, or scans another host.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/OpenMili/OpenMili-Radar/pkg/catalog"
)

// RunLocal executes one machine/protocol checklist item. A local probe is
// marked Configured because it has an implementation even when the current
// OS cannot expose the requested counter; in that case the evidence says why.
func RunLocal(ctx context.Context, p catalog.Probe) Result {
	started := time.Now()
	r := fromProbe(p, StatusUnknown, "")
	r.Started = true
	r.Configured = true
	r.Status, r.Evidence = localCheck(ctx, p)
	if r.Status != StatusUntested {
		r.Reason = ""
	}
	return finish(r, started)
}

func localCheck(ctx context.Context, p catalog.Probe) (Status, string) {
	key := strings.ToLower(strings.TrimSpace(p.Check + " " + p.ID + " " + p.Name))
	switch {
	case hasAny(key, "utc", "system-time", "系统时间", "协调世界时", "北京时间"):
		return StatusOK, "本机 UTC " + time.Now().UTC().Format(time.RFC3339Nano)
	case hasAny(key, "ntp", "时钟漂移", "时钟偏移"):
		return StatusUntested, "需要外部 NTP 服务器对时；当前版本不把本机时钟误差当作公网实测"
	case hasAny(key, "timezone", "时区"):
		name, offset := time.Now().Zone()
		return StatusOK, fmt.Sprintf("本机时区 %s（UTC%+d）", name, offset/3600)
	case hasAny(key, "cpu", "processor", "处理器"):
		return StatusOK, fmt.Sprintf("%d 个逻辑核心（%s/%s）", runtime.NumCPU(), runtime.GOOS, runtime.GOARCH)
	case hasAny(key, "memory", "ram", "内存"):
		if total, avail, ok := linuxMeminfo(); ok {
			return StatusOK, fmt.Sprintf("总内存 %s，可用 %s", humanBytes(total), humanBytes(avail))
		}
		return StatusUnknown, "当前系统未提供可读的内存统计接口"
	case hasAny(key, "swap", "交换"):
		if total, free, ok := linuxSwapinfo(); ok {
			return StatusOK, fmt.Sprintf("Swap 总量 %s，剩余 %s", humanBytes(total), humanBytes(free))
		}
		return StatusUnknown, "当前系统未提供可读的 Swap 统计接口"
	case hasAny(key, "os-version", "kernel", "内核", "操作系统"):
		return StatusOK, osVersion()
	case hasAny(key, "virtual", "虚拟化"):
		if value := readFirst("/sys/hypervisor/type"); value != "" {
			return StatusOK, "虚拟化类型 " + value
		}
		if out := command(ctx, "systemd-detect-virt"); out != "" {
			return StatusOK, "虚拟化类型 " + out
		}
		return StatusUnknown, "未能从当前系统识别虚拟化类型"
	case hasAny(key, "disk", "硬盘", "随机", "顺序"):
		return diskProbe(ctx)
	case hasAny(key, "ipv4", "本机 ipv4", "ipv4 地址"):
		if ip := interfaceIP(false); ip != "" {
			return StatusOK, "网卡地址 " + ip
		}
		return StatusUnknown, "未发现本机 IPv4 网卡地址"
	case hasAny(key, "ipv6", "本机 ipv6", "ipv6 地址"):
		if ip := interfaceIP(true); ip != "" {
			return StatusOK, "网卡地址 " + ip
		}
		return StatusUnknown, "未发现本机 IPv6 网卡地址"
	case hasAny(key, "resolv", "dns 配置", "域名解析配置"):
		for _, path := range []string{"/etc/resolv.conf"} {
			if data, err := os.ReadFile(path); err == nil {
				lines := 0
				for _, line := range strings.Split(string(data), "\n") {
					if strings.HasPrefix(strings.TrimSpace(line), "nameserver ") {
						lines++
					}
				}
				return StatusOK, fmt.Sprintf("读取 %s，发现 %d 个 nameserver", path, lines)
			}
		}
		return StatusUnknown, "当前系统没有可读取的 /etc/resolv.conf"
	case hasAny(key, "dns lookup", "dns-lookup", "解析耗时", "上游"):
		return dnsLookup(ctx)
	case hasAny(key, "dnssec", "dns 安全"):
		return StatusUntested, "需要对指定域名执行 DNSSEC 验证；当前版本不伪造本机结果"
	case hasAny(key, "doh", "dot", "加密域名"):
		return StatusUntested, "需要对上游解析器执行 DoH/DoT 握手；当前版本未配置测点"
	case hasAny(key, "mtu", "pmtu", "最大传输"):
		return mtuProbe(ctx)
	case hasAny(key, "route", "网关", "路由表", "路由"):
		return routeProbe(ctx)
	case hasAny(key, "congestion", "bbr", "cubic", "拥塞"):
		if value := readFirst("/proc/sys/net/ipv4/tcp_congestion_control"); value != "" {
			return StatusOK, "TCP 拥塞控制 " + value
		}
		return StatusUnknown, "当前系统未提供 TCP 拥塞控制读取接口"
	case hasAny(key, "queue", "fq_codel", "cake", "队列"):
		if value := readFirst("/proc/sys/net/core/default_qdisc"); value != "" {
			return StatusOK, "默认队列规则 " + value
		}
		return StatusUnknown, "当前系统未提供网卡队列规则读取接口"
	case hasAny(key, "port", "端口"):
		return portProbe(ctx, key)
	case hasAny(key, "latency", "ping", "延迟", "抖动"):
		return latencyProbe(ctx)
	case hasAny(key, "nat", "stun", "穿透", "锥型"):
		return StatusUntested, "需要外部 STUN 双端口测点；单机普通 GET 无法可靠区分 NAT 类型"
	case hasAny(key, "dnsbl", "spamhaus", "spamcop", "barracuda", "黑名单"):
		return dnsblProbe(ctx, p)
	case hasAny(key, "database", "maxmind", "ipinfo", "ip2location", "db-ip", "数据库", "风控库"):
		return StatusUntested, "数据库仅作参考，需要用户提供 API Key 或本地数据文件"
	case hasAny(key, "iperf", "吞吐", "测速", "bufferbloat", "带宽"):
		return StatusUntested, "需要用户指定测速节点；程序不擅自占用第三方带宽"
	case hasAny(key, "traceroute", "回程", "去程", "as-path", "bgp", "rpki", "ixp", "骨干"):
		return StatusUntested, "需要外部测点或路由数据库；本机无法单独证明去程/回程路径"
	case hasAny(key, "firewall", "icmp", "tls", "sni", "防火墙", "阻断"):
		return StatusUntested, "需要指定目标端点进行协议级连通性测试"
	case hasAny(key, "audit", "异常", "综合风险", "退款"):
		return StatusUntested, "综合判定需先完成对应基础探针"
	default:
		if p.Capability == "protocol" {
			return StatusUntested, "需要独立协议测点；当前版本保留清单项并报告原因"
		}
		return StatusUntested, "本机探针尚未为该清单项配置实现"
	}
}

var dnsblZones = []string{
	"zen.spamhaus.org", "sbl.spamhaus.org", "xbl.spamhaus.org", "pbl.spamhaus.org",
	"b.barracudacentral.org", "dnsbl.sorbs.net", "bl.spamcop.net",
	"dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net", "dnsbl-3.uceprotect.net",
}

func dnsblProbe(ctx context.Context, p catalog.Probe) (Status, string) {
	ip := net.ParseIP(exitIPFromContext(ctx))
	if ip == nil || ip.To4() == nil {
		return StatusUntested, "未获取可反查的公网 IPv4；DNSBL 项目未伪造结果"
	}
	index := 0
	if parts := strings.Split(p.Check, "-"); len(parts) > 1 {
		if n, err := strconv.Atoi(parts[len(parts)-1]); err == nil && n > 0 {
			index = n - 1
		}
	}
	if index < 0 || index >= len(dnsblZones) {
		return StatusUntested, "DNSBL 名单配置索引无效"
	}
	zone := dnsblZones[index]
	octets := strings.Split(ip.To4().String(), ".")
	for i, j := 0, len(octets)-1; i < j; i, j = i+1, j-1 {
		octets[i], octets[j] = octets[j], octets[i]
	}
	query := strings.Join(octets, ".") + "." + zone
	addrs, err := net.DefaultResolver.LookupHost(ctx, query)
	if err != nil {
		if ctx.Err() != nil {
			return StatusTimeout, zone + " DNSBL 查询超时"
		}
		// NXDOMAIN is the normal clean response. Go wraps it as *net.DNSError.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return StatusOK, zone + " 未发现列入记录"
		}
		return StatusUnknown, zone + " 查询失败（可能限制公共 DNSBL 查询）"
	}
	return StatusRisk, fmt.Sprintf("%s 返回 %s，表示该 IPv4 被该名单列入", zone, strings.Join(addrs, ", "))
}

func hasAny(s string, words ...string) bool {
	for _, word := range words {
		if strings.Contains(s, strings.ToLower(word)) {
			return true
		}
	}
	return false
}

func interfaceIP(v6 bool) string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if (ip.To4() == nil) == v6 {
				return ip.String()
			}
		}
	}
	return ""
}

func dnsLookup(ctx context.Context) (Status, string) {
	started := time.Now()
	addrs, err := net.DefaultResolver.LookupHost(ctx, "example.com")
	if err != nil {
		if ctx.Err() != nil {
			return StatusTimeout, "DNS 查询超时"
		}
		return StatusNetwork, "DNS 查询失败: " + safeError(err)
	}
	return StatusOK, fmt.Sprintf("example.com 返回 %d 个地址，用时 %d ms", len(addrs), time.Since(started).Milliseconds())
}

func latencyProbe(ctx context.Context) (Status, string) {
	started := time.Now()
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", "1.1.1.1:443")
	if err != nil {
		if ctx.Err() != nil {
			return StatusTimeout, "公共 HTTPS 测点连接超时"
		}
		return StatusNetwork, "公共 HTTPS 测点不可达"
	}
	_ = conn.Close()
	return StatusOK, fmt.Sprintf("1.1.1.1:443 TCP 建连 %d ms", time.Since(started).Milliseconds())
}

func portProbe(ctx context.Context, key string) (Status, string) {
	port := portFromKey(key)
	if port == 0 {
		return StatusUntested, "清单端口范围需要指定单一目标端口"
	}
	host := "1.1.1.1"
	started := time.Now()
	dialer := net.Dialer{Timeout: time.Second}
	if isUDPPort(port) {
		conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			if ctx.Err() != nil {
				return StatusTimeout, fmt.Sprintf("%s:%d UDP 路径初始化超时", host, port)
			}
			return StatusLimited, fmt.Sprintf("%s:%d UDP 路径不可用", host, port)
		}
		_ = conn.Close()
		return StatusUnknown, fmt.Sprintf("%s:%d UDP 路径已建立，但无服务响应，未判定端口开放（%d ms）", host, port, time.Since(started).Milliseconds())
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		if ctx.Err() != nil {
			return StatusTimeout, fmt.Sprintf("%s:%d 出站连接超时或被阻断", host, port)
		}
		return StatusLimited, fmt.Sprintf("%s:%d 出站连接未建立（%d ms）", host, port, time.Since(started).Milliseconds())
	}
	_ = conn.Close()
	return StatusOK, fmt.Sprintf("%s:%d 出站 TCP 可连（%d ms）", host, port, time.Since(started).Milliseconds())
}

func isUDPPort(port int) bool {
	switch port {
	case 53, 123, 500, 4500, 51820, 1194:
		return true
	default:
		return false
	}
}

func portFromKey(key string) int {
	for _, port := range []int{22, 80, 443, 8080, 8443, 25, 465, 587, 993, 995, 53, 853, 123, 51820, 1194, 500, 4500, 1080, 445, 135, 136, 137, 138, 139, 3389, 23, 3306, 5432, 6379, 27017} {
		if strings.Contains(key, strconv.Itoa(port)) {
			return port
		}
	}
	return 0
}

func mtuProbe(ctx context.Context) (Status, string) {
	for _, iface := range []string{"eth0", "ens3", "en0"} {
		path := filepath.Join("/sys/class/net", iface, "mtu")
		if value := readFirst(path); value != "" {
			return StatusOK, iface + " MTU " + value
		}
	}
	if out := command(ctx, "ip", "link"); out != "" {
		return StatusOK, firstLineContaining(out, "mtu")
	}
	return StatusUnknown, "当前系统未提供网卡 MTU 读取接口"
}

func routeProbe(ctx context.Context) (Status, string) {
	if out := command(ctx, "ip", "route"); out != "" {
		return StatusOK, firstLine(out)
	}
	if out := command(ctx, "route", "-n"); out != "" {
		return StatusOK, firstLine(out)
	}
	if runtime.GOOS == "windows" {
		if out := command(ctx, "route", "print"); out != "" {
			return StatusOK, firstLine(out)
		}
	}
	return StatusUnknown, "未读取到默认路由表"
}

func diskProbe(ctx context.Context) (Status, string) {
	if runtime.GOOS == "windows" {
		return StatusUntested, "Windows 磁盘基准测试需要显式指定卷，避免影响用户业务"
	}
	path := filepath.Join(os.TempDir(), ".openmili-disk-check")
	started := time.Now()
	data := make([]byte, 4096)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return StatusUnknown, "无法创建临时磁盘测试文件"
	}
	_ = os.Remove(path)
	return StatusOK, fmt.Sprintf("临时 4K 写入完成，用时 %d ms（轻量可逆检查）", time.Since(started).Milliseconds())
}

func osVersion() string {
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"") + " / " + runtime.GOOS + " " + runtime.GOARCH
			}
		}
	}
	return runtime.GOOS + " / " + runtime.GOARCH
}

func linuxMeminfo() (total, available uint64, ok bool) {
	values := parseMeminfo()
	total, available = values["MemTotal"], values["MemAvailable"]
	return total, available, total > 0
}

func linuxSwapinfo() (total, free uint64, ok bool) {
	values := parseMeminfo()
	total, free = values["SwapTotal"], values["SwapFree"]
	return total, free, total > 0
}

func parseMeminfo() map[string]uint64 {
	values := make(map[string]uint64)
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return values
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 2 {
			continue
		}
		n, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			continue
		}
		if len(parts) > 2 && parts[2] == "kB" {
			n *= 1024
		}
		values[strings.TrimSuffix(parts[0], ":")] = n
	}
	return values
}

func humanBytes(value uint64) string {
	if value == 0 {
		return "0 B"
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	for value >= 1024 && i < len(units)-1 {
		value /= 1024
		i++
	}
	return fmt.Sprintf("%d %s", value, units[i])
}

func readFirst(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func command(ctx context.Context, name string, args ...string) string {
	commandCtx, cancel := context.WithTimeout(ctx, 900*time.Millisecond)
	defer cancel()
	data, err := exec.CommandContext(commandCtx, name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func firstLine(value string) string {
	if i := strings.IndexByte(value, '\n'); i >= 0 {
		return strings.TrimSpace(value[:i])
	}
	return strings.TrimSpace(value)
}

func firstLineContaining(value, needle string) string {
	for _, line := range strings.Split(value, "\n") {
		if strings.Contains(strings.ToLower(line), strings.ToLower(needle)) {
			return strings.TrimSpace(line)
		}
	}
	return firstLine(value)
}
