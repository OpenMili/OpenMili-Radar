// Code generated from OpenMili_全量网络与风控探测大纲_CN.md.
// Keep the source checklist outside the public release; this registry is the
// stable, read-only index used by the full report.
package catalog

import "fmt"

// auditGroup contains checklist items which are not ordinary webpage probes.
// They remain indexed even before their native probe is available.
type auditGroup struct {
	category   string
	key        string
	capability string
	reason     string
	names      []string
}

var preWebAuditGroups = []auditGroup{
	{
		category: "本机系统与硬件环境", key: "system", capability: "local", reason: "需要本机系统探针；当前版本未实现",
		names: []string{
			"本机系统时间 (协调世界时 / 北京时间)",
			"网络时钟漂移 (NTP 毫秒偏移量)",
			"系统底层配置时区",
			"处理器硬件规格 (核心数 / 频率 / 硬件加速指令集)",
			"物理内存容量与交换分区 (Swap)",
			"硬盘读写性能 (4K随机与顺序读写)",
			"虚拟化底层架构 (KVM / Xen / LXC)",
			"操作系统与 Linux 内核版本",
		},
	},
	{
		category: "底层网络配置与传输协议栈", key: "network", capability: "local", reason: "需要本机系统探针；当前版本未实现",
		names: []string{
			"本机 IPv4 地址",
			"本机 IPv6 地址",
			"双栈优先级调度策略 (IPv6 / IPv4 调度权重)",
			"原生 IPv6 广播判定",
			"飓风电气 6in4 隧道伪装判定",
			"双栈路由路径差异度",
			"默认网关与静态路由表",
			"地址转换暴露类型 (公网原生 / 1:1 NAT / 运营商级 NAT)",
			"传输层最大传输单元 (MTU / PMTU 自动探测)",
			"报文最大段长协商 (TCP MSS)",
			"IPv6 路径分片黑洞与丢包检测",
			"核心拥塞控制算法 (BBR / Cubic)",
			"报文队列调度规则 (fq / fq_codel / cake)",
			"显式拥塞通知 (ECN)",
			"TCP 快速打开 (TFO)",
			"TCP 窗口缩放 (Window Scaling)",
			"TCP 报文传输重传率",
			"突发带宽流量整形限制检测",
			"系统最大并发 TCP 连接数上限",
			"连接跟踪表容量上限 (nf_conntrack Limit)",
			"中间件透明代理劫持检测 (Middlebox)",
			"安全证书透明度检测 (Certificate Transparency)",
			"域名反向解析记录 (rDNS / PTR)",
			"网卡物理协商速率与双工状态",
			"网卡底层丢包统计 (接收丢包 / 发送错误)",
		},
	},
	{
		category: "域名解析架构、隐私泄漏与安全审计", key: "dns", capability: "local", reason: "需要本机系统探针；当前版本未实现",
		names: []string{
			"本机系统域名解析配置 (/etc/resolv.conf)",
			"上游域名服务器解析端到端耗时",
			"域名解析隐私泄漏检测 (DNS Leak)",
			"网页实时通信真实地址泄漏检测 (WebRTC Leak)",
			"域名解析劫持与缓存投毒嗅探",
			"客户端子网标识传递 (EDNS Client Subnet)",
			"加密域名解析协议支持 (DoH / DoT)",
			"域名系统安全扩展签名校验 (DNSSEC)",
		},
	},
	{
		category: "物理定位与全球权威数据库对账", key: "geo", capability: "database", reason: "需要配置数据源或 API；当前版本未实现",
		names: []string{
			"BGP 边界网关协议真实底层广播位置",
			"麦克斯曼德数据库 (MaxMind GeoLite2)",
			"艾皮信息官方库 (IPinfo)",
			"艾皮位置数据库 (IP2Location)",
			"数据艾皮库 (DB-IP)",
			"国际通用地址库 (ip-api)",
			"百度 IP 数据库",
			"纯真网络离线库 (CZ88)",
			"多数据库定位冲突与广播漂移指数",
		},
	},
	{
		category: "浅层离线风控数据库", key: "risk", capability: "database", reason: "需要配置数据源或 API；当前版本未实现",
		names: []string{
			"运营商官方注册使用类别 (家庭宽带 / 商业宽带 / 机房中心)",
			"滥用行为举报库评分 (AbuseIPDB)",
			"欺诈风险评级库分值 (Scamalytics)",
			"综合威胁评级库分值 (IPQualityScore)",
		},
	},
	{
		category: "全球邮件与安全反垃圾实时黑名单库", key: "dnsbl", capability: "dnsbl", reason: "需要 DNSBL 查询器与名单配置；当前版本未实现",
		names: []string{
			"斯帕姆豪斯综合名单 (Spamhaus ZEN)",
			"斯帕姆豪斯垃圾IP名单 (Spamhaus SBL)",
			"斯帕姆豪斯漏洞利用名单 (Spamhaus XBL)",
			"斯帕姆豪斯动态用户名单 (Spamhaus PBL)",
			"梭子鱼安全威胁库 (Barracuda)",
			"索布斯黑名单库 (SORBS)",
			"垃圾邮件警察库 (SpamCop)",
			"优胜保护一级黑名单 (UCEPROTECT Level 1)",
			"优胜保护二级网段名单 (UCEPROTECT Level 2)",
			"优胜保护三级自治域名单 (UCEPROTECT Level 3)",
		},
	},
	{
		category: "网络穿透类型与打洞测试", key: "nat", capability: "protocol", reason: "需要独立协议探针；当前版本未实现",
		names: []string{
			"全锥型网络地址转换 (Full Cone NAT)",
			"受限锥型网络地址转换 (Restricted Cone NAT)",
			"端口受限锥型网络地址转换 (Port Restricted Cone NAT)",
			"对称型网络地址转换 (Symmetric NAT)",
			"穿透服务器测试响应延迟 (STUN Latency)",
		},
	},
	{
		category: "边界网关拓扑与全球互联网交换中心", key: "bgp", capability: "network", reason: "需要网络诊断或外部测点；当前版本未实现",
		names: []string{
			"路由起源授权验证 (RPKI ROA)",
			"泛播与单播网络架构判定 (Anycast / Unicast)",
			"自治系统路径跳数分析 (AS-Path)",
			"国际一级骨干运营商识别 (Lumen / Arelion / Cogent / NTT / GTT / HE.net)",
			"互联网交换中心接入识别 (IXP)",
			"中国香港互联网交换中心 (HKIX)",
			"美国阿什本易昆尼克斯交换中心 (Equinix Ashburn)",
			"美国圣何塞易昆尼克斯交换中心 (Equinix San Jose)",
			"荷兰阿姆斯特丹交换中心 (AMS-IX)",
			"德国法兰克福交换中心 (DE-CIX)",
			"英国伦敦交换中心 (LINX)",
		},
	},
	{
		category: "防火墙阻断与双向网络连通性检测", key: "firewall", capability: "network", reason: "需要网络诊断或外部测点；当前版本未实现",
		names: []string{
			"网际控制报文协议阻断检测 (ICMP 阻断)",
			"传输控制协议端口阻断检测 (TCP 端口阻断)",
			"传输层安全服务器名称指示握手阻断检测 (TLS / SNI 阻断)",
			"去程与回程网络路由非对称性检测",
		},
	},
	{
		category: "主要网络端口出入站检测", key: "ports", capability: "network", reason: "需要网络诊断或外部测点；当前版本未实现",
		names: []string{
			"端口 22 (SSH 远程安全终端)",
			"端口 80 (HTTP 基础网页)",
			"端口 443 (HTTPS 加密网页 / HTTP3)",
			"端口 8080 (HTTP 备用网页)",
			"端口 8443 (HTTPS 备用安全端口)",
			"端口 25 (SMTP 标准邮件发信)",
			"端口 465 (SMTPS 加密邮件发信)",
			"端口 587 (Submission 客户端邮件提交)",
			"端口 993 (IMAPS 加密邮件收取)",
			"端口 995 (POP3S 加密邮件拉取)",
			"端口 53 (DNS 域名解析通信)",
			"端口 853 (DoT 加密域名解析)",
			"端口 123 (NTP 网络时间同步)",
			"端口 51820 (WireGuard 虚拟专网)",
			"端口 1194 (OpenVPN 虚拟专网)",
			"端口 500 / 4500 (IPsec / IKEv2 原生专网)",
			"端口 1080 (SOCKS5 代理通信)",
			"端口 445 (SMB 文件共享局域网)",
			"端口 135-139 (NetBIOS 局域网协议)",
			"端口 3389 (RDP 远程桌面协议)",
			"端口 23 (Telnet 早期明文终端)",
			"端口 3306 (MySQL 数据库服务)",
			"端口 5432 (PostgreSQL 数据库服务)",
			"端口 6379 (Redis 缓存数据库服务)",
			"端口 27017 (MongoDB 文档数据库服务)",
		},
	},
	{
		category: "真实网络连接性能、测速、延迟与双向路由", key: "performance", capability: "network", reason: "需要网络诊断或外部测点；当前版本未实现",
		names: []string{
			"域名解析耗时 (DNS Lookup Time)",
			"三次握手耗时 (TCP Handshake Time)",
			"安全握手协商耗时 (TLS / SSL Handshake Time)",
			"首字节响应耗时 (TTFB)",
			"完整请求总耗时 (Total Time)",
			"空闲状态网络延迟 (Unloaded Latency)",
			"满载下载网络延迟 (Download Active Latency)",
			"满载上传网络延迟 (Upload Active Latency)",
			"缓冲区膨胀综合评级 (Bufferbloat Grade)",
			"TCP 单线程纯吞吐量",
			"TCP 多线程极限吞吐量",
			"UDP 极限带宽吞吐量",
			"UDP 物理传输丢包率",
			"UDP 传输丢包率检测",
			"UDP 服务质量限速检测 (QoS 限制)",
			"HTTP/3 (QUIC) 穿透能力检测",
			"WireGuard UDP 连通性检测",
			"中国电信 (上海)",
			"中国联通 (北京)",
			"中国移动 (广州)",
			"谷歌公共解析节点 (Google DNS)",
			"云闪安全解析节点 (Cloudflare DNS)",
			"中国香港节点 (HKIX)",
			"日本东京节点 (NTT)",
			"新加坡节点 (Singtel)",
			"德国法兰克福节点 (DE-CIX)",
			"单线程下载速度",
			"单线程上传速度",
			"多线程下载速度",
			"多线程上传速度",
			"测速延迟与抖动",
			"上海电信",
			"北京电信",
			"广州电信",
			"武汉电信",
			"成都电信",
			"上海联通",
			"北京联通",
			"广州联通",
			"郑州联通",
			"沈阳联通",
			"上海移动",
			"北京移动",
			"广州移动",
			"杭州移动",
			"成都移动",
			"中国香港",
			"中国台湾",
			"日本东京",
			"韩国首尔",
			"新加坡",
			"美国洛杉矶",
			"美国圣何塞",
			"美国西雅图",
			"美国纽约",
			"德国法兰克福",
			"英国伦敦",
			"北京电信去程",
			"上海电信去程",
			"广州电信去程",
			"北京联通去程",
			"上海联通去程",
			"广州联通去程",
			"北京移动去程",
			"上海移动去程",
			"广州移动去程",
			"电信去程线路判定 (163骨干网 / CN2 GT / CN2 GIA)",
			"联通去程线路判定 (4837骨干网 / 9929精品网)",
			"移动去程线路判定 (CMI骨干网 / CMIN2精品网)",
			"北京电信回程",
			"上海电信回程",
			"广州电信回程",
			"成都电信回程",
			"武汉电信回程",
			"北京联通回程",
			"上海联通回程",
			"广州联通回程",
			"郑州联通回程",
			"沈阳联通回程",
			"北京移动回程",
			"上海移动回程",
			"广州移动回程",
			"杭州移动回程",
			"成都移动回程",
			"中国教育科研网 (北京)",
			"中国科技网 (上海)",
			"电信回程线路判定 (163骨干网 / CN2 GT / CN2 GIA)",
			"联通回程线路判定 (4837骨干网 / 9929精品网 / CUG)",
			"移动回程线路判定 (CMI骨干网 / CMIN2精品网)",
		},
	},
}

var postWebAuditGroups = []auditGroup{
	{
		category: "核心异常指标与综合审计判定", key: "audit", capability: "derived", reason: "依赖其他探针结果；当前版本未实现",
		names: []string{
			"奈飞原生链路封锁与域名解析劫持判定",
			"云闪边缘安全防护盾牌阻断判定",
			"谷歌自动化网络爬虫沙盒挑战判定",
			"双栈协议网络超时与迟滞判定",
			"全网综合风险等级评定与原路退款判定标准",
		},
	},
}

// buildAuditItems materializes a copy so callers can safely edit Full results.
func buildAuditItems(groups []auditGroup) []Probe {
	count := 0
	for _, group := range groups {
		count += len(group.names)
	}
	items := make([]Probe, 0, count)
	for _, group := range groups {
		for index, name := range group.names {
			check := fmt.Sprintf("%s-%02d", group.key, index+1)
			items = append(items, Probe{
				ID:   fmt.Sprintf("audit-%s-%02d", group.key, index+1),
				Name: name, Category: group.category, Capability: group.capability,
				Check: check, Reason: group.reason,
			})
		}
	}
	return items
}

// Full returns every item in the source checklist, in source order: chapters
// 1-11, the 319 webpage entries from chapter 12, then chapter 13. Empty URLs
// are intentional for native checks that still need their implementation.
func Full() []Probe {
	pre := buildAuditItems(preWebAuditGroups)
	post := buildAuditItems(postWebAuditGroups)
	web := All()
	result := make([]Probe, 0, len(pre)+len(web)+len(post))
	result = append(result, pre...)
	result = append(result, web...)
	result = append(result, post...)
	return result
}
