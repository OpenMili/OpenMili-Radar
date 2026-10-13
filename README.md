# OpenMili

OpenMili 用当前访问路径检查 VPS、住宅 IP 或代理 IP 的实际网页可用性。网页响应是主要依据，地理位置、ASN、住宅属性和 DNSBL 等数据库信息只作为参考。

## 使用

需要 Go 1.22+ 编译：

```bash
go build -o openmili ./cmd/openmili
./openmili
```

代理必须明确协议。HTTP 和 SOCKS5 均支持，代理失败时不会自动改用直连：

```bash
./openmili --proxy socks5://127.0.0.1:10808
./openmili --proxy http://127.0.0.1:10808 --timeout 8s
```

Windows PowerShell：

```powershell
go build -o openmili.exe .\cmd\openmili
.\openmili.exe --proxy socks5://127.0.0.1:10808
```

macOS 和 Linux 直接运行对应二进制即可。`--full` 执行全部已配置网页探针（默认 15 秒预算）；默认模式只执行重点探针。`--width 80` 或 `--width 100` 控制双列终端宽度，`--no-color` 禁用 ANSI 颜色，`--json` 输出完整机器可读证据。

GitHub Release 发布后，Linux 用户一行安装并开始测试：

```bash
curl -fsSL https://raw.githubusercontent.com/OpenMili/OpenMili-Radar/main/scripts/install.sh | bash && ~/.local/bin/openmili
```

代理测试示例：

```bash
~/.local/bin/openmili --proxy socks5://127.0.0.1:10808
```

上面的仓库地址默认是 `OpenMili/OpenMili-Radar`；如果实际 GitHub 用户名或仓库名不同，发布前同步修改 `scripts/install.sh`、`scripts/install.ps1` 和这段命令。

首次发布时推送一个版本标签即可触发自动编译和 Release：

```bash
git tag v0.1.0
git push origin v0.1.0
```

网页探针只执行普通 GET 和安全重定向跟随，记录状态码、标题、正文片段、最终 URL 和耗时；不登录、不提交表单、不绕过验证码、不执行真实播放。`pkg/probe.ClickSameOriginLink` 可按需验证同源普通链接，CLI 默认不自动点击；依赖 JavaScript 的按钮仍需后续可选浏览器运行时。出口 IP 查询与网页请求使用同一访问路径，开始和结束会各核验一次；出口变化会在报告中提示。

## 跨平台构建

```bash
GOOS=linux GOARCH=amd64 go build -o dist/openmili-linux-amd64 ./cmd/openmili
GOOS=darwin GOARCH=arm64 go build -o dist/openmili-darwin-arm64 ./cmd/openmili
GOOS=windows GOARCH=amd64 go build -o dist/openmili-windows-amd64.exe ./cmd/openmili
```

项目不读取 API 密钥、Cookies 或代理口令文件；代理认证信息只从命令行 URL 读取，并不会写入报告。

## 开源

OpenMili 自身采用 MIT License，见 [LICENSE](LICENSE)。公开仓库不包含 API 密钥、Cookies、Token、代理口令或真实用户数据。

批量生成 Linux、macOS、Windows 构建产物：`scripts/build.sh` 或 `scripts/build.ps1`。发布前应为每个产物生成 SHA-256 校验值，并在 GitHub Release 中同时发布版本、校验值和变更说明。

从源码目录安装可执行文件：Linux/macOS 运行 `scripts/install.sh`，Windows PowerShell 运行 `scripts/install.ps1`。安装脚本通过 SHA-256SUMS 校验 GitHub Release 产物，也可用 `OPENMILI_VERSION` 和 `OPENMILI_REPO` 指定版本和仓库。
