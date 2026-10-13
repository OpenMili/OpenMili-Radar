$ErrorActionPreference = 'Stop'
$prefix = if ($env:OPENMILI_PREFIX) { $env:OPENMILI_PREFIX } else { Join-Path $HOME 'bin' }
$repo = if ($env:OPENMILI_REPO) { $env:OPENMILI_REPO } else { 'OpenMili/OpenMili-Radar' }
$version = if ($env:OPENMILI_VERSION) { $env:OPENMILI_VERSION } else { 'latest' }
New-Item -ItemType Directory -Force -Path $prefix | Out-Null

$rootDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$binary = Join-Path $prefix 'openmili.exe'
if ((Test-Path (Join-Path $rootDir 'go.mod')) -and (Test-Path (Join-Path $rootDir 'cmd\openmili'))) {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw '未找到 Go 1.22+；从源码安装需要先安装 Go。' }
    Push-Location $rootDir
    try {
        $env:CGO_ENABLED = '0'
        & go build -trimpath -ldflags '-s -w' -o $binary ./cmd/openmili
        if ($LASTEXITCODE -ne 0) { throw 'go build 失败' }
    } finally { Pop-Location }
    Write-Host "已从源码安装到 $binary"
    exit 0
}

$arch = if ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { throw '仅支持 64 位 Windows' }
$url = if ($version -eq 'latest') {
    "https://github.com/$repo/releases/latest/download/openmili-windows-$arch.exe"
} else {
    "https://github.com/$repo/releases/download/$version/openmili-windows-$arch.exe"
}
$sumsUrl = if ($version -eq 'latest') {
    "https://github.com/$repo/releases/latest/download/SHA256SUMS"
} else {
    "https://github.com/$repo/releases/download/$version/SHA256SUMS"
}
$tmp = "$binary.tmp"
$sums = "$binary.sha256"
try {
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tmp
    Invoke-WebRequest -UseBasicParsing -Uri $sumsUrl -OutFile $sums
    $asset = "openmili-windows-$arch.exe"
    $line = Get-Content -LiteralPath $sums | Where-Object { $_ -match "\s$([regex]::Escape($asset))$" } | Select-Object -First 1
    if (-not $line) { throw "发布校验文件中缺少 $asset" }
    $expected = ($line -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw 'SHA-256 校验失败' }
    Move-Item -Force -LiteralPath $tmp -Destination $binary
} finally {
    Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $tmp, $sums
}
Write-Host "已安装 $repo $version 到 $binary"
