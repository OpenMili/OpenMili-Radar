$ErrorActionPreference = 'Stop'
$rootDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$outDir = Join-Path $rootDir 'dist'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

function Build-One([string]$goos, [string]$goarch, [string]$suffix) {
    $name = "openmili-$goos-$goarch$suffix"
    Write-Host "building $name"
    Push-Location $rootDir
    try {
        $env:GOOS = $goos
        $env:GOARCH = $goarch
        $env:CGO_ENABLED = '0'
        & go build -trimpath -ldflags '-s -w' -o (Join-Path $outDir $name) ./cmd/openmili
        if ($LASTEXITCODE -ne 0) { throw "go build failed for $name" }
    } finally {
        Pop-Location
    }
}

Build-One 'linux' 'amd64' ''
Build-One 'linux' 'arm64' ''
Build-One 'darwin' 'amd64' ''
Build-One 'darwin' 'arm64' ''
Build-One 'windows' 'amd64' '.exe'
Build-One 'windows' 'arm64' '.exe'
Write-Host "artifacts written to $outDir"
