$ErrorActionPreference = "Stop"

function Write-Info($msg)  { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Warn($msg)  { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)   { Write-Host "[x] $msg" -ForegroundColor Red }

# Ensure Go is available; attempt installation via Chocolatey/Scoop if present.
function Ensure-Go {
    if (Get-Command go -ErrorAction SilentlyContinue) {
        Write-Info "Go is already installed: $(go version)"
        return
    }

    Write-Warn "Go not found in PATH."

    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Info "Installing Go via Chocolatey..."
        choco install golang -y
        return
    }
    if (Get-Command scoop -ErrorAction SilentlyContinue) {
        Write-Info "Installing Go via Scoop..."
        scoop install go
        return
    }

    Write-Err "Go toolchain is required. Install Go manually, then rerun this script."
    exit 1
}

# Ensure $binDir is on PATH for current session and persist for the user.
function Ensure-Path($binDir) {
    if (-not ($env:PATH.Split([IO.Path]::PathSeparator) -contains $binDir)) {
        Write-Info "Adding $binDir to PATH for current session."
        $env:PATH = "$binDir$([IO.Path]::PathSeparator)$env:PATH"
    }

    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if (-not ($userPath.Split([IO.Path]::PathSeparator) -contains $binDir)) {
        Write-Info "Persisting $binDir to user PATH."
        $newUserPath = "$binDir$([IO.Path]::PathSeparator)$userPath"
        setx PATH $newUserPath | Out-Null
    }
}

Ensure-Go

# Default GOPATH/bin (works even if GOPATH is unset).
$goEnv = go env GOPATH
if (-not $goEnv) {
    $goEnv = Join-Path $HOME "go"
}
$binDir = Join-Path $goEnv "bin"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
Ensure-Path $binDir

$tools = @{
    subfinder  = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    dnsx       = "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    httpx      = "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    katana     = "github.com/projectdiscovery/katana/cmd/katana@latest"
    gau        = "github.com/lc/gau/v2/cmd/gau@latest"
    waybackurls= "github.com/tomnomnom/waybackurls@latest"
}

foreach ($tool in $tools.Keys) {
    $mod = $tools[$tool]
    Write-Info "Installing $tool from $mod ..."
    go install $mod
}

Write-Info "Verifying tool versions:"
$versionChecks = @{
    subfinder   = "-version"
    dnsx        = "-version"
    httpx       = "-version"
    katana      = "-version"
    gau         = "--version"
    waybackurls = "--version"
}

foreach ($tool in $versionChecks.Keys) {
    $flag = $versionChecks[$tool]
    if (Get-Command $tool -ErrorAction SilentlyContinue) {
        $out = & $tool $flag 2>$null
        if (-not $out) { $out = & $tool -h 2>&1 | Select-Object -First 1 }
        Write-Host (" - {0}: {1}" -f $tool, ($out | Select-Object -First 1))
    }
    else {
        Write-Warn "Could not find $tool in PATH after install."
    }
}

Write-Host ""
Write-Info "All done. You may need to open a new terminal for PATH changes to take effect."
