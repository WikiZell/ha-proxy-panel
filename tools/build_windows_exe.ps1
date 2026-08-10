$ErrorActionPreference = "Stop"

$ToolsDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepositoryRoot = Split-Path -Parent $ToolsDirectory
$OutputDirectory = Join-Path $RepositoryRoot "dist"
$WorkDirectory = Join-Path $env:LOCALAPPDATA "HAProxyPanel\pyinstaller"

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null

Push-Location $ToolsDirectory
try {
    python -m PyInstaller --noconfirm --clean `
        --distpath $OutputDirectory `
        --workpath $WorkDirectory `
        "ha_proxy_panel_manager.spec"
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

$Executable = Join-Path $OutputDirectory "HA-Proxy-Panel-Manager.exe"
if (-not (Test-Path -LiteralPath $Executable)) {
    throw "Expected executable was not created: $Executable"
}

$Hash = Get-FileHash -Algorithm SHA256 -LiteralPath $Executable
Write-Output "Built $Executable"
Write-Output "SHA256 $($Hash.Hash)"
