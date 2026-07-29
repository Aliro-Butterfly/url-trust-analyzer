param(
    [string]$PortBackend = "8000",
    [string]$PortFrontend = "5173"
)

$repoRoot = Split-Path -Parent $PSScriptRoot
$backendDir = Join-Path $repoRoot "backend"
$frontendDir = Join-Path $repoRoot "frontend"

$env:PYTHONPATH = $repoRoot

$nodePath = "C:\Program Files\nodejs"
if (Test-Path $nodePath) {
    $env:Path = "$nodePath;$env:Path"
}

Write-Host "Starting backend on http://127.0.0.1:$PortBackend..."
Start-Process -FilePath "python" -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", $PortBackend -WorkingDirectory $backendDir -WindowStyle Hidden | Out-Null

Write-Host "Starting frontend on http://127.0.0.1:$PortFrontend..."
Start-Process -FilePath "npm" -ArgumentList "run", "dev", "--", "--host", "127.0.0.1", "--port", $PortFrontend -WorkingDirectory $frontendDir -WindowStyle Hidden | Out-Null

Start-Sleep -Seconds 3
Write-Host "Backend: http://127.0.0.1:$PortBackend"
Write-Host "Frontend: http://127.0.0.1:$PortFrontend"
