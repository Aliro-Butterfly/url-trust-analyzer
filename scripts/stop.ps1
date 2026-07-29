Get-CimInstance Win32_Process |
    Where-Object {
        $_.Name -in @("python.exe", "node.exe") -and
        ($_.CommandLine -match "uvicorn|vite")
    } |
    ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force
    }

Write-Host "Stopped local development processes."
