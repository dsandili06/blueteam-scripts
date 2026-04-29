<#
.SYNOPSIS
    Analiza procesos en ejecucion en busca de comportamiento sospechoso.
.DESCRIPTION
    Lista procesos activos, detecta los que no tienen firma digital valida,
    identifica conexiones de red asociadas y procesos inyectados o sin imagen en disco.
.NOTES
    Autor: Santiago Daniel Sandili
    MITRE ATT&CK: T1057 - Process Discovery | T1055 - Process Injection
    Requiere: PowerShell 5.1+, ejecucion como Administrador
.EXAMPLE
    .\process_checker.ps1
    .\process_checker.ps1 -Export
#>

param(
    [switch]$Export,
    [string]$OutputPath = ".\processes_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
)

$results = @{
    Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Hostname    = $env:COMPUTERNAME
    Processes   = @()
    Connections = @()
}

$suspiciousNames = @('powershell','cmd','wscript','cscript','mshta','rundll32',
                      'regsvr32','certutil','bitsadmin','wmic','schtasks','at',
                      'net','netsh','mimikatz','procdump','psexec')

Write-Host "`n[*] Enumerando procesos activos..." -ForegroundColor Cyan

$processes = Get-Process | ForEach-Object {
    $proc = $_
    $path = try { $proc.MainModule.FileName } catch { 'N/A' }
    $signed = 'N/A'
    $publisher = 'N/A'

    if ($path -ne 'N/A' -and (Test-Path $path)) {
        $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
        $signed    = $sig.Status
        $publisher = $sig.SignerCertificate.Subject
    }

    $suspicious = ($signed -notin @('Valid','NotApplicable') -and $path -ne 'N/A') -or
                  ($suspiciousNames -contains $proc.Name.ToLower() -and $path -match 'temp|appdata|public|downloads')

    $procInfo = @{
        PID         = $proc.Id
        Name        = $proc.Name
        Path        = $path
        Signed      = $signed
        Publisher   = $publisher
        CPU         = [math]::Round($proc.CPU, 2)
        MemoryMB    = [math]::Round($proc.WorkingSet64 / 1MB, 2)
        StartTime   = try { $proc.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } catch { 'N/A' }
        Suspicious  = $suspicious
    }

    $results.Processes += $procInfo

    if ($suspicious) {
        Write-Host "  [!] PID $($proc.Id) - $($proc.Name) | Firma: $signed | Path: $path" -ForegroundColor Red
    } else {
        Write-Host "  [+] PID $($proc.Id) - $($proc.Name)" -ForegroundColor Gray
    }

    $procInfo
}

Write-Host "`n[*] Analizando conexiones de red activas..." -ForegroundColor Cyan

try {
    $netConns = Get-NetTCPConnection -State Established,Listen -ErrorAction Stop
    foreach ($conn in $netConns) {
        $ownerProc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $connInfo = @{
            LocalAddress  = $conn.LocalAddress
            LocalPort     = $conn.LocalPort
            RemoteAddress = $conn.RemoteAddress
            RemotePort    = $conn.RemotePort
            State         = $conn.State
            PID           = $conn.OwningProcess
            ProcessName   = if ($ownerProc) { $ownerProc.Name } else { 'N/A' }
        }
        $results.Connections += $connInfo
        if ($conn.State -eq 'Established' -and $conn.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)') {
            Write-Host "  [NET] $($ownerProc.Name) (PID $($conn.OwningProcess)) -> $($conn.RemoteAddress):$($conn.RemotePort)" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "  [!] No se pudieron obtener conexiones de red: $_" -ForegroundColor Red
}

$suspCount = ($results.Processes | Where-Object { $_.Suspicious }).Count

Write-Host "`n[+] Resumen:" -ForegroundColor Green
Write-Host "  Procesos totales    : $($results.Processes.Count)"
Write-Host "  Procesos sospechosos: $suspCount" -ForegroundColor $(if ($suspCount -gt 0) {'Red'} else {'Gray'})
Write-Host "  Conexiones activas  : $($results.Connections.Count)"

if ($Export) {
    $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "`n[+] Exportado a: $OutputPath" -ForegroundColor Green
}
