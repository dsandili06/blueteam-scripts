<#
.SYNOPSIS
    Verifica DLLs cargadas por procesos en busca de DLL Hijacking o Side-Loading.
.DESCRIPTION
    Lista modulos (DLLs) cargados por cada proceso, verifica su firma digital
    e identifica DLLs cargadas desde ubicaciones inusuales (temp, appdata, etc.).
.NOTES
    Autor: Santiago Daniel Sandili
    MITRE ATT&CK: T1574.001 - DLL Search Order Hijacking | T1574.002 - DLL Side-Loading
    Requiere: PowerShell 5.1+, ejecucion como Administrador
.EXAMPLE
    .\dll_checker.ps1
    .\dll_checker.ps1 -ProcessName svchost
    .\dll_checker.ps1 -Export
#>

param(
    [string]$ProcessName = '*',
    [switch]$Export,
    [string]$OutputPath = ".\dlls_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
)

$suspiciousPaths = @('temp','appdata\local\temp','appdata\roaming','downloads',
                      'public','programdata','\users\\.*\\appdata')

$results = @{
    Timestamp    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Hostname     = $env:COMPUTERNAME
    SuspiciousDLLs = @()
    TotalScanned   = 0
}

Write-Host "`n[*] Escaneando DLLs cargadas por procesos..." -ForegroundColor Cyan

$procs = if ($ProcessName -eq '*') { Get-Process } else { Get-Process -Name $ProcessName -ErrorAction SilentlyContinue }

foreach ($proc in $procs) {
    try {
        $modules = $proc.Modules
        foreach ($mod in $modules) {
            $results.TotalScanned++
            $modPath = $mod.FileName

            $isSuspiciousPath = $false
            foreach ($sp in $suspiciousPaths) {
                if ($modPath -match [regex]::Escape($sp) -or $modPath -match $sp) {
                    $isSuspiciousPath = $true
                    break
                }
            }

            $signed = 'N/A'
            if (Test-Path $modPath) {
                $sig = Get-AuthenticodeSignature -FilePath $modPath -ErrorAction SilentlyContinue
                $signed = $sig.Status
            }

            $isUnsigned = $signed -notin @('Valid', 'NotApplicable')

            if ($isSuspiciousPath -or $isUnsigned) {
                $dllInfo = @{
                    PID          = $proc.Id
                    ProcessName  = $proc.Name
                    DLLName      = $mod.ModuleName
                    DLLPath      = $modPath
                    Signed       = $signed
                    SuspPath     = $isSuspiciousPath
                    Unsigned     = $isUnsigned
                }
                $results.SuspiciousDLLs += $dllInfo
                Write-Host "  [!] $($proc.Name) (PID $($proc.Id)) -> $modPath | Firma: $signed" -ForegroundColor Red
            }
        }
    } catch {
        # Procesos del sistema sin acceso a modulos
    }
}

Write-Host "`n[+] Resumen:" -ForegroundColor Green
Write-Host "  DLLs escaneadas      : $($results.TotalScanned)"
Write-Host "  DLLs sospechosas     : $($results.SuspiciousDLLs.Count)" -ForegroundColor $(if ($results.SuspiciousDLLs.Count -gt 0) {'Red'} else {'Gray'})

if ($Export) {
    $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "`n[+] Exportado a: $OutputPath" -ForegroundColor Green
}
