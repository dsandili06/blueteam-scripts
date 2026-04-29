<#
.SYNOPSIS
    Analiza entradas de inicio automatico en busca de persistencia.
.DESCRIPTION
    Revisa Run keys del registro, tareas programadas y servicios instalados
    para identificar posibles mecanismos de persistencia.
.NOTES
    Autor: Santiago Daniel Sandili
    MITRE ATT&CK: T1547 - Boot or Logon Autostart Execution
    Requiere: PowerShell 5.1+, ejecucion como Administrador recomendada
.EXAMPLE
    .\autoruns_analyzer.ps1
    .\autoruns_analyzer.ps1 -Export -OutputPath C:\triage\autoruns.json
#>

param(
    [switch]$Export,
    [string]$OutputPath = ".\autoruns_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
)

$results = @{
    Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Hostname    = $env:COMPUTERNAME
    RunKeys     = @()
    ScheduledTasks = @()
    Services    = @()
}

Write-Host "`n[*] Analizando Run Keys del registro..." -ForegroundColor Cyan

$runKeyPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($path in $runKeyPaths) {
    if (Test-Path $path) {
        $entries = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        if ($entries) {
            $entries.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $entry = @{
                    RegistryPath = $path
                    Name         = $_.Name
                    Value        = $_.Value
                    Suspicious   = ($_.Value -match 'temp|appdata|public|downloads|cmd|powershell|wscript|cscript|mshta|rundll32' -or
                                    $_.Value -match 'base64|encoded|bypass|hidden')
                }
                $results.RunKeys += $entry
                $color = if ($entry.Suspicious) { "Red" } else { "Gray" }
                Write-Host "  [$($path -replace 'HKLM:\\|HKCU:\\','')] $($_.Name): $($_.Value)" -ForegroundColor $color
            }
        }
    }
}

Write-Host "`n[*] Analizando Tareas Programadas..." -ForegroundColor Cyan

Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
    $action = $_.Actions | Select-Object -First 1
    $taskInfo = @{
        TaskName    = $_.TaskName
        TaskPath    = $_.TaskPath
        State       = $_.State
        Execute     = $action.Execute
        Arguments   = $action.Arguments
        Author      = $_.Author
        Suspicious  = ($action.Execute -match 'powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32' -and
                       $action.Arguments -match 'hidden|bypass|encoded|base64|downloadstring|iex')
    }
    $results.ScheduledTasks += $taskInfo
    if ($taskInfo.Suspicious) {
        Write-Host "  [!] SOSPECHOSA: $($_.TaskName) -> $($action.Execute) $($action.Arguments)" -ForegroundColor Red
    }
}

Write-Host "`n[*] Analizando Servicios instalados..." -ForegroundColor Cyan

Get-WmiObject Win32_Service | Where-Object { $_.StartMode -in @('Auto','Manual') } | ForEach-Object {
    $svcInfo = @{
        Name        = $_.Name
        DisplayName = $_.DisplayName
        State       = $_.State
        StartMode   = $_.StartMode
        PathName    = $_.PathName
        StartName   = $_.StartName
        Suspicious  = ($_.PathName -match 'temp|appdata|public|downloads' -or
                       $_.StartName -match 'LocalSystem' -and $_.PathName -match 'powershell|cmd')
    }
    $results.Services += $svcInfo
    if ($svcInfo.Suspicious) {
        Write-Host "  [!] SOSPECHOSO: $($_.Name) -> $($_.PathName)" -ForegroundColor Red
    }
}

$suspRunKeys   = ($results.RunKeys    | Where-Object { $_.Suspicious }).Count
$suspTasks     = ($results.ScheduledTasks | Where-Object { $_.Suspicious }).Count
$suspServices  = ($results.Services   | Where-Object { $_.Suspicious }).Count

Write-Host "`n[+] Resumen:" -ForegroundColor Green
Write-Host "  Run Keys totales     : $($results.RunKeys.Count)  |  Sospechosos: $suspRunKeys" -ForegroundColor $(if ($suspRunKeys -gt 0) {'Red'} else {'Gray'})
Write-Host "  Tareas programadas   : $($results.ScheduledTasks.Count)  |  Sospechosas: $suspTasks" -ForegroundColor $(if ($suspTasks -gt 0) {'Red'} else {'Gray'})
Write-Host "  Servicios analizados : $($results.Services.Count)  |  Sospechosos: $suspServices" -ForegroundColor $(if ($suspServices -gt 0) {'Red'} else {'Gray'})

if ($Export) {
    $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "`n[+] Resultados exportados a: $OutputPath" -ForegroundColor Green
}
