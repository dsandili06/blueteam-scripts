# 🖥️ Endpoint Triage

Scripts para triage rápido de endpoints Windows durante un incidente de seguridad.

## Scripts

| Script | Descripción | Lenguaje |
|--------|-------------|----------|
| `autoruns_analyzer.ps1` | Analiza entradas de inicio automático (Run keys, servicios, tareas programadas) en busca de persistencia | PowerShell |
| `process_checker.ps1` | Lista procesos en ejecución, detecta procesos sin firma digital y conexiones de red activas | PowerShell |
| `dll_checker.ps1` | Verifica DLLs cargadas por procesos buscando posibles casos de DLL Hijacking o Side-Loading | PowerShell |

## Uso

```powershell
# Ejecutar desde PowerShell como Administrador
.\autoruns_analyzer.ps1
.\process_checker.ps1
.\dll_checker.ps1
```

## MITRE ATT&CK relevante

- T1547 — Boot or Logon Autostart Execution
- T1574 — Hijack Execution Flow (DLL Side-Loading)
- T1057 — Process Discovery
