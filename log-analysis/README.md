# 📋 Log Analysis

Parsers y detectores para análisis de logs en entornos Windows y Linux.

## Scripts

| Script | Descripción | Lenguaje |
|--------|-------------|----------|
| `event_log_parser.py` | Parsea Windows Event Logs (.evtx) y extrae eventos relevantes por EventID | Python |
| `suspicious_powershell_detector.py` | Detecta comandos PowerShell ofuscados o sospechosos en logs de seguridad | Python |

## Uso

```bash
python event_log_parser.py --file Security.evtx --eventid 4624 4625 4648
python suspicious_powershell_detector.py --log powershell_operational.evtx
```

## EventIDs de referencia

| EventID | Descripción |
|---------|-------------|
| 4624 | Logon exitoso |
| 4625 | Logon fallido |
| 4648 | Logon con credenciales explícitas |
| 4688 | Creación de proceso |
| 4698 | Tarea programada creada |
| 7045 | Servicio instalado |

## MITRE ATT&CK relevante

- T1059.001 — PowerShell
- T1078 — Valid Accounts
- T1053 — Scheduled Task/Job
