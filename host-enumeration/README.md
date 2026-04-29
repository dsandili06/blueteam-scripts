# 🔍 Host Enumeration

Scripts para enumeración de hosts en contexto de respuesta a incidentes o análisis forense.

## Scripts

| Script | Descripción | Lenguaje |
|--------|-------------|----------|
| `user_enumerator.py` | Enumera usuarios locales, grupos, último logon y cuentas privilegiadas | Python |
| `port_scanner.py` | Escaneo de puertos TCP/UDP para identificar servicios expuestos en un host | Python |
| `file_enumerator.py` | Busca archivos sospechosos por extensión, ubicación o fecha de modificación | Python |

## Uso

```bash
python user_enumerator.py
python port_scanner.py --target 192.168.1.10 --ports 1-1024
python file_enumerator.py --path /home --ext .sh .py .ps1
```

## MITRE ATT&CK relevante

- T1087 — Account Discovery
- T1046 — Network Service Discovery
- T1083 — File and Directory Discovery
