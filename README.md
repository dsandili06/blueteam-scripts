#  blueteam-scripts

Colección de scripts de Blue Team para operaciones SOC: triage de endpoints, enumeración de hosts, análisis de logs e inteligencia de amenazas.

Desarrollados como parte de mi formación práctica en ciberseguridad defensiva.

---

## 📁 Estructura

```
blueteam-scripts/
├── endpoint-triage/       # Scripts de triage y análisis de endpoints Windows
├── host-enumeration/      # Enumeración de hosts, usuarios, puertos y archivos
├── log-analysis/          # Parsers y detectores sobre logs de Windows/Linux
├── threat-intel/          # Consultas a APIs de inteligencia de amenazas (VT, AbuseIPDB, etc.)
└── notes/                 # Notas técnicas y referencias
```

---

## 🔧 Tecnologías

- **Python 3.x** — scripts de análisis, parsers, consultas a APIs
- **PowerShell** — triage y análisis forense en entornos Windows
- **Bash** — automatización en entornos Linux

---

## 📌 Categorías

### 🖥️ Endpoint Triage
Scripts para analizar el estado de un endpoint durante un incidente: procesos sospechosos, DLLs cargadas, entradas de autoruns y persistencia.

### 🔍 Host Enumeration
Enumeración de usuarios locales, puertos abiertos y archivos relevantes en un host comprometido o bajo análisis.

### 📋 Log Analysis
Parsers para Windows Event Logs y detección de comportamiento sospechoso en PowerShell, autenticaciones y eventos de sistema.

### 🌐 Threat Intel
Scripts para consultar IOCs (IPs, hashes, dominios, URLs) contra plataformas como VirusTotal, AbuseIPDB y ThreatFox.

---

##  Autor

**Santiago Daniel Sandili**  
SOC Analyst / Blue Team Practitioner  
[LinkedIn](https://linkedin.com/in/santiagodsandili) · [Portfolio](https://dsandili06.github.io) · [Labs & Writeups](https://github.com/dsandili06/SOC-Practitioner-Labs)
