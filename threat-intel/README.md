# 🌐 Threat Intel

Scripts para consultar IOCs contra plataformas de inteligencia de amenazas.

## Scripts

| Script | Descripción | API requerida |
|--------|-------------|---------------|
| `ip_lookup.py` | Consulta una IP contra AbuseIPDB y obtiene reputación, país y reportes | AbuseIPDB |
| `hash_checker.py` | Verifica un hash MD5/SHA1/SHA256 contra VirusTotal | VirusTotal |
| `domain_checker.py` | Analiza un dominio contra VirusTotal y obtiene categorías y detecciones | VirusTotal |
| `url_checker.py` | Escanea una URL completa en VirusTotal y retorna el resultado del análisis | VirusTotal |

## Configuración

Copiar `.env.example` a `.env` y completar las API keys:

```bash
cp .env.example .env
```

```env
VIRUSTOTAL_API_KEY=tu_api_key_aqui
ABUSEIPDB_API_KEY=tu_api_key_aqui
```

## Uso

```bash
python ip_lookup.py --ip 1.2.3.4
python hash_checker.py --hash d41d8cd98f00b204e9800998ecf8427e
python domain_checker.py --domain evil.example.com
python url_checker.py --url https://suspicious-site.com/payload
```
