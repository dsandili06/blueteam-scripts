#!/usr/bin/env python3
"""
IP Lookup
---------
Consulta una IP contra AbuseIPDB y obtiene reputacion, pais y reportes.

Autor: Santiago Daniel Sandili

Uso:
    python ip_lookup.py --ip 1.2.3.4
    python ip_lookup.py --ip 1.2.3.4 --json
    python ip_lookup.py --file ips.txt

Dependencias:
    pip install requests python-dotenv

Configuracion:
    Crear archivo .env con: ABUSEIPDB_API_KEY=tu_api_key
"""

import sys
import json
import argparse
import requests
from datetime import datetime
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import os

API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
BASE_URL = 'https://api.abuseipdb.com/api/v2/check'


def check_ip(ip, max_age_days=90, verbose=True):
    """Consulta una IP en AbuseIPDB."""
    if not API_KEY:
        print('[!] ABUSEIPDB_API_KEY no configurada. Crea un .env con la variable.', file=sys.stderr)
        sys.exit(1)

    headers = {
        'Key':    API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress':    ip,
        'maxAgeInDays': max_age_days,
        'verbose':      verbose
    }

    try:
        resp = requests.get(BASE_URL, headers=headers, params=params, timeout=15)
        resp.raise_for_status()
        return resp.json().get('data', {})
    except requests.exceptions.RequestException as e:
        print(f'[!] Error consultando AbuseIPDB: {e}', file=sys.stderr)
        return None


def display_result(ip, data):
    if not data:
        print(f'  [!] Sin resultados para {ip}')
        return

    score = data.get('abuseConfidenceScore', 0)
    color_flag = '[!] MALICIOSA' if score >= 50 else ('[~] SOSPECHOSA' if score >= 10 else '[OK] LIMPIA')

    print(f'  IP            : {ip}')
    print(f'  Resultado     : {color_flag} (Score: {score}/100)')
    print(f'  Pais          : {data.get("countryCode", "N/A")}')
    print(f'  ISP           : {data.get("isp", "N/A")}')
    print(f'  Uso           : {data.get("usageType", "N/A")}')
    print(f'  Reportes      : {data.get("totalReports", 0)}')
    print(f'  Ultimo reporte: {data.get("lastReportedAt", "N/A")}')
    print(f'  Tor node      : {data.get("isTor", False)}')
    print()


def main():
    parser = argparse.ArgumentParser(description='Consulta IPs en AbuseIPDB.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--ip',   type=str, help='IP a consultar')
    group.add_argument('--file', type=str, help='Archivo con lista de IPs (una por linea)')
    parser.add_argument('--days',   type=int, default=90, help='Dias de historial (default: 90)')
    parser.add_argument('--json',   action='store_true', help='Output en JSON')
    parser.add_argument('--output', type=str, help='Exportar a archivo JSON')
    args = parser.parse_args()

    ips = []
    if args.ip:
        ips = [args.ip.strip()]
    elif args.file:
        with open(args.file, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]

    print(f'\n[*] Consultando {len(ips)} IP(s) en AbuseIPDB...\n')

    results = {}
    for ip in ips:
        data = check_ip(ip, max_age_days=args.days)
        results[ip] = data
        display_result(ip, data)

    if args.json or args.output:
        report = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'results':   results
        }
        output = json.dumps(report, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f'[+] Exportado a: {args.output}')
        else:
            print(output)


if __name__ == '__main__':
    main()
