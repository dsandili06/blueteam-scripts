#!/usr/bin/env python3
"""
Domain Checker
--------------
Analiza un dominio contra VirusTotal y obtiene categorias y detecciones.

Autor: Santiago Daniel Sandili

Uso:
    python domain_checker.py --domain evil.example.com
    python domain_checker.py --file domains.txt --json

Dependencias:
    pip install requests python-dotenv

Configuracion:
    Crear archivo .env con: VIRUSTOTAL_API_KEY=tu_api_key
"""

import os
import sys
import json
import argparse
import requests
from datetime import datetime

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

API_KEY  = os.environ.get('VIRUSTOTAL_API_KEY', '')
BASE_URL = 'https://www.virustotal.com/api/v3/domains'


def check_domain(domain):
    if not API_KEY:
        print('[!] VIRUSTOTAL_API_KEY no configurada.', file=sys.stderr)
        sys.exit(1)

    headers = {'x-apikey': API_KEY}
    try:
        resp = requests.get(f'{BASE_URL}/{domain}', headers=headers, timeout=15)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        print(f'[!] Error consultando VirusTotal: {e}', file=sys.stderr)
        return None


def display_result(domain, data):
    if not data:
        print(f'  [{domain}] No encontrado en VirusTotal\n')
        return

    attrs     = data.get('data', {}).get('attributes', {})
    stats     = attrs.get('last_analysis_stats', {})
    malicious = stats.get('malicious', 0)
    total     = sum(stats.values())
    cats      = attrs.get('categories', {})
    creation  = attrs.get('creation_date', 'N/A')
    registrar = attrs.get('registrar', 'N/A')
    reputation= attrs.get('reputation', 0)

    flag = '[!!!] MALICIOSO' if malicious >= 3 else ('[!] SOSPECHOSO' if malicious > 0 else '[OK] LIMPIO')

    print(f'  Dominio       : {domain}')
    print(f'  Resultado     : {flag}')
    print(f'  Detecciones   : {malicious}/{total}')
    print(f'  Reputacion VT : {reputation}')
    print(f'  Registrador   : {registrar}')
    print(f'  Creacion      : {creation}')
    if cats:
        print(f'  Categorias    : {", ".join(set(cats.values()))}')

    if malicious > 0:
        results = attrs.get('last_analysis_results', {})
        dets = [(av, r.get('result','')) for av, r in results.items() if r.get('category') == 'malicious'][:5]
        print('  Top detecciones:')
        for av, result in dets:
            print(f'    - {av}: {result}')
    print()


def main():
    parser = argparse.ArgumentParser(description='Consulta dominios en VirusTotal.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--domain', type=str, help='Dominio a analizar')
    group.add_argument('--file',   type=str, help='Archivo con lista de dominios')
    parser.add_argument('--json',   action='store_true', help='Output en JSON')
    parser.add_argument('--output', type=str, help='Exportar a archivo JSON')
    args = parser.parse_args()

    domains = [args.domain.strip()] if args.domain else []
    if args.file:
        with open(args.file) as f:
            domains = [l.strip() for l in f if l.strip()]

    print(f'\n[*] Consultando {len(domains)} dominio(s) en VirusTotal...\n')

    results = {}
    for d in domains:
        data = check_domain(d)
        results[d] = data
        display_result(d, data)

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
