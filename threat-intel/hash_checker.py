#!/usr/bin/env python3
"""
Hash Checker
------------
Verifica un hash MD5/SHA1/SHA256 contra VirusTotal.

Autor: Santiago Daniel Sandili

Uso:
    python hash_checker.py --hash d41d8cd98f00b204e9800998ecf8427e
    python hash_checker.py --file hashes.txt
    python hash_checker.py --scan archivo.exe

Dependencias:
    pip install requests python-dotenv

Configuracion:
    Crear archivo .env con: VIRUSTOTAL_API_KEY=tu_api_key
"""

import os
import sys
import json
import hashlib
import argparse
import requests
from datetime import datetime

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

API_KEY  = os.environ.get('VIRUSTOTAL_API_KEY', '')
BASE_URL = 'https://www.virustotal.com/api/v3/files'


def compute_hash(filepath):
    """Calcula SHA256 de un archivo."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def check_hash(hash_value):
    """Consulta un hash en VirusTotal v3."""
    if not API_KEY:
        print('[!] VIRUSTOTAL_API_KEY no configurada.', file=sys.stderr)
        sys.exit(1)

    headers = {'x-apikey': API_KEY}
    try:
        resp = requests.get(f'{BASE_URL}/{hash_value}', headers=headers, timeout=15)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        print(f'[!] Error: {e}', file=sys.stderr)
        return None


def display_result(hash_val, data):
    if not data:
        print(f'  [{hash_val[:16]}...] No encontrado en VirusTotal')
        return

    attrs    = data.get('data', {}).get('attributes', {})
    stats    = attrs.get('last_analysis_stats', {})
    malicious = stats.get('malicious', 0)
    total    = sum(stats.values())
    names    = attrs.get('meaningful_name', 'N/A')
    vt_type  = attrs.get('type_description', 'N/A')
    size     = attrs.get('size', 0)

    flag = '[!!!] MALICIOSO' if malicious >= 5 else ('[!] SOSPECHOSO' if malicious > 0 else '[OK] LIMPIO')

    print(f'  Hash          : {hash_val}')
    print(f'  Resultado     : {flag}')
    print(f'  Detecciones   : {malicious}/{total}')
    print(f'  Nombre        : {names}')
    print(f'  Tipo          : {vt_type}')
    print(f'  Tamano        : {size} bytes')

    if malicious > 0:
        results = attrs.get('last_analysis_results', {})
        detections = [(av, r['result']) for av, r in results.items() if r.get('category') == 'malicious'][:5]
        print(f'  Top detecciones:')
        for av, result in detections:
            print(f'    - {av}: {result}')
    print()


def main():
    parser = argparse.ArgumentParser(description='Consulta hashes en VirusTotal.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--hash', type=str, help='Hash a consultar (MD5/SHA1/SHA256)')
    group.add_argument('--file', type=str, help='Archivo con lista de hashes')
    group.add_argument('--scan', type=str, help='Archivo local: calcular SHA256 y consultar')
    parser.add_argument('--json',   action='store_true', help='Output en JSON')
    parser.add_argument('--output', type=str, help='Exportar a archivo JSON')
    args = parser.parse_args()

    hashes = []
    if args.hash:
        hashes = [args.hash.strip()]
    elif args.file:
        with open(args.file) as f:
            hashes = [l.strip() for l in f if l.strip()]
    elif args.scan:
        h = compute_hash(args.scan)
        print(f'[*] SHA256 de {args.scan}: {h}')
        hashes = [h]

    print(f'\n[*] Consultando {len(hashes)} hash(es) en VirusTotal...\n')

    results = {}
    for h in hashes:
        data = check_hash(h)
        results[h] = data
        display_result(h, data)

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
