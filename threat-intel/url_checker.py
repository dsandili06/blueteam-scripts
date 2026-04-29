#!/usr/bin/env python3
"""
URL Checker
-----------
Escanea una URL completa en VirusTotal y retorna el resultado del analisis.

Autor: Santiago Daniel Sandili

Uso:
    python url_checker.py --url https://suspicious-site.com/payload
    python url_checker.py --file urls.txt --json

Dependencias:
    pip install requests python-dotenv

Configuracion:
    Crear archivo .env con: VIRUSTOTAL_API_KEY=tu_api_key
"""

import os
import sys
import json
import base64
import argparse
import requests
from datetime import datetime
import time

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

API_KEY   = os.environ.get('VIRUSTOTAL_API_KEY', '')
SCAN_URL  = 'https://www.virustotal.com/api/v3/urls'
ANALYSIS_URL = 'https://www.virustotal.com/api/v3/analyses'


def url_to_id(url):
    """Convierte URL a ID de VirusTotal (base64url sin padding)."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')


def submit_url(url):
    """Envia una URL a VirusTotal para analisis."""
    if not API_KEY:
        print('[!] VIRUSTOTAL_API_KEY no configurada.', file=sys.stderr)
        sys.exit(1)

    headers = {
        'x-apikey':     API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    try:
        resp = requests.post(SCAN_URL, headers=headers, data=f'url={url}', timeout=15)
        resp.raise_for_status()
        return resp.json().get('data', {}).get('id', '')
    except requests.exceptions.RequestException as e:
        print(f'[!] Error enviando URL: {e}', file=sys.stderr)
        return None


def get_url_report(url):
    """Obtiene el reporte existente de una URL por su ID."""
    url_id = url_to_id(url)
    headers = {'x-apikey': API_KEY}
    try:
        resp = requests.get(f'{SCAN_URL}/{url_id}', headers=headers, timeout=15)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        print(f'[!] Error obteniendo reporte: {e}', file=sys.stderr)
        return None


def wait_for_analysis(analysis_id, max_wait=60):
    """Espera a que el analisis se complete."""
    headers = {'x-apikey': API_KEY}
    waited = 0
    while waited < max_wait:
        try:
            resp = requests.get(f'{ANALYSIS_URL}/{analysis_id}', headers=headers, timeout=15)
            data = resp.json()
            status = data.get('data', {}).get('attributes', {}).get('status', '')
            if status == 'completed':
                return data
            time.sleep(5)
            waited += 5
        except Exception:
            time.sleep(5)
            waited += 5
    return None


def display_result(url, data):
    if not data:
        print(f'  [{url[:50]}...] Sin resultados\n')
        return

    attrs     = data.get('data', {}).get('attributes', {})
    stats     = attrs.get('last_analysis_stats', {})
    malicious = stats.get('malicious', 0)
    total     = sum(stats.values())
    final_url = attrs.get('last_final_url', url)
    title     = attrs.get('title', 'N/A')
    categories= attrs.get('categories', {})

    flag = '[!!!] MALICIOSA' if malicious >= 3 else ('[!] SOSPECHOSA' if malicious > 0 else '[OK] LIMPIA')

    print(f'  URL           : {url[:80]}')
    print(f'  Resultado     : {flag}')
    print(f'  Detecciones   : {malicious}/{total}')
    print(f'  URL final     : {final_url[:80]}')
    print(f'  Titulo pagina : {title}')
    if categories:
        print(f'  Categorias    : {", ".join(set(categories.values()))}')

    if malicious > 0:
        results = attrs.get('last_analysis_results', {})
        dets = [(av, r.get('result','')) for av, r in results.items() if r.get('category') == 'malicious'][:5]
        print('  Detecciones:')
        for av, result in dets:
            print(f'    - {av}: {result}')
    print()


def main():
    parser = argparse.ArgumentParser(description='Analiza URLs en VirusTotal.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--url',  type=str, help='URL a analizar')
    group.add_argument('--file', type=str, help='Archivo con lista de URLs')
    parser.add_argument('--submit', action='store_true', help='Enviar URL para nuevo analisis (consume cuota)')
    parser.add_argument('--json',   action='store_true', help='Output en JSON')
    parser.add_argument('--output', type=str, help='Exportar a archivo JSON')
    args = parser.parse_args()

    urls = [args.url.strip()] if args.url else []
    if args.file:
        with open(args.file) as f:
            urls = [l.strip() for l in f if l.strip()]

    print(f'\n[*] Analizando {len(urls)} URL(s) en VirusTotal...\n')

    results = {}
    for url in urls:
        if args.submit:
            print(f'  [*] Enviando {url[:60]} para nuevo analisis...')
            analysis_id = submit_url(url)
            if analysis_id:
                print('  [*] Esperando resultados...')
                data = wait_for_analysis(analysis_id)
            else:
                data = None
        else:
            data = get_url_report(url)

        results[url] = data
        display_result(url, data)

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
