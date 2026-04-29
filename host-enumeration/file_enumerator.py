#!/usr/bin/env python3
"""
File Enumerator
---------------
Busca archivos sospechosos por extension, ubicacion o fecha de modificacion.
Util para encontrar artefactos maliciosos en un host comprometido.

Autor: Santiago Daniel Sandili
MITRE ATT&CK: T1083 - File and Directory Discovery

Uso:
    python file_enumerator.py --path C:\\Users --ext .ps1 .bat .vbs
    python file_enumerator.py --path /home --days 7
    python file_enumerator.py --path C:\\Temp --all-suspicious
"""

import os
import sys
import json
import hashlib
import argparse
import platform
from datetime import datetime, timedelta
from pathlib import Path

SUSPICIOUS_EXTENSIONS = [
    '.ps1', '.psm1', '.psd1',
    '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
    '.bat', '.cmd',
    '.hta',
    '.dll', '.ocx',
    '.lnk',
    '.scr', '.pif',
    '.jar',
    '.py', '.rb',
]

SUSPICIOUS_PATHS = [
    'temp', 'tmp', 'appdata', 'downloads', 'public', 'programdata',
    'recycle', '$recycle.bin',
]


def compute_md5(filepath, max_size_mb=50):
    """Calcula MD5 de un archivo si no supera el tamano maximo."""
    try:
        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        if size_mb > max_size_mb:
            return 'FILE_TOO_LARGE'
        with open(filepath, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except (PermissionError, OSError):
        return 'ACCESS_DENIED'


def is_suspicious_path(filepath):
    fp_lower = str(filepath).lower()
    return any(sp in fp_lower for sp in SUSPICIOUS_PATHS)


def scan_directory(base_path, extensions=None, days=None, compute_hash=False, all_suspicious=False):
    """Escanea un directorio recursivamente buscando archivos sospechosos."""
    results = []
    base = Path(base_path)
    cutoff = datetime.now() - timedelta(days=days) if days else None
    exts = [e.lower() for e in extensions] if extensions else SUSPICIOUS_EXTENSIONS

    for root, dirs, files in os.walk(base, followlinks=False):
        # Saltar directorios del sistema
        dirs[:] = [d for d in dirs if not d.startswith('.')]

        for filename in files:
            filepath = Path(root) / filename
            ext = filepath.suffix.lower()

            if ext not in exts:
                continue

            try:
                stat = filepath.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime)
                size  = stat.st_size
            except (PermissionError, OSError):
                continue

            if cutoff and mtime < cutoff:
                continue

            susp_path  = is_suspicious_path(filepath)
            susp_entry = all_suspicious or susp_path or ext in SUSPICIOUS_EXTENSIONS

            if not susp_entry:
                continue

            entry = {
                'path':       str(filepath),
                'name':       filename,
                'extension':  ext,
                'size_bytes': size,
                'modified':   mtime.strftime('%Y-%m-%d %H:%M:%S'),
                'susp_path':  susp_path,
                'md5':        compute_md5(str(filepath)) if compute_hash else 'not_computed'
            }
            results.append(entry)

    return results


def main():
    parser = argparse.ArgumentParser(description='Busca archivos sospechosos en el sistema.')
    parser.add_argument('--path',   default='.', help='Directorio base para escanear')
    parser.add_argument('--ext',    nargs='+', help='Extensiones a buscar (ej: .ps1 .vbs .bat)')
    parser.add_argument('--days',   type=int, help='Solo archivos modificados en los ultimos N dias')
    parser.add_argument('--hash',   action='store_true', help='Calcular MD5 de cada archivo')
    parser.add_argument('--all-suspicious', action='store_true', help='Buscar todas las extensiones sospechosas')
    parser.add_argument('--json',   action='store_true', help='Output en JSON')
    parser.add_argument('--output', type=str, help='Exportar resultados a archivo JSON')
    args = parser.parse_args()

    print(f'\n[*] Escaneando: {args.path}')
    if args.days:
        print(f'[*] Filtro: ultimos {args.days} dias')
    if args.ext:
        print(f'[*] Extensiones: {" ".join(args.ext)}')

    findings = scan_directory(
        args.path,
        extensions=args.ext,
        days=args.days,
        compute_hash=args.hash,
        all_suspicious=args.all_suspicious
    )

    for f in findings:
        flag = ' [RUTA SOSPECHOSA]' if f['susp_path'] else ''
        print(f'  [{f["extension"]}] {f["path"]}  ({f["size_bytes"]} bytes){flag}')
        if args.hash:
            print(f'       MD5: {f["md5"]}')

    print(f'\n[+] Archivos encontrados: {len(findings)}')

    report = {
        'timestamp':  datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'scan_path':  args.path,
        'total':      len(findings),
        'files':      findings
    }

    if args.json or args.output:
        output = json.dumps(report, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f'[+] Exportado a: {args.output}')
        else:
            print('\n' + output)


if __name__ == '__main__':
    main()
