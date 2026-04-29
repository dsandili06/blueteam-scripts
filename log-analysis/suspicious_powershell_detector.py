#!/usr/bin/env python3
"""
Suspicious PowerShell Detector
-------------------------------
Detecta comandos PowerShell ofuscados o sospechosos en logs de Windows.
Analiza archivos de texto, .evtx o stdin buscando patrones de evasion.

Autor: Santiago Daniel Sandili
MITRE ATT&CK: T1059.001 - PowerShell | T1027 - Obfuscated Files or Information

Uso:
    python suspicious_powershell_detector.py --file powershell_log.txt
    python suspicious_powershell_detector.py --file Security.evtx --evtx
    python suspicious_powershell_detector.py --stdin < commands.txt
"""

import re
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

# Patrones de comportamiento sospechoso en PowerShell
SUSPICIOUS_PATTERNS = {
    'Encoded Command':         r'-[Ee]nc(odedCommand)?\s+[A-Za-z0-9+/=]{20,}',
    'Bypass Execution Policy': r'-[Ee]xec(utionPolicy)?\s+(bypass|unrestricted|remotesigned)',
    'Hidden Window':           r'-(W|Window)\s*(H|Hidden)|(-NonInteractive)',
    'DownloadString':          r'(DownloadString|DownloadFile|WebClient|Invoke-WebRequest|iwr|curl|wget)',
    'Invoke Expression':       r'\bIEX\b|Invoke-Expression',
    'Base64 Decode':           r'FromBase64String|base64|\[System\.Text\.Encoding\]::UTF8',
    'Reflection / Assembly':   r'Reflection\.Assembly|\[System\.Reflection',
    'Process Injection':       r'VirtualAlloc|WriteProcessMemory|CreateThread|NtAllocateVirtualMemory',
    'Credential Dumping':      r'sekurlsa|lsass|mimikatz|credential|Get-Credential|ConvertTo-SecureString',
    'AMSI Bypass':             r'amsiInitFailed|Invoke-Bypass|Disable-Amsi|amsi\.dll',
    'Nishang / Empire':        r'Invoke-PowerShellTcp|Invoke-Mimikatz|PowerSploit|Get-Information',
    'Net Download':            r'Net\.WebClient|System\.Net\.Http|Start-BitsTransfer',
    'Registry Modification':   r'Set-ItemProperty.*HKLM|reg add|RegWrite',
    'Compression / Expand':    r'IO\.Compression|GZipStream|DeflateStream|Expand-Archive',
    'String Concatenation Obf':r"'[a-z]'\s*\+\s*'[a-z]'",
    'Long Base64 String':      r'[A-Za-z0-9+/]{100,}={0,2}',
}

SEVERITY = {
    'Encoded Command':         'HIGH',
    'Bypass Execution Policy': 'HIGH',
    'Invoke Expression':       'HIGH',
    'AMSI Bypass':             'CRITICAL',
    'Process Injection':       'CRITICAL',
    'Credential Dumping':      'CRITICAL',
    'Nishang / Empire':        'CRITICAL',
    'DownloadString':          'MEDIUM',
    'Base64 Decode':           'MEDIUM',
    'Reflection / Assembly':   'MEDIUM',
    'Net Download':            'MEDIUM',
    'Registry Modification':   'MEDIUM',
    'Hidden Window':           'LOW',
    'Compression / Expand':    'LOW',
    'String Concatenation Obf':'LOW',
    'Long Base64 String':      'LOW',
}

SEVERITY_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}


def analyze_line(line, line_number):
    """Analiza una linea en busca de patrones sospechosos."""
    hits = []
    for pattern_name, regex in SUSPICIOUS_PATTERNS.items():
        if re.search(regex, line, re.IGNORECASE):
            hits.append({
                'pattern':  pattern_name,
                'severity': SEVERITY.get(pattern_name, 'MEDIUM')
            })
    return hits


def analyze_text(lines):
    """Analiza una lista de lineas. Retorna lista de hallazgos."""
    findings = []
    for i, line in enumerate(lines, 1):
        hits = analyze_line(line, i)
        if hits:
            max_sev = max(hits, key=lambda h: SEVERITY_ORDER.get(h['severity'], 0))
            findings.append({
                'line_number': i,
                'line':        line.strip()[:300],
                'hits':        hits,
                'max_severity': max_sev['severity']
            })
    return findings


SEV_COLORS = {
    'CRITICAL': '\033[91m',
    'HIGH':     '\033[93m',
    'MEDIUM':   '\033[33m',
    'LOW':      '\033[37m',
    'RESET':    '\033[0m'
}


def print_finding(finding, use_color=True):
    sev   = finding['max_severity']
    color = SEV_COLORS.get(sev, '') if use_color else ''
    reset = SEV_COLORS['RESET'] if use_color else ''
    patterns = ', '.join(h['pattern'] for h in finding['hits'])
    print(f"{color}  [{sev}] Linea {finding['line_number']}: {patterns}{reset}")
    print(f"         {finding['line'][:120]}")


def main():
    parser = argparse.ArgumentParser(description='Detecta comandos PowerShell sospechosos en logs.')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--file',  type=str, help='Archivo de log a analizar (.txt o .evtx)')
    source.add_argument('--stdin', action='store_true', help='Leer desde stdin')
    parser.add_argument('--evtx',   action='store_true', help='Parsear como archivo .evtx')
    parser.add_argument('--min-severity', choices=['LOW','MEDIUM','HIGH','CRITICAL'],
                        default='LOW', help='Severidad minima a reportar')
    parser.add_argument('--json',   action='store_true', help='Output en JSON')
    parser.add_argument('--output', type=str, help='Exportar resultados a archivo')
    args = parser.parse_args()

    lines = []

    if args.stdin:
        lines = sys.stdin.readlines()
    elif args.evtx:
        try:
            import Evtx.Evtx as evtx
            with evtx.Evtx(args.file) as log:
                for record in log.records():
                    lines.append(record.xml())
        except ImportError:
            print('[!] Instala python-evtx: pip install python-evtx', file=sys.stderr)
            sys.exit(1)
    else:
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

    print(f'\n[*] Analizando {len(lines)} lineas...\n')

    findings = analyze_text(lines)

    min_order = SEVERITY_ORDER.get(args.min_severity, 1)
    findings  = [f for f in findings if SEVERITY_ORDER.get(f['max_severity'], 0) >= min_order]

    sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev_counts[f['max_severity']] = sev_counts.get(f['max_severity'], 0) + 1
        print_finding(f)

    print(f'\n[+] Hallazgos: {len(findings)}')
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if sev_counts[sev] > 0:
            print(f'  {sev}: {sev_counts[sev]}')

    if args.json or args.output:
        report = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source':    args.file or 'stdin',
            'total':     len(findings),
            'severity_summary': sev_counts,
            'findings':  findings
        }
        output = json.dumps(report, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f'[+] Exportado a: {args.output}')
        else:
            print('\n' + output)


if __name__ == '__main__':
    main()
