#!/usr/bin/env python3
"""
Port Scanner
------------
Escanea puertos TCP en un host objetivo para identificar servicios expuestos.

Autor: Santiago Daniel Sandili
MITRE ATT&CK: T1046 - Network Service Discovery

Uso:
    python port_scanner.py --target 192.168.1.10
    python port_scanner.py --target 192.168.1.10 --ports 1-1024
    python port_scanner.py --target 192.168.1.10 --ports 22,80,443,3389 --json
"""

import socket
import json
import argparse
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
    389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 636: 'LDAPS', 993: 'IMAPS',
    995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
    3389: 'RDP', 5432: 'PostgreSQL', 5985: 'WinRM-HTTP',
    5986: 'WinRM-HTTPS', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    27017: 'MongoDB'
}

RISKY_PORTS = {21, 23, 135, 139, 445, 1433, 3389, 5985, 5986}


def scan_port(host, port, timeout=1.0):
    """Intenta conexion TCP al puerto. Retorna True si esta abierto."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def grab_banner(host, port, timeout=2.0):
    """Intenta obtener banner del servicio."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200] if banner else ''
    except Exception:
        return ''


def parse_ports(ports_arg):
    """Parsea argumento de puertos: '22,80,443' o '1-1024'."""
    ports = []
    for part in ports_arg.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def main():
    parser = argparse.ArgumentParser(description='Escanea puertos TCP en un host objetivo.')
    parser.add_argument('--target', required=True, help='IP o hostname objetivo')
    parser.add_argument('--ports',  default='1-1024', help='Puertos a escanear (ej: 22,80,443 o 1-1024)')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout por puerto en segundos (default: 1.0)')
    parser.add_argument('--threads', type=int, default=100, help='Hilos concurrentes (default: 100)')
    parser.add_argument('--banner', action='store_true', help='Intentar capturar banners')
    parser.add_argument('--json',   action='store_true', help='Output en formato JSON')
    parser.add_argument('--output', type=str, help='Exportar resultados a archivo JSON')
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    open_ports = []

    report = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'target':    args.target,
        'ports_scanned': len(ports),
        'open_ports': []
    }

    print(f'\n[*] Escaneando {args.target} ({len(ports)} puertos) con {args.threads} hilos...')

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, args.target, p, args.timeout): p for p in ports}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)

    open_ports.sort()

    for port in open_ports:
        service = COMMON_SERVICES.get(port, 'Unknown')
        banner = grab_banner(args.target, port) if args.banner else ''
        risky = port in RISKY_PORTS
        entry = {
            'port':    port,
            'service': service,
            'banner':  banner,
            'risky':   risky
        }
        report['open_ports'].append(entry)
        flag = ' [!] RIESGOSO' if risky else ''
        print(f'  [OPEN] {port:5d}/tcp  {service:<15}{flag}')
        if banner:
            print(f'         Banner: {banner[:80]}')

    print(f'\n[+] Puertos abiertos: {len(open_ports)} / {len(ports)} escaneados')

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
