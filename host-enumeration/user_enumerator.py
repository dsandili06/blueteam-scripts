#!/usr/bin/env python3
"""
User Enumerator
---------------
Enumera usuarios locales, grupos y privilegios en el host.
Compatible con Windows y Linux.

Autor: Santiago Daniel Sandili
MITRE ATT&CK: T1087 - Account Discovery

Uso:
    python user_enumerator.py
    python user_enumerator.py --json
    python user_enumerator.py --output report.json
"""

import os
import sys
import json
import argparse
import platform
import subprocess
from datetime import datetime


def get_platform():
    return platform.system().lower()


def enumerate_windows_users():
    """Enumera usuarios locales en Windows via WMIC/net."""
    users = []
    try:
        result = subprocess.run(
            ['net', 'user'],
            capture_output=True, text=True, timeout=15
        )
        lines = result.stdout.splitlines()
        in_users = False
        for line in lines:
            if '---' in line:
                in_users = not in_users
                continue
            if in_users and line.strip():
                for name in line.split():
                    if name:
                        detail = get_windows_user_detail(name)
                        users.append(detail)
    except Exception as e:
        print(f'  [!] Error enumerando usuarios Windows: {e}', file=sys.stderr)
    return users


def get_windows_user_detail(username):
    """Obtiene detalles de un usuario Windows."""
    detail = {'username': username, 'platform': 'windows'}
    try:
        result = subprocess.run(
            ['net', 'user', username],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if 'Account active' in line or 'Cuenta activa' in line:
                detail['active'] = 'Yes' in line or 'Yes' in line
            if 'Password last set' in line or 'contrasena' in line.lower():
                detail['password_last_set'] = line.split(None, 3)[-1].strip()
            if 'Last logon' in line or 'ltimo inicio' in line:
                detail['last_logon'] = line.split(None, 2)[-1].strip()
            if 'Local Group Memberships' in line:
                detail['groups'] = line.split('*')[-1].strip()
    except Exception:
        pass
    return detail


def enumerate_linux_users():
    """Enumera usuarios en Linux desde /etc/passwd."""
    users = []
    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) < 7:
                    continue
                uid = int(parts[2])
                shell = parts[6]
                # Usuarios reales o con UID 0
                if uid == 0 or (uid >= 1000 and shell not in ['/sbin/nologin', '/bin/false', '/usr/sbin/nologin']):
                    users.append({
                        'username':    parts[0],
                        'uid':         uid,
                        'gid':         int(parts[3]),
                        'home':        parts[5],
                        'shell':       shell,
                        'platform':    'linux',
                        'privileged':  uid == 0
                    })
    except Exception as e:
        print(f'  [!] Error leyendo /etc/passwd: {e}', file=sys.stderr)
    return users


def get_sudo_users():
    """Obtiene usuarios con privilegios sudo en Linux."""
    sudo_users = []
    try:
        result = subprocess.run(
            ['getent', 'group', 'sudo'],
            capture_output=True, text=True, timeout=10
        )
        if result.stdout:
            members = result.stdout.strip().split(':')[-1]
            sudo_users = [u for u in members.split(',') if u]
    except Exception:
        pass
    return sudo_users


def main():
    parser = argparse.ArgumentParser(description='Enumera usuarios locales del host.')
    parser.add_argument('--json',   action='store_true', help='Mostrar output en JSON')
    parser.add_argument('--output', type=str, help='Exportar resultados a archivo JSON')
    args = parser.parse_args()

    report = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'hostname':  platform.node(),
        'platform':  get_platform(),
        'users':     []
    }

    print('\n[*] Enumerando usuarios locales...', flush=True)

    if get_platform() == 'windows':
        report['users'] = enumerate_windows_users()
    else:
        report['users'] = enumerate_linux_users()
        report['sudo_users'] = get_sudo_users()

    print(f'  [+] Usuarios encontrados: {len(report["users"])}')
    for user in report['users']:
        line = f'  -> {user["username"]}'
        if user.get('privileged') or user.get('groups', '').lower().find('admin') != -1:
            print(f'{line}  [PRIVILEGIADO]')
        else:
            print(line)

    if args.json or args.output:
        output = json.dumps(report, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f'\n[+] Exportado a: {args.output}')
        else:
            print('\n' + output)


if __name__ == '__main__':
    main()
