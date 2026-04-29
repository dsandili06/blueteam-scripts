#!/usr/bin/env python3
"""
Event Log Parser
----------------
Parsea Windows Event Logs (.evtx) y extrae eventos por EventID.
Requiere la libreria python-evtx o acceso via wevtutil en Windows.

Autor: Santiago Daniel Sandili
MITRE ATT&CK: T1078 - Valid Accounts | T1053 - Scheduled Task

Uso:
    python event_log_parser.py --file Security.evtx --eventid 4624 4625
    python event_log_parser.py --file System.evtx --eventid 7045 --json
    python event_log_parser.py --live Security --eventid 4624 4625 4648

Dependencias:
    pip install python-evtx lxml
"""

import sys
import json
import argparse
import platform
from datetime import datetime
from pathlib import Path

INTERESTING_EVENTIDS = {
    4624: 'Logon exitoso',
    4625: 'Logon fallido',
    4648: 'Logon con credenciales explicitas',
    4672: 'Privilegios especiales asignados',
    4688: 'Proceso creado',
    4698: 'Tarea programada creada',
    4699: 'Tarea programada eliminada',
    4702: 'Tarea programada modificada',
    4720: 'Cuenta de usuario creada',
    4726: 'Cuenta de usuario eliminada',
    4732: 'Miembro agregado a grupo local',
    7034: 'Servicio termino inesperadamente',
    7045: 'Servicio instalado',
    1102: 'Log de auditoria borrado',
    4616: 'Hora del sistema modificada',
}


def parse_evtx_file(filepath, target_ids):
    """Parsea un archivo .evtx usando python-evtx."""
    try:
        import Evtx.Evtx as evtx
        import xml.etree.ElementTree as ET
    except ImportError:
        print('[!] Instala python-evtx: pip install python-evtx lxml', file=sys.stderr)
        sys.exit(1)

    events = []
    ns = 'http://schemas.microsoft.com/win/2004/08/events/event'

    with evtx.Evtx(filepath) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                root = ET.fromstring(xml_str)

                system  = root.find(f'{{{ns}}}System')
                event_id = int(system.find(f'{{{ns}}}EventID').text)

                if target_ids and event_id not in target_ids:
                    continue

                time_created = system.find(f'{{{ns}}}TimeCreated').attrib.get('SystemTime', '')
                computer     = system.find(f'{{{ns}}}Computer').text
                channel      = system.find(f'{{{ns}}}Channel').text

                event_data_elem = root.find(f'{{{ns}}}EventData')
                event_data = {}
                if event_data_elem is not None:
                    for data in event_data_elem.findall(f'{{{ns}}}Data'):
                        name  = data.attrib.get('Name', 'Unknown')
                        value = data.text or ''
                        event_data[name] = value

                events.append({
                    'EventID':      event_id,
                    'Description':  INTERESTING_EVENTIDS.get(event_id, 'Evento personalizado'),
                    'TimeCreated':  time_created,
                    'Computer':     computer,
                    'Channel':      channel,
                    'EventData':    event_data
                })

            except Exception:
                continue

    return events


def query_live_log_windows(channel, target_ids):
    """Consulta el log en vivo usando wevtutil (solo Windows)."""
    import subprocess
    events = []
    
    id_query = ' or '.join([f'EventID={eid}' for eid in target_ids]) if target_ids else 'EventID>0'
    xpath = f"*[System[{id_query}]]"
    
    try:
        result = subprocess.run(
            ['wevtutil', 'qe', channel, f'/q:{xpath}', '/f:xml', '/c:500'],
            capture_output=True, text=True, timeout=30
        )
        # Parsear XML de salida de wevtutil
        import xml.etree.ElementTree as ET
        ns = 'http://schemas.microsoft.com/win/2004/08/events/event'
        
        for line in result.stdout.split('</Event>'):
            line = line.strip()
            if not line:
                continue
            try:
                root = ET.fromstring(line + '</Event>')
                system = root.find(f'{{{ns}}}System')
                event_id = int(system.find(f'{{{ns}}}EventID').text)
                time_created = system.find(f'{{{ns}}}TimeCreated').attrib.get('SystemTime', '')
                
                event_data_elem = root.find(f'{{{ns}}}EventData')
                event_data = {}
                if event_data_elem is not None:
                    for data in event_data_elem.findall(f'{{{ns}}}Data'):
                        name = data.attrib.get('Name', 'Unknown')
                        event_data[name] = data.text or ''
                
                events.append({
                    'EventID':     event_id,
                    'Description': INTERESTING_EVENTIDS.get(event_id, ''),
                    'TimeCreated': time_created,
                    'EventData':   event_data
                })
            except Exception:
                continue
    except Exception as e:
        print(f'[!] Error ejecutando wevtutil: {e}', file=sys.stderr)

    return events


def main():
    parser = argparse.ArgumentParser(description='Parsea Windows Event Logs.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--file', type=str, help='Archivo .evtx a parsear')
    group.add_argument('--live', type=str, help='Canal de log en vivo (ej: Security, System)')
    parser.add_argument('--eventid', type=int, nargs='+', help='EventIDs a filtrar')
    parser.add_argument('--json',    action='store_true', help='Output en JSON')
    parser.add_argument('--output',  type=str, help='Exportar a archivo JSON')
    args = parser.parse_args()

    target_ids = set(args.eventid) if args.eventid else set()

    print(f'\n[*] EventIDs objetivo: {sorted(target_ids) if target_ids else "todos"}\n')

    if args.file:
        events = parse_evtx_file(args.file, target_ids)
    else:
        events = query_live_log_windows(args.live, target_ids)

    for ev in events:
        desc = INTERESTING_EVENTIDS.get(ev['EventID'], '')
        print(f'  [{ev["EventID"]}] {ev["TimeCreated"]}  {desc}')
        for k, v in ev.get('EventData', {}).items():
            if v and k in ('SubjectUserName', 'TargetUserName', 'ProcessName', 'CommandLine', 'IpAddress', 'ServiceName', 'ImagePath'):
                print(f'         {k}: {v}')

    print(f'\n[+] Eventos encontrados: {len(events)}')

    if args.json or args.output:
        report = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source':    args.file or args.live,
            'total':     len(events),
            'events':    events
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
