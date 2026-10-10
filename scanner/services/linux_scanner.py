"""Linux Wi-Fi scanning via NetworkManager's ``nmcli`` tool.

No shell is used: every call passes a fixed argument list, so no user input
can reach the command line.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess

from .windows_scanner import ScannedNetwork

logger = logging.getLogger('scanner')

NMCLI_TIMEOUT_SECONDS = 12

# IN-USE,SSID,BSSID,SIGNAL,SECURITY,CHAN,FREQ fields
NMCLI_FIELDS = 'IN-USE,SSID,BSSID,SIGNAL,SECURITY,CHAN,FREQ'


def available() -> bool:
    return shutil.which('nmcli') is not None


def _run_nmcli(args: list[str]) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            ['nmcli', *args],
            capture_output=True,
            timeout=NMCLI_TIMEOUT_SECONDS,
            check=False,
            text=True,
            encoding='utf-8',
            errors='replace',
        )
    except FileNotFoundError:
        return False, 'nmcli executable not found. NetworkManager is required.'
    except subprocess.TimeoutExpired:
        return False, 'nmcli timed out.'
    except OSError as exc:
        return False, f'OS error while running nmcli: {exc}'
    output = (completed.stdout or '') + (completed.stderr or '')
    return completed.returncode == 0, output.strip()


def get_adapter_status() -> dict:
    ok, output = _run_nmcli(['-t', '-f', 'STATE', 'general'])
    if not ok:
        return {'available': False, 'connected': False, 'ssid': None, 'detail': output}
    state = output.strip()
    connected_ssid = None
    ok2, wifi = _run_nmcli(['-t', '-f', 'ACTIVE,SSID', 'dev', 'wifi'])
    if ok2:
        for line in wifi.splitlines():
            parts = line.split(':', 1)
            if len(parts) == 2 and parts[0] == 'yes' and parts[1]:
                connected_ssid = parts[1]
                break
    return {
        'available': state == 'connected',
        'connected': connected_ssid is not None,
        'ssid': connected_ssid,
        'state': state,
        'detail': 'NetworkManager interface detected.',
    }


def scan() -> list[ScannedNetwork]:
    if not available():
        raise RuntimeError('nmcli is not installed. Install NetworkManager to scan on Linux.')

    ok, output = _run_nmcli(['-f', NMCLI_FIELDS, 'dev', 'wifi', 'list', '--rescan', 'auto'])
    if not ok:
        raise RuntimeError(output or 'Unable to scan Wi-Fi networks on Linux.')

    networks: list[ScannedNetwork] = []
    seen: set[str] = set()

    for line in output.splitlines():
        parts = _split_nmcli_line(line)
        if len(parts) < 4:
            continue
        in_use, ssid, bssid = parts[0], parts[1], parts[2]
        signal_raw = parts[3]
        security = parts[4] if len(parts) > 4 else ''
        channel_raw = parts[5] if len(parts) > 5 else ''
        freq_raw = parts[6] if len(parts) > 6 else ''

        bssid = bssid.strip().upper()
        if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', bssid) or bssid in seen:
            continue
        seen.add(bssid)

        try:
            signal = max(0, min(100, int(float(signal_raw))))
        except (TypeError, ValueError):
            signal = 0

        hidden = not ssid.strip()
        try:
            channel = int(channel_raw) if channel_raw.strip().isdigit() else None
        except ValueError:
            channel = None

        networks.append(
            ScannedNetwork(
                ssid=ssid.strip() if not hidden else 'Hidden network',
                bssid=bssid,
                signal_strength=signal,
                security_type=(security.strip() or 'Open'),
                frequency=freq_raw.strip(),
                channel=channel,
                is_connected=in_use.strip() == '*',
                is_hidden=hidden,
            )
        )

    return networks


def _split_nmcli_line(line: str) -> list[str]:
    """Split an nmcli terse line, honouring backslash-escaped separators."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == ':':
            fields.append(''.join(current))
            current = []
        else:
            current.append(char)
    fields.append(''.join(current))
    return fields


def get_connected_ssid() -> str | None:
    status = get_adapter_status()
    return status.get('ssid')
