"""Windows Wi-Fi scanning via the ``netsh`` WLAN API.

All subprocess invocations use a fixed argument list with no shell interpolation,
so no user input ever reaches a command line.
"""

from __future__ import annotations

import logging
import platform
import re
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger('scanner')

NETSH_TIMEOUT_SECONDS = 12

BSSID_RE = re.compile(r'BSSID\s+\d+\s*:\s*([0-9A-Fa-f:]{17})')
SSID_RE = re.compile(r'^\s*SSID\s+\d+\s*:\s*(.*)$')
SIGNAL_RE = re.compile(r'^\s*Signal\s*:\s*(\d+)\s*%')
AUTH_RE = re.compile(r'^\s*Authentication\s*:\s*(.+)$')
CIPHER_RE = re.compile(r'^\s*Cipher\s*:\s*(.+)$')
BAND_RE = re.compile(r'^\s*Band\s*:\s*(.+)$', re.IGNORECASE)
RADIO_RE = re.compile(r'^\s*Radio\s*:\s*(.+)$', re.IGNORECASE)
CHANNEL_RE = re.compile(r'^\s*Channel\s*:\s*(\d+)')
FREQ_RE = re.compile(r'^\s*Frequency\s*:\s*(\d+)\s*MHz', re.IGNORECASE)
STATE_RE = re.compile(r'^\s*State\s*:\s*(.+)$', re.MULTILINE)
CONNECTED_SSID_RE = re.compile(r'^\s*SSID\s*:\s*(.+)$')


@dataclass
class ScannedNetwork:
    ssid: str = ''
    bssid: str = ''
    signal_strength: int = 0
    security_type: str = 'Open'
    frequency: str = ''
    channel: int | None = None
    is_connected: bool = False
    is_hidden: bool = False
    extra: dict = field(default_factory=dict)


def _run_netsh(args: list[str]) -> tuple[bool, str]:
    """Run a netsh command safely. Returns (ok, stdout+stderr)."""
    try:
        completed = subprocess.run(
            ['netsh', *args],
            capture_output=True,
            timeout=NETSH_TIMEOUT_SECONDS,
            check=False,
            text=True,
            encoding='utf-8',
            errors='replace',
        )
    except FileNotFoundError:
        return False, 'netsh executable not found. Is this a Windows system?'
    except subprocess.TimeoutExpired:
        return False, 'netsh timed out. The WLAN service may be busy.'
    except OSError as exc:
        return False, f'OS error while running netsh: {exc}'
    output = (completed.stdout or '') + (completed.stderr or '')
    return completed.returncode == 0, output.strip()


def _infer_band_and_channel(network: ScannedNetwork, output: str) -> None:
    """Extract band/channel details from the network's own block when present."""
    if network.bssid not in output:
        return
    try:
        idx = output.index(network.bssid)
    except ValueError:
        return
    block = output[idx: idx + 400]
    channel = CHANNEL_RE.search(block)
    if channel and network.channel is None:
        try:
            network.channel = int(channel.group(1))
        except ValueError:
            network.channel = None
    freq = FREQ_RE.search(block)
    if freq:
        network.frequency = f'{freq.group(1)} MHz'
    band = BAND_RE.search(block) or RADIO_RE.search(block)
    if band and not network.frequency:
        network.frequency = band.group(1).strip()


def _clean_ssid(raw: str) -> tuple[str, bool]:
    ssid = raw.rstrip()
    if not ssid.strip():
        return 'Hidden network', True
    return ssid, False


def get_connected_ssid() -> str | None:
    """Return the SSID the adapter is currently associated with, if any."""
    ok, output = _run_netsh(['wlan', 'show', 'interfaces'])
    if not ok:
        return None
    for line in output.splitlines():
        match = CONNECTED_SSID_RE.match(line)
        if match and 'BSSID' not in line:
            ssid = match.group(1).strip()
            if ssid:
                return ssid
    return None


def get_adapter_status() -> dict:
    """Describe the state of the local WLAN adapter(s)."""
    ok, output = _run_netsh(['wlan', 'show', 'interfaces'])
    if not ok:
        return {
            'available': False,
            'connected': False,
            'ssid': None,
            'detail': output or 'Wi-Fi interface information is unavailable.',
        }
    state = STATE_RE.search(output)
    ssid = get_connected_ssid()
    return {
        'available': bool(state) or bool(ssid),
        'connected': bool(ssid),
        'ssid': ssid,
        'state': state.group(1).strip() if state else 'Unknown',
        'detail': 'Windows WLAN interface detected.',
    }


def scan() -> list[ScannedNetwork]:
    """Scan visible networks using ``netsh wlan show networks mode=bssid``."""
    ok, output = _run_netsh(['wlan', 'show', 'networks', 'mode=bssid'])
    if not ok:
        raise RuntimeError(output or 'Unable to scan Wi-Fi networks on Windows.')

    networks: list[ScannedNetwork] = []
    current: ScannedNetwork | None = None
    connected_ssid = get_connected_ssid()
    current_ssid = ''
    hidden = False
    pending_auth = ''

    for line in output.splitlines():
        ssid_match = SSID_RE.match(line)
        if ssid_match:
            if current is not None:
                networks.append(current)
            current = None
            pending_auth = ''
            current_ssid, hidden = _clean_ssid(ssid_match.group(1))
            continue

        bssid_match = BSSID_RE.search(line)
        if bssid_match:
            if current is not None:
                networks.append(current)
            current = ScannedNetwork(
                ssid=current_ssid or 'Hidden network',
                bssid=bssid_match.group(1).upper(),
                security_type=pending_auth or 'Open',
                is_hidden=hidden,
            )
            continue

        if current is None:
            # netsh prints Authentication/Encryption per SSID *before* the
            # BSSID block, so remember it and apply it when BSSIDs appear.
            auth = AUTH_RE.match(line)
            if auth:
                pending_auth = auth.group(1).strip()
            continue

        signal = SIGNAL_RE.match(line)
        if signal:
            try:
                current.signal_strength = max(0, min(100, int(signal.group(1))))
            except ValueError:
                current.signal_strength = 0
            continue

        auth = AUTH_RE.match(line)
        if auth:
            current.security_type = auth.group(1).strip()
            continue

        band = BAND_RE.match(line) or RADIO_RE.match(line)
        if band:
            current.frequency = band.group(1).strip()
            continue

        channel = CHANNEL_RE.match(line)
        if channel:
            try:
                current.channel = int(channel.group(1))
            except ValueError:
                current.channel = None
            continue

        freq = FREQ_RE.match(line)
        if freq:
            current.frequency = f'{freq.group(1)} MHz'

    if current is not None:
        networks.append(current)

    for network in networks:
        if network.channel is None and not network.frequency:
            _infer_band_and_channel(network, output)
        if not network.frequency and network.channel:
            network.frequency = _frequency_for_channel(network.channel)
        if connected_ssid and network.ssid == connected_ssid:
            network.is_connected = True

    deduped = {n.bssid: n for n in networks if n.bssid}
    return list(deduped.values())


def _frequency_for_channel(channel: int) -> str:
    if 1 <= channel <= 14:
        return f'{2407 + channel * 5} MHz' if channel != 14 else '2484 MHz'
    if 32 <= channel <= 177:
        return f'{5000 + channel * 5} MHz'
    if channel >= 32 and channel <= 233:
        return f'{5950 + (channel - 1) * 5} MHz'
    return ''


def platform_name() -> str:
    return platform.system()
