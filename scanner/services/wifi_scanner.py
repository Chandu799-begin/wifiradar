"""Platform-aware Wi-Fi scanning orchestrator.

Responsibilities
----------------
* Pick the right backend (Windows ``netsh``, Linux ``nmcli``, or demo data).
* Cache results briefly so periodic front-end polls do not hammer the OS.
* Persist observed networks and scan history through the Django ORM.
* Never store, log, or transmit Wi-Fi passwords from this module.
"""

from __future__ import annotations

import logging
import platform
import random
import threading
import time
from dataclasses import asdict
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from ..models import ScanHistory, WiFiNetwork
from . import linux_scanner, windows_scanner

logger = logging.getLogger('scanner')

_cache_lock = threading.Lock()
_cache: dict = {'timestamp': 0.0, 'payload': None, 'source': None, 'demo': None}


class WiFiScanError(RuntimeError):
    """Raised when the OS-level scan cannot be performed."""


DEMO_NETWORKS = [
    {'ssid': 'Home_WiFi', 'bssid': 'A4:6B:B5:12:01:01', 'signal_strength': 95, 'security_type': 'WPA2-Personal', 'frequency': '2412 MHz', 'channel': 1},
    {'ssid': 'Office_Network', 'bssid': 'A4:6B:B5:12:01:02', 'signal_strength': 72, 'security_type': 'WPA3-Personal', 'frequency': '5180 MHz', 'channel': 36},
    {'ssid': 'Guest_WiFi', 'bssid': 'A4:6B:B5:12:01:03', 'signal_strength': 45, 'security_type': 'WPA2-Personal', 'frequency': '2437 MHz', 'channel': 6},
    {'ssid': 'CoffeeShop_Free', 'bssid': 'A4:6B:B5:12:01:04', 'signal_strength': 33, 'security_type': 'Open', 'frequency': '2462 MHz', 'channel': 11},
    {'ssid': 'Lab_5G', 'bssid': 'A4:6B:B5:12:01:05', 'signal_strength': 88, 'security_type': 'WPA2-Enterprise', 'frequency': '5745 MHz', 'channel': 149},
    {'ssid': 'Neighbour_2.4', 'bssid': 'A4:6B:B5:12:01:06', 'signal_strength': 27, 'security_type': 'WPA2-Personal', 'frequency': '2412 MHz', 'channel': 1},
    {'ssid': 'IoT_Hub', 'bssid': 'A4:6B:B5:12:01:07', 'signal_strength': 58, 'security_type': 'WPA2-Personal', 'frequency': '2437 MHz', 'channel': 6},
    {'ssid': 'Hidden network', 'bssid': 'A4:6B:B5:12:01:08', 'signal_strength': 41, 'security_type': 'WPA2-Personal', 'frequency': '5200 MHz', 'channel': 40, 'is_hidden': True},
    {'ssid': 'Campus_Eduroam', 'bssid': 'A4:6B:B5:12:01:09', 'signal_strength': 66, 'security_type': 'WPA2-Enterprise', 'frequency': '2462 MHz', 'channel': 11},
    {'ssid': 'Printer_Hotspot', 'bssid': 'A4:6B:B5:12:01:0A', 'signal_strength': 19, 'security_type': 'WPA3-Personal', 'frequency': '5805 MHz', 'channel': 161},
]


def _is_demo_mode(request=None) -> bool:
    if not getattr(settings, 'WIFI_ALLOW_DEMO_MODE', True):
        return False
    if request is not None and request.session.get('demo_mode'):
        return True
    return platform.system() not in ('Windows', 'Linux')


def _live_scan() -> tuple[list[dict], dict]:
    system = platform.system()
    if system == 'Windows':
        raw = windows_scanner.scan()
        adapter = windows_scanner.get_adapter_status()
    elif system == 'Linux':
        if not linux_scanner.available():
            raise WiFiScanError('NetworkManager (nmcli) is not available on this system.')
        raw = linux_scanner.scan()
        adapter = linux_scanner.get_adapter_status()
    else:
        raise WiFiScanError(f'Unsupported operating system: {system or "unknown"}.')
    return [asdict(n) for n in raw], adapter


def _demo_scan() -> tuple[list[dict], dict]:
    now = time.time()
    jitter = random.Random(int(now // 5))
    networks = []
    for entry in DEMO_NETWORKS:
        item = dict(entry)
        item['signal_strength'] = max(
            1, min(100, item['signal_strength'] + jitter.randint(-4, 4))
        )
        item['is_connected'] = item['ssid'] == 'Home_WiFi'
        item.setdefault('is_hidden', False)
        networks.append(item)
    adapter = {'available': True, 'connected': True, 'ssid': 'Home_WiFi', 'state': 'connected', 'detail': 'Demo mode: simulated adapter.'}
    return networks, adapter


def _persist(networks: list[dict], source: str, adapter: dict) -> ScanHistory:
    now = timezone.now()
    seen_bssids = set()
    connected_ssid = ''

    for item in networks:
        seen_bssids.add(item['bssid'])
        if item.get('is_connected'):
            connected_ssid = item.get('ssid', '')
        defaults = {
            'ssid': item.get('ssid') or 'Hidden network',
            'signal_strength': int(item.get('signal_strength') or 0),
            'security_type': item.get('security_type') or 'Open',
            'frequency': item.get('frequency') or '',
            'channel': item.get('channel'),
            'is_connected': bool(item.get('is_connected')),
            'is_hidden': bool(item.get('is_hidden')),
            'last_seen': now,
        }
        WiFiNetwork.objects.update_or_create(bssid=item['bssid'], defaults=defaults)

    stale = WiFiNetwork.objects.exclude(bssid__in=seen_bssids)
    if source == 'live':
        stale.delete()
    elif seen_bssids:
        stale.filter(last_seen__lt=now - timedelta(minutes=30)).delete()

    signals = [int(n.get('signal_strength') or 0) for n in networks] or [0]
    history = ScanHistory.objects.create(
        total_networks=len(networks),
        strongest_signal=max(signals),
        weakest_signal=min(signals),
        connected_ssid=connected_ssid or (adapter.get('ssid') or ''),
        adapter=str(adapter.get('state') or ''),
        source=source,
    )
    stale_ids = list(ScanHistory.objects.values_list('id', flat=True)[500:])
    if stale_ids:
        ScanHistory.objects.filter(id__in=stale_ids).delete()
    return history


def scan(request=None, force: bool = False) -> dict:
    """Run a scan (or serve a cached result) and return a JSON-ready payload."""
    ttl = float(getattr(settings, 'WIFI_SCAN_CACHE_SECONDS', 4))
    now = time.time()
    demo = _is_demo_mode(request)

    with _cache_lock:
        if not force and _cache['payload'] is not None and _cache['demo'] == demo and now - _cache['timestamp'] < ttl:
            payload = dict(_cache['payload'])
            payload['cached'] = True
            return payload

    try:
        if demo:
            raw, adapter = _demo_scan()
            source = 'demo'
        else:
            raw, adapter = _live_scan()
            source = 'live'
    except WiFiScanError as exc:
        logger.warning('Scan failed: %s', exc)
        raise
    except Exception as exc:  # noqa: BLE001 - defensive: OS tooling is unpredictable
        logger.exception('Unexpected scanner failure')
        raise WiFiScanError(str(exc)) from exc

    history = _persist(raw, source, adapter)
    networks = sorted(raw, key=lambda n: -int(n.get('signal_strength') or 0))

    payload = {
        'networks': networks,
        'adapter': adapter,
        'source': source,
        'scan': history.to_dict(),
        'demo_mode': demo,
        'cached': False,
        'scanned_at': timezone.now().isoformat(),
        'disclaimer': 'Radar positions are illustrative. Signal strength does not reveal real-world location or direction.',
    }

    with _cache_lock:
        _cache.update({'timestamp': time.time(), 'payload': payload, 'demo': demo})

    return payload


def connected_network() -> dict | None:
    network = WiFiNetwork.objects.filter(is_connected=True).order_by('-signal_strength').first()
    return network.to_dict() if network else None


def adapter_status(request=None) -> dict:
    demo = _is_demo_mode(request)
    try:
        if demo:
            return {**_demo_scan()[1], 'demo_mode': True}
        if platform.system() == 'Windows':
            return {**windows_scanner.get_adapter_status(), 'demo_mode': False}
        if platform.system() == 'Linux':
            return {**linux_scanner.get_adapter_status(), 'demo_mode': False}
        return {'available': False, 'connected': False, 'ssid': None, 'detail': 'Unsupported OS.', 'demo_mode': False}
    except Exception as exc:  # noqa: BLE001
        return {'available': False, 'connected': False, 'ssid': None, 'detail': str(exc), 'demo_mode': demo}
