"""Saved Wi-Fi profile inspection for Windows.

Responsibilities
----------------
* List the Wi-Fi profiles saved on the *local* computer using
  ``netsh wlan show profiles`` and ``netsh wlan show profile name=...``.
* Reveal a single saved key on explicit demand using
  ``netsh wlan show profile name=... key=clear``.

Hard security rules
-------------------
* Every OS call is a fixed argument list executed with ``shell=False``; no
  user text is ever interpolated into a command line.
* A profile name is only accepted if it is present in the locally enumerated
  profile list, so callers cannot probe arbitrary profile names.
* The revealed key is returned to the caller (which hands it straight to the
  browser) and is NEVER logged, cached on disk, persisted to the database, or
  written to a file.
* This module only runs on the machine that owns the adapter. On other
  platforms it reports that the feature is unavailable (or demo data when
  demo mode is enabled).
"""

from __future__ import annotations

import logging
import platform
import re
import subprocess
import threading
import time

from django.conf import settings

from ..models import SavedWiFiProfile

logger = logging.getLogger('scanner')

NETSH_TIMEOUT_SECONDS = 12
MAX_PROFILE_NAME_LENGTH = 255

_INTERFACE_RE = re.compile(r'^\s*Profiles on interface\s+(.+?)\s*:\s*$', re.IGNORECASE)
_PROFILE_ROW_RE = re.compile(r'^\s*All User Profile\s*:\s*(.+?)\s*$')
_NAME_RE = re.compile(r'^\s*Name\s*:\s*(.+?)\s*$')
_AUTH_RE = re.compile(r'^\s*Authentication\s*:\s*(.+?)\s*$')
_SECURITY_KEY_RE = re.compile(r'^\s*Security key\s*:\s*(.+?)\s*$')
_KEY_CONTENT_RE = re.compile(r'^\s*Key Content\s*:\s?(.*)$')

# Demo profiles are only used when demo mode is enabled and mirror the
# simulated nearby networks so the dashboard is functional off-Windows.
DEMO_SAVED_PROFILES = [
    {'name': 'Home_WiFi', 'security': 'WPA2-Personal', 'has_key_material': True, 'is_connected': True, 'interface': 'Wi-Fi'},
    {'name': 'Office_Network', 'security': 'WPA3-Personal', 'has_key_material': True, 'is_connected': False, 'interface': 'Wi-Fi'},
    {'name': 'Guest_WiFi', 'security': 'WPA2-Personal', 'has_key_material': True, 'is_connected': False, 'interface': 'Wi-Fi'},
    {'name': 'CoffeeShop_Free', 'security': 'Open', 'has_key_material': False, 'is_connected': False, 'interface': 'Wi-Fi'},
]
DEMO_PASSWORD = 'Radar-Demo-1234'

_cache_lock = threading.Lock()
_cache: dict = {'timestamp': 0.0, 'profiles': None, 'source': None}


class WiFiProfileError(RuntimeError):
    """Raised when saved profiles cannot be enumerated on this machine."""


def is_windows() -> bool:
    return platform.system() == 'Windows'


def demo_enabled() -> bool:
    return bool(getattr(settings, 'WIFI_ALLOW_DEMO_MODE', True)) and not is_windows()


def can_view_passwords(user) -> bool:
    """Authorization gate for revealing saved passwords.

    Requires an authenticated account that is either a site/system
    administrator (``is_staff``) or explicitly granted the
    ``scanner.view_wifi_passwords`` permission.
    """
    if not user or not user.is_authenticated:
        return False
    return bool(user.is_staff or user.has_perm('scanner.view_wifi_passwords'))


# ---------------------------------------------------------------------------
# netsh plumbing
# ---------------------------------------------------------------------------

def _decode(raw: bytes) -> str:
    """Decode netsh output, which is not always UTF-8 on Windows consoles."""
    import locale

    candidates = ['utf-8']
    try:
        preferred = locale.getpreferredencoding(False)
        if preferred:
            candidates.append(preferred)
    except Exception:  # noqa: BLE001 - locale probing is best-effort
        pass
    candidates.append('cp437')
    for encoding in candidates:
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode('utf-8', errors='replace')


def _run_netsh(args: list[str]) -> tuple[bool, str]:
    """Run a netsh command as an argument list. Returns (ok, combined output)."""
    try:
        completed = subprocess.run(
            ['netsh', *args],
            capture_output=True,
            timeout=NETSH_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return False, 'netsh executable not found. Is this a Windows system?'
    except subprocess.TimeoutExpired:
        return False, 'netsh timed out. The WLAN service may be busy.'
    except OSError as exc:
        return False, f'OS error while running netsh: {exc}'
    output = _decode(completed.stdout or b'') + _decode(completed.stderr or b'')
    return completed.returncode == 0, output.strip()


def _current_connected_ssid() -> str:
    ok, output = _run_netsh(['wlan', 'show', 'interfaces'])
    if not ok:
        return ''
    for line in output.splitlines():
        if 'BSSID' in line:
            continue
        match = re.match(r'^\s*SSID\s*:\s*(.+?)\s*$', line)
        if match and match.group(1).strip():
            return match.group(1).strip()
    return ''


def _enumerate_profile_names() -> list[dict]:
    ok, output = _run_netsh(['wlan', 'show', 'profiles'])
    if not ok:
        raise WiFiProfileError(output or 'Unable to list saved Wi-Fi profiles.')

    profiles: list[dict] = []
    seen: set[str] = set()
    interface = ''
    for line in output.splitlines():
        interface_match = _INTERFACE_RE.match(line)
        if interface_match:
            interface = interface_match.group(1).strip()
            continue
        row_match = _PROFILE_ROW_RE.match(line)
        if not row_match:
            continue
        name = row_match.group(1).strip()
        if not name or name.lower() == '<none>' or name in seen:
            continue
        seen.add(name)
        profiles.append({'name': name, 'interface': interface})
    return profiles


def _profile_details(name: str) -> dict:
    """Fetch a profile's security settings without requesting the key."""
    ok, output = _run_netsh(['wlan', 'show', 'profile', f'name={name}'])
    if not ok:
        return {'security': '', 'has_key_material': False, 'found': False}
    security = ''
    has_key = False
    found = False
    for line in output.splitlines():
        if _NAME_RE.match(line):
            found = True
        auth = _AUTH_RE.match(line)
        if auth:
            security = auth.group(1).strip()
            continue
        key = _SECURITY_KEY_RE.match(line)
        if key:
            has_key = key.group(1).strip().lower() == 'present'
    return {'security': security, 'has_key_material': has_key, 'found': found}


def _persist(profiles: list[dict]) -> None:
    """Store descriptive metadata only. No key material is ever written."""
    for item in profiles:
        SavedWiFiProfile.objects.update_or_create(
            name=item['name'],
            defaults={
                'security': item.get('security') or '',
                'has_key_material': bool(item.get('has_key_material')),
                'is_connected': bool(item.get('is_connected')),
                'interface': item.get('interface') or '',
            },
        )
    names = [item['name'] for item in profiles]
    if names:
        SavedWiFiProfile.objects.exclude(name__in=names).delete()
    else:
        SavedWiFiProfile.objects.all().delete()


def list_saved_profiles(force: bool = False) -> dict:
    """Return ``{'profiles': [...], 'source': 'live'|'demo'}`` metadata only."""
    ttl = float(getattr(settings, 'WIFI_PROFILE_CACHE_SECONDS', 10))
    now = time.time()

    with _cache_lock:
        if (
            not force
            and _cache['profiles'] is not None
            and now - _cache['timestamp'] < ttl
        ):
            return {'profiles': [dict(p) for p in _cache['profiles']], 'source': _cache['source'], 'cached': True}

    if not is_windows():
        if demo_enabled():
            profiles = [dict(p) for p in DEMO_SAVED_PROFILES]
            _persist(profiles)
            result = {'profiles': profiles, 'source': 'demo', 'cached': False,
                      'message': 'Demo mode: simulated saved profiles.'}
            with _cache_lock:
                _cache.update({'timestamp': now, 'profiles': profiles, 'source': 'demo'})
            return result
        return {'profiles': [], 'source': 'unavailable', 'cached': False,
                'message': 'Saved Wi-Fi profiles are only available on Windows.'}

    try:
        connected = _current_connected_ssid()
        profiles = []
        for entry in _enumerate_profile_names():
            details = _profile_details(entry['name'])
            if not details['found']:
                continue
            profiles.append({
                'name': entry['name'],
                'security': details['security'] or 'Open',
                'has_key_material': details['has_key_material'],
                'is_connected': bool(connected) and entry['name'] == connected,
                'interface': entry['interface'],
            })
    except WiFiProfileError:
        raise
    except Exception as exc:  # noqa: BLE001 - OS tooling is unpredictable
        logger.exception('Unexpected saved-profile enumeration failure')
        raise WiFiProfileError(str(exc)) from exc

    _persist(profiles)
    with _cache_lock:
        _cache.update({'timestamp': now, 'profiles': profiles, 'source': 'live'})
    return {'profiles': profiles, 'source': 'live', 'cached': False}


def profile_exists(name: str) -> bool:
    """Validate a caller-supplied profile name against the local profile list."""
    if not name or len(name) > MAX_PROFILE_NAME_LENGTH or '\x00' in name:
        return False
    try:
        data = list_saved_profiles()
    except WiFiProfileError:
        return False
    return any(profile['name'] == name for profile in data['profiles'])


def reveal_profile_key(name: str) -> dict:
    """Reveal a single saved key on demand.

    Returns a dict with ``status`` in
    ``{'ok', 'no_key', 'denied', 'unavailable', 'invalid'}``. The key is only
    present for ``status == 'ok'`` and is never logged.
    """
    if not name or len(name) > MAX_PROFILE_NAME_LENGTH or '\x00' in name:
        return {'status': 'invalid', 'message': 'Invalid profile name.'}

    if not is_windows():
        if demo_enabled():
            if not any(p['name'] == name for p in DEMO_SAVED_PROFILES):
                return {'status': 'invalid', 'message': 'That saved profile does not exist.'}
            profile = next(p for p in DEMO_SAVED_PROFILES if p['name'] == name)
            if not profile['has_key_material']:
                return {'status': 'no_key', 'message': 'This network is open and has no saved password.'}
            return {'status': 'ok', 'password': DEMO_PASSWORD, 'demo': True,
                    'message': 'Demo mode: simulated password (not a real key).'}
        return {'status': 'unavailable',
                'message': 'Saved passwords can only be read on Windows.'}

    if not profile_exists(name):
        return {'status': 'invalid', 'message': 'That saved profile does not exist on this machine.'}

    ok, output = _run_netsh(['wlan', 'show', 'profile', f'name={name}', 'key=clear'])
    if not ok:
        return {'status': 'unavailable',
                'message': output or 'Windows could not read this profile.'}

    key = ''
    key_absent = False
    for line in output.splitlines():
        content = _KEY_CONTENT_RE.match(line)
        if content:
            key = content.group(1).rstrip()
            continue
        security_key = _SECURITY_KEY_RE.match(line)
        if security_key and security_key.group(1).strip().lower() in ('absent', 'no'):
            key_absent = True

    if key:
        return {'status': 'ok', 'password': key, 'demo': False}
    if key_absent:
        return {'status': 'no_key',
                'message': 'Windows reports this profile has no saved password (open network).'}
    return {'status': 'denied',
            'message': (
                'Windows did not return the key content. This is usually an enterprise '
                '(802.1X/PEAP) or certificate profile whose key cannot be read this way.'
            )}


def invalidate_cache() -> None:
    with _cache_lock:
        _cache.update({'timestamp': 0.0, 'profiles': None, 'source': None})
