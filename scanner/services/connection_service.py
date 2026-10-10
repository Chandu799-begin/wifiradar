"""Authorized Wi-Fi connection helper.

Design rules enforced here
---------------------------
* Only authenticated, authorized users may request a connection.
* The target SSID must match a network that was actually scanned (prevents
  arbitrary strings from being forwarded anywhere).
* Passwords are held in memory only for the duration of the agent request.
  They are never written to the database, logs, or session storage.
* The shell is never used: the local agent builds a fixed argument list.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from django.conf import settings
from django.contrib.auth.models import User

from ..models import ConnectionLog, WiFiNetwork

logger = logging.getLogger('scanner')

AGENT_TIMEOUT_SECONDS = 10


def can_control_wifi(user: User | None) -> bool:
    """Authorization gate for connect/disconnect operations."""
    if not user or not user.is_authenticated:
        return False
    return bool(user.is_staff or user.is_active and user.has_perm('scanner.control_wifi'))


def agent_base_url() -> str:
    return getattr(settings, 'WIFI_LOCAL_AGENT_URL', 'http://127.0.0.1:8765')


def agent_reachable() -> dict:
    """Ping the local agent to see whether it is running on this machine."""
    url = agent_base_url().rstrip('/') + '/status'
    request = urllib.request.Request(url, method='GET')
    request.add_header('X-Agent-Secret', getattr(settings, 'WIFI_LOCAL_AGENT_SHARED_SECRET', ''))
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            body = json.loads(response.read().decode('utf-8') or '{}')
        return {'reachable': True, **body}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        logger.info('Local agent not reachable: %s', exc)
        return {
            'reachable': False,
            'error': str(exc),
            'hint': 'Start the desktop agent: python local_agent/agent.py',
            'agent_url': agent_base_url(),
        }


def _call_agent(path: str, payload: dict) -> dict:
    """POST JSON to the local agent. The shared secret is sent in a header."""
    url = agent_base_url().rstrip('/') + path
    data = json.dumps(payload).encode('utf-8')
    request = urllib.request.Request(url, data=data, method='POST')
    request.add_header('Content-Type', 'application/json')
    request.add_header('X-Agent-Secret', getattr(settings, 'WIFI_LOCAL_AGENT_SHARED_SECRET', ''))
    try:
        with urllib.request.urlopen(request, timeout=AGENT_TIMEOUT_SECONDS) as response:
            return {'ok': True, 'status': response.status, **json.loads(response.read().decode('utf-8') or '{}')}
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode('utf-8') or '{}')
        except ValueError:
            body = {}
        return {'ok': False, 'status': exc.code, **body}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {'ok': False, 'status': 0, 'error': str(exc)}


def connect(user: User, ssid: str, password: str | None = None) -> dict:
    """Attempt a connection through the local agent. Returns a result dict."""
    if not can_control_wifi(user):
        log_connection(None, ssid, ConnectionLog.STATUS_DENIED, 'User is not authorized.', user=user)
        return {'success': False, 'status': ConnectionLog.STATUS_DENIED,
                'message': 'Not authorized. Local control requires an authorised account.'}

    network = WiFiNetwork.objects.filter(ssid=ssid).order_by('-signal_strength').first()
    if network is None:
        log_connection(None, ssid, ConnectionLog.STATUS_FAILED, 'Unknown network.', user=user)
        return {'success': False, 'status': ConnectionLog.STATUS_FAILED,
                'message': 'Network not found in the latest scan. Refresh and try again.'}

    secured = (network.security_type or '').lower() not in ('open', '', 'owe')
    if secured and not password:
        log_connection(network, ssid, ConnectionLog.STATUS_FAILED, 'Password required.', user=user)
        return {'success': False, 'status': ConnectionLog.STATUS_FAILED,
                'message': 'A password is required for this secured network.', 'password_required': True}
    if not secured:
        password = None

    status = agent_reachable()
    if not status.get('reachable'):
        log_connection(network, ssid, ConnectionLog.STATUS_PENDING_AGENT, 'Agent offline.', user=user)
        return {
            'success': False,
            'status': ConnectionLog.STATUS_PENDING_AGENT,
            'message': (
                'The local connection agent is not running on this machine. '
                'A remote website cannot control your Wi-Fi adapter directly.'
            ),
            'agent': status,
        }

    result = _call_agent('/connect', {'ssid': ssid, 'password': password, 'bssid': network.bssid})
    del password  # explicit: plaintext password lifetime ends here

    if result.get('ok') and result.get('success'):
        network.is_connected = True
        network.save(update_fields=['is_connected', 'last_seen'])
        WiFiNetwork.objects.filter(is_connected=True).exclude(pk=network.pk).update(is_connected=False)
        log_connection(network, ssid, ConnectionLog.STATUS_SUCCESS, str(result.get('message', '')), user=user)
        return {'success': True, 'status': ConnectionLog.STATUS_SUCCESS,
                'message': result.get('message', f'Connected to {ssid}.')}

    detail = str(result.get('error') or result.get('message') or 'Connection failed.')
    log_connection(network, ssid, ConnectionLog.STATUS_FAILED, detail[:250], user=user)
    return {'success': False, 'status': ConnectionLog.STATUS_FAILED, 'message': detail}


def disconnect(user: User) -> dict:
    """Disconnect the current network through the local agent."""
    if not can_control_wifi(user):
        return {'success': False, 'status': ConnectionLog.STATUS_DENIED,
                'message': 'Not authorized. Local control requires an authorised account.'}

    current = WiFiNetwork.objects.filter(is_connected=True).first()
    status = agent_reachable()
    if not status.get('reachable'):
        log_connection(current, current.ssid if current else '', ConnectionLog.STATUS_PENDING_AGENT, 'Agent offline.', user=user)
        return {
            'success': False,
            'status': ConnectionLog.STATUS_PENDING_AGENT,
            'message': 'The local connection agent is not running. Start it to disconnect.',
            'agent': status,
        }

    result = _call_agent('/disconnect', {})
    ssid = current.ssid if current else ''
    if result.get('ok') and result.get('success'):
        WiFiNetwork.objects.filter(is_connected=True).update(is_connected=False)
        log_connection(current, ssid, ConnectionLog.STATUS_DISCONNECTED, str(result.get('message', '')), user=user)
        return {'success': True, 'status': ConnectionLog.STATUS_DISCONNECTED,
                'message': result.get('message', 'Disconnected.')}

    detail = str(result.get('error') or result.get('message') or 'Disconnect failed.')
    log_connection(current, ssid, ConnectionLog.STATUS_FAILED, detail[:250], user=user)
    return {'success': False, 'status': ConnectionLog.STATUS_FAILED, 'message': detail}


def log_connection(
    network: WiFiNetwork | None,
    ssid: str,
    status: str,
    detail: str = '',
    user: User | None = None,
) -> ConnectionLog:
    """Persist an audit entry. Never pass passwords into this function."""
    return ConnectionLog.objects.create(
        network=network,
        ssid=(ssid or '')[:255],
        user=user if (user is not None and user.is_authenticated) else None,
        connection_status=status,
        detail=detail[:255],
    )
