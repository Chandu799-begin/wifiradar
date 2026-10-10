#!/usr/bin/env python
"""Local Wi-Fi connection agent.

Runs on the visitor's own computer, binds to 127.0.0.1 only, and executes
Wi-Fi connect/disconnect operations on behalf of the local Django site.

Security properties
-------------------
* Localhost-only binding.
* Shared-secret header required on every mutating request.
* No shell is ever used; all OS calls are fixed argument lists.
* SSID must match a conservative character whitelist (max 253 chars).
* Passwords live in memory only; the Windows profile XML is written with
  restrictive permissions and deleted immediately after use.
* Passwords are never logged.

Usage:
    python local_agent/agent.py [--port 8765] [--secret SECRET]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import re
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.sax.saxutils import escape

DEFAULT_PORT = 8765
DEFAULT_SECRET = os.environ.get(
    'WIFI_AGENT_SECRET', 'change-me-local-agent-secret'
)

SSID_RE = re.compile(r'^[\x20-\x7E]{1,253}$')
MAX_PASSWORD_LENGTH = 64

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
)
logger = logging.getLogger('wifi-agent')

SECRET = DEFAULT_SECRET
COMMAND_TIMEOUT = 30


def _run(args: list[str], timeout: int = COMMAND_TIMEOUT) -> tuple[bool, str]:
    """Run a command as an argument list (no shell). Returns (ok, output)."""
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            check=False,
            text=True,
            encoding='utf-8',
            errors='replace',
        )
    except FileNotFoundError:
        return False, f'{args[0]} not found on this system.'
    except subprocess.TimeoutExpired:
        return False, 'Command timed out.'
    except OSError as exc:
        return False, f'OS error: {exc}'
    output = ((completed.stdout or '') + (completed.stderr or '')).strip()
    return completed.returncode == 0, output


# ---------------------------------------------------------------------------
# Windows implementation (netsh)
# ---------------------------------------------------------------------------

def _windows_profile_xml(ssid: str, password: str | None) -> str:
    if password:
        security = """
        <security>
            <authEncryption>
                <auth>WPA2PSK</auth>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{key}</keyMaterial>
            </sharedKey>
        </security>""".format(key=escape(password))
    else:
        security = """
        <security>
            <authEncryption>
                <auth>open</auth>
                <encryption>none</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>"""
    return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{escape(ssid)}</name>
    <SSIDConfig>
        <SSID>
            <name>{escape(ssid)}</name>
        </SSID>
        <nonBroadcast>false</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>{security}
    </MSM>
</WLANProfile>"""


def windows_connect(ssid: str, password: str | None) -> dict:
    profile_path = None
    try:
        xml = _windows_profile_xml(ssid, password)
        fd, profile_path = tempfile.mkstemp(suffix='.xml', prefix='wifiradar_')
        os.close(fd)
        try:
            os.chmod(profile_path, 0o600)
        except OSError:
            pass
        with open(profile_path, 'w', encoding='utf-8') as handle:
            handle.write(xml)

        ok, output = _run(['netsh', 'wlan', 'add', 'profile', f'filename={profile_path}'])
        if not ok:
            return {'success': False, 'error': f'Could not add WLAN profile: {output[:300]}'}

        ok, output = _run(['netsh', 'wlan', 'connect', f'name={ssid}'])
        if not ok:
            return {'success': False, 'error': f'Connection attempt failed: {output[:300]}'}
        return {'success': True, 'message': f'Connection to "{ssid}" requested.'}
    finally:
        del password
        if profile_path:
            try:
                os.remove(profile_path)
            except OSError:
                pass


def windows_disconnect() -> dict:
    ok, output = _run(['netsh', 'wlan', 'disconnect'])
    if ok:
        return {'success': True, 'message': 'Disconnect requested.'}
    return {'success': False, 'error': output[:300] or 'Disconnect failed.'}


# ---------------------------------------------------------------------------
# Linux implementation (nmcli)
# ---------------------------------------------------------------------------

def linux_connect(ssid: str, password: str | None) -> dict:
    args = ['nmcli', 'dev', 'wifi', 'connect', ssid]
    if password:
        args += ['password', password]
    ok, output = _run(args)
    if ok:
        return {'success': True, 'message': f'Connection to "{ssid}" requested.'}
    return {'success': False, 'error': output[:300] or 'Connection failed.'}


def linux_disconnect() -> dict:
    ok, output = _run(['nmcli', 'dev', 'disconnect', 'wlan0'])
    if ok:
        return {'success': True, 'message': 'Disconnect requested.'}
    ok, output = _run(['nmcli', 'connection', 'down', 'id', 'wlan0'])
    return (
        {'success': True, 'message': 'Disconnect requested.'}
        if ok else {'success': False, 'error': output[:300] or 'Disconnect failed.'}
    )


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

def status_payload() -> dict:
    return {
        'ok': True,
        'running': True,
        'platform': platform.system(),
        'python': platform.python_version(),
        'capabilities': ['connect', 'disconnect'],
    }


def handle_connect(body: dict) -> tuple[int, dict]:
    ssid = str(body.get('ssid', ''))
    password = body.get('password') or None
    if password is not None:
        password = str(password)
        if not (4 <= len(password) <= MAX_PASSWORD_LENGTH):
            del password
            return 400, {'success': False, 'error': 'Password must be 4-64 characters.'}
    if not SSID_RE.match(ssid) or '\x00' in ssid:
        del password
        return 400, {'success': False, 'error': 'Invalid SSID.'}

    system = platform.system()
    if system == 'Windows':
        result = windows_connect(ssid, password)
    elif system == 'Linux':
        result = linux_connect(ssid, password)
    else:
        result = {'success': False, 'error': f'Unsupported OS: {system}'}
    del password

    logger.info('connect result for %r: %s', ssid, 'ok' if result.get('success') else 'failed')
    return (200 if result.get('success') else 500), result


def handle_disconnect() -> tuple[int, dict]:
    system = platform.system()
    if system == 'Windows':
        result = windows_disconnect()
    elif system == 'Linux':
        result = linux_disconnect()
    else:
        result = {'success': False, 'error': f'Unsupported OS: {system}'}
    logger.info('disconnect result: %s', 'ok' if result.get('success') else 'failed')
    return (200 if result.get('success') else 500), result


class AgentHandler(BaseHTTPRequestHandler):
    server_version = 'WifiRadarAgent/1.0'

    def _send(self, code: int, payload: dict) -> None:
        data = json.dumps(payload).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> bool:
        return self.headers.get('X-Agent-Secret', '') == SECRET

    def do_GET(self):  # noqa: N802
        if self.path == '/status':
            self._send(200, status_payload())
        else:
            self._send(404, {'error': 'Not found'})

    def do_POST(self):  # noqa: N802
        if not self._authorized():
            logger.warning('Rejected unauthorized request from %s', self.client_address[0])
            self._send(401, {'success': False, 'error': 'Missing or invalid X-Agent-Secret.'})
            return

        try:
            length = int(self.headers.get('Content-Length') or 0)
            raw = self.rfile.read(min(length, 8192)) if length else b'{}'
            body = json.loads(raw.decode('utf-8') or '{}')
        except (ValueError, UnicodeDecodeError):
            self._send(400, {'success': False, 'error': 'Invalid JSON body.'})
            return

        if self.path == '/connect':
            code, payload = handle_connect(body if isinstance(body, dict) else {})
        elif self.path == '/disconnect':
            code, payload = handle_disconnect()
        else:
            code, payload = 404, {'error': 'Not found'}
        self._send(code, payload)

    def log_message(self, fmt, *args):  # noqa: A003
        # Suppress default access log (keeps query strings/paths out of logs).
        logger.debug(fmt, *args)


def main(argv: list[str] | None = None) -> int:
    global SECRET
    parser = argparse.ArgumentParser(description='Wi-Fi Radar local connection agent')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    parser.add_argument('--secret', default=DEFAULT_SECRET, help='Shared secret (or WIFI_AGENT_SECRET env var)')
    parser.add_argument('--host', default='127.0.0.1', help='Bind address (default: localhost only)')
    args = parser.parse_args(argv)

    if args.host not in ('127.0.0.1', 'localhost', '::1'):
        logger.error('Refusing to bind to %s — the agent must stay on localhost.', args.host)
        return 2

    SECRET = args.secret
    server = ThreadingHTTPServer((args.host, args.port), AgentHandler)
    logger.info('Wi-Fi agent listening on http://%s:%d (platform=%s)', args.host, args.port, platform.system())
    logger.info('Keep this running; the Django site calls this agent for connect/disconnect.')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info('Shutting down.')
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
