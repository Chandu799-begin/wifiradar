import csv
import json
import logging
import time

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import ConnectionLog, PasswordAccessLog, ScanHistory, WiFiNetwork
from .serializers import ConnectRequestSerializer, ScanHistorySerializer, WiFiNetworkSerializer
from .services import connection_service, wifi_profiles, wifi_scanner

logger = logging.getLogger('scanner')

DEFAULT_REFRESH_SECONDS = 5
WIFI_REAUTH_SESSION_KEY = 'wifi_pw_reauth'

STATUS_TO_LOG = {
    'ok': PasswordAccessLog.STATUS_GRANTED,
    'no_key': PasswordAccessLog.STATUS_NO_KEY,
    'denied': PasswordAccessLog.STATUS_DENIED,
    'unavailable': PasswordAccessLog.STATUS_UNAVAILABLE,
    'invalid': PasswordAccessLog.STATUS_DENIED,
}


def _client_is_local(request) -> bool:
    """True when the request originates from the local loopback interface."""
    remote = (request.META.get('REMOTE_ADDR') or '').strip()
    return remote in ('127.0.0.1', '::1', 'localhost')


def _password_gate(request) -> tuple[bool, str]:
    """Shared access checks for every saved-password endpoint.

    Enforces: feature enabled, local-only (unless overridden), and an
    authenticated administrator account.
    """
    if not getattr(settings, 'WIFI_PASSWORD_REVEAL_ENABLED', True):
        return False, 'Saved-password reveal is disabled on this deployment.'
    if getattr(settings, 'WIFI_REQUIRE_LOCAL_FOR_PASSWORDS', True) and not _client_is_local(request):
        return False, 'Showing saved passwords is only permitted from the local machine.'
    if not wifi_profiles.can_view_passwords(request.user):
        return False, 'Administrator access is required to view saved passwords.'
    return True, ''


def _reauth_is_fresh(request) -> bool:
    """True when this user completed a recent re-authentication in this session."""
    data = request.session.get(WIFI_REAUTH_SESSION_KEY)
    if not isinstance(data, dict) or data.get('user') != request.user.pk:
        return False
    try:
        return time.time() < float(data.get('until') or 0)
    except (TypeError, ValueError):
        return False


def _stats() -> dict:
    networks = list(WiFiNetwork.objects.all())
    signals = [n.signal_strength for n in networks] or [0]
    connected = next((n for n in networks if n.is_connected), None)
    last_scan = ScanHistory.objects.first()
    return {
        'total_networks': len(networks),
        'connected_ssid': connected.ssid if connected else None,
        'connected': connected,
        'strongest': max(signals),
        'weakest': min(signals),
        'secured': sum(1 for n in networks if (n.security_type or '').lower() not in ('open', '', 'owe')),
        'open': sum(1 for n in networks if (n.security_type or '').lower() in ('open', '', 'owe')),
        'strong_count': sum(1 for n in networks if n.signal_class == 'strong'),
        'medium_count': sum(1 for n in networks if n.signal_class == 'medium'),
        'weak_count': sum(1 for n in networks if n.signal_class == 'weak'),
        'last_scan': last_scan.scan_time if last_scan else None,
        'last_scan_source': last_scan.source if last_scan else '',
    }


def _page_context(request, **extra) -> dict:
    context = {
        'stats': _stats(),
        'refresh_seconds': request.session.get('refresh_seconds', DEFAULT_REFRESH_SECONDS),
        'demo_mode': request.session.get('demo_mode', False),
        'user': request.user,
    }
    context.update(extra)
    return context


def _safe_scan(request):
    try:
        return wifi_scanner.scan(request), None
    except wifi_scanner.WiFiScanError as exc:
        logger.warning('Scan unavailable: %s', exc)
        return None, str(exc)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

def dashboard(request):
    payload, error = _safe_scan(request)
    return render(request, 'scanner/dashboard.html', _page_context(request, scan=payload, scan_error=error))


def radar_page(request):
    payload, error = _safe_scan(request)
    return render(request, 'scanner/radar.html', _page_context(request, scan=payload, scan_error=error))


def networks_page(request):
    payload, error = _safe_scan(request)
    return render(request, 'scanner/networks.html', _page_context(request, scan=payload, scan_error=error))


def connected_page(request):
    adapter = wifi_scanner.adapter_status(request)
    network = WiFiNetwork.objects.filter(is_connected=True).first()
    logs = ConnectionLog.objects.all()[:20]
    return render(
        request,
        'scanner/connected.html',
        _page_context(request, adapter=adapter, current=network, connection_logs=logs),
    )


def analytics_page(request):
    history = list(ScanHistory.objects.all()[:30])
    history.reverse()
    labels = [h.scan_time.strftime('%H:%M:%S') for h in history]
    strongest = [h.strongest_signal for h in history]
    totals = [h.total_networks for h in history]
    chart = {'labels': labels, 'strongest': strongest, 'totals': totals}
    return render(
        request,
        'scanner/analytics.html',
        _page_context(request, chart=json.dumps(chart), history=history),
    )


def history_page(request):
    history = ScanHistory.objects.all()[:200]
    return render(request, 'scanner/history.html', _page_context(request, history=history))


def settings_page(request):
    agent = connection_service.agent_reachable()
    return render(request, 'scanner/settings.html', _page_context(request, agent=agent))


@require_POST
def update_settings(request):
    """Persist user preferences in the session (no accounts required)."""
    try:
        refresh = int(request.POST.get('refresh_seconds', DEFAULT_REFRESH_SECONDS))
    except (TypeError, ValueError):
        refresh = DEFAULT_REFRESH_SECONDS
    request.session['refresh_seconds'] = max(1, min(300, refresh))

    if 'demo_mode' in request.POST:
        request.session['demo_mode'] = request.POST.get('demo_mode') == 'on'

    if 'dark_mode' in request.POST:
        request.session['dark_mode'] = request.POST.get('dark_mode') == 'on'

    messages.success(request, 'Settings saved.')
    return redirect(request.META.get('HTTP_REFERER', 'settings'))


# ---------------------------------------------------------------------------
# Saved Wi-Fi profiles & password reveal (local, administrator-only)
# ---------------------------------------------------------------------------

@login_required
def wifi_dashboard(request):
    """Premium dashboard showing saved profiles + nearby networks."""
    can_reveal, reason = _password_gate(request)
    return render(
        request,
        'scanner/wifi_dashboard.html',
        _page_context(
            request,
            can_reveal=can_reveal,
            reveal_reason=reason or '',
            reveal_enabled=getattr(settings, 'WIFI_PASSWORD_REVEAL_ENABLED', True),
            reauth_seconds=getattr(settings, 'WIFI_PASSWORD_REAUTH_SECONDS', 120),
            is_local=_client_is_local(request),
            is_admin=wifi_profiles.can_view_passwords(request.user),
            password_logs=PasswordAccessLog.objects.all()[:10],
        ),
    )


@login_required
@require_GET
def saved_profiles_api(request):
    """Return saved-profile *metadata only*. Passwords are never exposed here."""
    try:
        data = wifi_profiles.list_saved_profiles(force=request.GET.get('force') == '1')
    except wifi_profiles.WiFiProfileError as exc:
        logger.warning('Saved profiles unavailable: %s', exc)
        return JsonResponse({'detail': str(exc), 'profiles': [], 'source': 'unavailable'}, status=503)
    can_reveal, _ = _password_gate(request)
    return JsonResponse({
        'profiles': data['profiles'],
        'source': data.get('source'),
        'cached': data.get('cached', False),
        'message': data.get('message', ''),
        'can_reveal': can_reveal,
    })


@login_required
@require_POST
@never_cache
def wifi_password_reauth(request):
    """Re-verify the user's account password before any reveal is allowed."""
    ok, reason = _password_gate(request)
    if not ok:
        return JsonResponse({'ok': False, 'message': reason}, status=403)

    password = request.POST.get('password') or ''
    user = authenticate(request, username=request.user.get_username(), password=password)
    if user is None or not user.is_active or user.pk != request.user.pk:
        PasswordAccessLog.objects.create(
            user=request.user, profile_name='', action=PasswordAccessLog.ACTION_REAUTH,
            status=PasswordAccessLog.STATUS_DENIED, detail='Re-authentication failed.',
        )
        return JsonResponse({'ok': False, 'message': 'Incorrect password. Try again.'}, status=403)

    seconds = max(15, int(getattr(settings, 'WIFI_PASSWORD_REAUTH_SECONDS', 120)))
    request.session[WIFI_REAUTH_SESSION_KEY] = {'user': request.user.pk, 'until': time.time() + seconds}
    request.session.modified = True
    PasswordAccessLog.objects.create(
        user=request.user, profile_name='', action=PasswordAccessLog.ACTION_REAUTH,
        status=PasswordAccessLog.STATUS_GRANTED, detail='Fresh authentication granted.',
    )
    return JsonResponse({'ok': True, 'valid_for': seconds, 'until': time.time() + seconds})


@login_required
@require_POST
@never_cache
def wifi_password_reveal(request):
    """Reveal a single saved password. Never returns more than one key."""
    ok, reason = _password_gate(request)
    if not ok:
        PasswordAccessLog.objects.create(
            user=request.user, profile_name='', action=PasswordAccessLog.ACTION_REVEAL,
            status=PasswordAccessLog.STATUS_DENIED, detail=reason[:250],
        )
        return JsonResponse({'ok': False, 'message': reason}, status=403)

    if not _reauth_is_fresh(request):
        return JsonResponse(
            {'ok': False, 'reauth_required': True,
             'message': 'Please re-authenticate before revealing a saved password.'},
            status=428,
        )

    name = (request.POST.get('profile') or '').strip()
    if not name or len(name) > wifi_profiles.MAX_PROFILE_NAME_LENGTH:
        return JsonResponse({'ok': False, 'message': 'Invalid profile name.'}, status=400)

    result = wifi_profiles.reveal_profile_key(name)
    PasswordAccessLog.objects.create(
        user=request.user, profile_name=name[:255], action=PasswordAccessLog.ACTION_REVEAL,
        status=STATUS_TO_LOG.get(result['status'], PasswordAccessLog.STATUS_ERROR),
        detail=(result.get('message') or '')[:250],
    )

    response = None
    if result['status'] == 'ok':
        response = JsonResponse({
            'ok': True, 'profile': name, 'password': result['password'],
            'demo': result.get('demo', False), 'message': result.get('message', ''),
        })
    elif result['status'] == 'invalid':
        response = JsonResponse({'ok': False, 'status': 'invalid', 'message': result.get('message', 'Profile not found.')}, status=404)
    elif result['status'] == 'no_key':
        response = JsonResponse({'ok': False, 'status': 'no_key', 'message': result.get('message', 'No saved password.')}, status=400)
    else:  # denied / unavailable
        response = JsonResponse({'ok': False, 'status': result['status'], 'message': result.get('message', 'Windows denied the request.')}, status=502)

    # Belt-and-braces: never let any proxy or browser cache a revealed key.
    response['Cache-Control'] = 'no-store'
    response['Pragma'] = 'no-cache'
    return response


@require_GET
def export_history(request):
    """Export scan history as CSV (no passwords, by design)."""
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="wifi_scan_history.csv"'
    writer = csv.writer(response)
    writer.writerow(['Scan time', 'Total networks', 'Strongest signal', 'Weakest signal', 'Connected SSID', 'Source'])
    for item in ScanHistory.objects.all()[:5000]:
        writer.writerow([
            item.scan_time.strftime('%Y-%m-%d %H:%M:%S'),
            item.total_networks,
            item.strongest_signal,
            item.weakest_signal,
            item.connected_ssid,
            item.source,
        ])
    return response


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

class ScanAPI(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        force = request.query_params.get('force') == '1'
        try:
            payload = wifi_scanner.scan(request, force=force)
        except wifi_scanner.WiFiScanError as exc:
            return Response(
                {'detail': str(exc), 'networks': [], 'source': 'unavailable'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return Response(payload)


class NetworksAPI(APIView):
    def get(self, request):
        queryset = WiFiNetwork.objects.all()
        query = request.query_params.get('search', '').strip()
        if query:
            queryset = queryset.filter(ssid__icontains=query)
        signal_class = request.query_params.get('signal_class', '').strip().lower()
        if signal_class in ('strong', 'medium', 'weak'):
            queryset = queryset.filter(
                signal_strength__gte={'strong': 75, 'medium': 40, 'weak': 0}[signal_class],
                signal_strength__lte={'strong': 100, 'medium': 74, 'weak': 39}[signal_class],
            )
        if request.query_params.get('connected') == '1':
            queryset = queryset.filter(is_connected=True)

        sort = request.query_params.get('sort', '-signal_strength')
        if sort in ('signal_strength', '-signal_strength', 'ssid', '-ssid', 'last_seen', '-last_seen'):
            queryset = queryset.order_by(sort)
        elif sort == 'ssid':
            queryset = queryset.order_by('ssid')

        page_size = min(int(request.query_params.get('page_size', 100) or 100), 500)
        serializer = WiFiNetworkSerializer(queryset[:page_size], many=True)
        return Response({'count': queryset.count(), 'results': serializer.data})


class ConnectedAPI(APIView):
    def get(self, request):
        network = WiFiNetwork.objects.filter(is_connected=True).order_by('-signal_strength').first()
        adapter = wifi_scanner.adapter_status(request)
        serializer = WiFiNetworkSerializer(network) if network else None
        return Response({
            'network': serializer.data if serializer else None,
            'adapter': adapter,
            'agent': connection_service.agent_reachable(),
        })


class HistoryAPI(APIView):
    def get(self, request):
        limit = min(int(request.query_params.get('limit', 100) or 100), 1000)
        queryset = ScanHistory.objects.all()[:limit]
        serializer = ScanHistorySerializer(queryset, many=True)
        return Response({'count': ScanHistory.objects.count(), 'results': serializer.data})


class ConnectAPI(APIView):
    """Requires an authenticated, authorized session + CSRF token.

    The password is forwarded to the local desktop agent and is never
    written to the database or logs.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ConnectRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = connection_service.connect(
            request.user,
            serializer.validated_data['ssid'],
            serializer.validated_data.get('password') or None,
        )
        code = status.HTTP_200_OK if result['success'] else status.HTTP_400_BAD_REQUEST
        if result.get('status') == ConnectionLog.STATUS_PENDING_AGENT:
            code = status.HTTP_502_BAD_GATEWAY
        elif result.get('status') == ConnectionLog.STATUS_DENIED:
            code = status.HTTP_403_FORBIDDEN
        return Response(result, status=code)


class DisconnectAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        result = connection_service.disconnect(request.user)
        code = status.HTTP_200_OK if result['success'] else status.HTTP_400_BAD_REQUEST
        if result.get('status') == ConnectionLog.STATUS_PENDING_AGENT:
            code = status.HTTP_502_BAD_GATEWAY
        elif result.get('status') == ConnectionLog.STATUS_DENIED:
            code = status.HTTP_403_FORBIDDEN
        return Response(result, status=code)
