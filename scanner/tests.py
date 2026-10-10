from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from unittest.mock import patch

from .models import ConnectionLog, PasswordAccessLog, SavedWiFiProfile, ScanHistory, WiFiNetwork
from .services import wifi_profiles, wifi_scanner
from .services.connection_service import can_control_wifi
from .services.wifi_profiles import can_view_passwords
from .views import WIFI_REAUTH_SESSION_KEY


class ModelTests(TestCase):
    def test_signal_classification(self):
        cases = [(95, 'strong'), (75, 'strong'), (74, 'medium'), (40, 'medium'), (39, 'weak'), (0, 'weak')]
        for value, expected in cases:
            network = WiFiNetwork.objects.create(ssid='n', bssid=f'AA:BB:CC:DD:EE:{value:02X}', signal_strength=value)
            self.assertEqual(network.signal_class, expected, f'{value}% should be {expected}')

    def test_to_dict_contains_no_password_field(self):
        network = WiFiNetwork.objects.create(ssid='n', bssid='AA:BB:CC:DD:EE:FF', signal_strength=50)
        payload = network.to_dict()
        self.assertNotIn('password', payload)
        self.assertNotIn('psk', payload)


def demo_request():
    class FakeRequest:
        session = {'demo_mode': True}
    return FakeRequest()


class ScanServiceTests(TestCase):
    def test_demo_scan_persists_networks_and_history(self):
        payload = wifi_scanner.scan(demo_request(), force=True)
        self.assertTrue(payload['demo_mode'])
        self.assertGreater(len(payload['networks']), 0)
        self.assertEqual(WiFiNetwork.objects.count(), len(payload['networks']))
        self.assertEqual(ScanHistory.objects.count(), 1)
        history = ScanHistory.objects.first()
        self.assertEqual(history.total_networks, len(payload['networks']))
        self.assertEqual(history.source, 'demo')

    def test_scan_uses_cache_between_calls(self):
        first = wifi_scanner.scan(demo_request(), force=True)
        second = wifi_scanner.scan(demo_request())
        self.assertFalse(first['cached'])
        self.assertTrue(second['cached'])

    def test_scan_history_never_contains_passwords(self):
        wifi_scanner.scan(demo_request(), force=True)
        fields = [f.name for f in ScanHistory._meta.get_fields()]
        self.assertNotIn('password', fields)
        self.assertNotIn('psk', fields)


class PageTests(TestCase):
    def test_dashboard_renders(self):
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Wi-Fi Radar Pro')

    def test_all_pages_render(self):
        for name in ['dashboard', 'radar', 'networks', 'connected', 'analytics', 'history', 'settings', 'login']:
            with self.subTest(page=name):
                response = self.client.get(reverse(name))
                self.assertEqual(response.status_code, 200)

    def test_export_history_csv(self):
        wifi_scanner.scan(demo_request(), force=True)
        response = self.client.get(reverse('export_history'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/csv', response['Content-Type'])
        self.assertIn('wifi_scan_history.csv', response['Content-Disposition'])


class ApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_scan_api(self):
        response = self.client.get(reverse('api_scan'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('networks', response.json())

    def test_networks_api_search_and_filter(self):
        wifi_scanner.scan(demo_request(), force=True)
        response = self.client.get(reverse('api_networks'), {'search': 'Office'})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(all('Office' in item['ssid'] for item in data['results']))

        response = self.client.get(reverse('api_networks'), {'signal_class': 'strong'})
        data = response.json()
        self.assertTrue(all(item['signal_strength'] >= 75 for item in data['results']))

        response = self.client.get(reverse('api_networks'), {'sort': 'ssid'})
        data = response.json()
        ssids = [item['ssid'] for item in data['results']]
        self.assertEqual(ssids, sorted(ssids))

    def test_connected_api(self):
        response = self.client.get(reverse('api_connected'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('adapter', response.json())

    def test_history_api(self):
        wifi_scanner.scan(demo_request(), force=True)
        response = self.client.get(reverse('api_history'))
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.json()['count'], 1)

    def test_connect_requires_authentication(self):
        response = self.client.post(reverse('api_connect'), {'ssid': 'Home_WiFi'}, format='json')
        self.assertIn(response.status_code, (401, 403))

    def test_disconnect_requires_authentication(self):
        response = self.client.post(reverse('api_disconnect'), {}, format='json')
        self.assertIn(response.status_code, (401, 403))


class AuthorizationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('viewer', password='x' * 9)
        self.staff = User.objects.create_user('admin', password='x' * 9, is_staff=True)

    def test_regular_user_may_not_control_wifi(self):
        self.assertFalse(can_control_wifi(self.user))
        self.assertFalse(can_control_wifi(None))

    def test_staff_may_control_wifi(self):
        self.assertTrue(can_control_wifi(self.staff))

    def test_connect_never_persists_password(self):
        wifi_scanner.scan(demo_request(), force=True)
        client = APIClient()
        client.force_authenticate(self.staff)
        secret = 'Sup3r-Secret-Pass!'
        response = client.post(
            reverse('api_connect'),
            {'ssid': 'Office_Network', 'password': secret},
            format='json',
        )
        self.assertIn(response.status_code, (200, 400, 502))
        log = ConnectionLog.objects.filter(ssid='Office_Network').first()
        self.assertIsNotNone(log)
        self.assertNotIn(secret, log.detail)
        for entry in ConnectionLog.objects.all():
            self.assertNotIn(secret, entry.detail)
        self.assertNotIn(secret, str(response.json()))

    def test_connect_requires_password_for_secured_network(self):
        wifi_scanner.scan(demo_request(), force=True)
        client = APIClient()
        client.force_authenticate(self.staff)
        response = client.post(reverse('api_connect'), {'ssid': 'Office_Network'}, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertTrue(response.json().get('password_required'))

    def test_connect_rejects_unknown_network(self):
        wifi_scanner.scan(demo_request(), force=True)
        client = APIClient()
        client.force_authenticate(self.staff)
        response = client.post(reverse('api_connect'), {'ssid': 'not-a-real-network'}, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('not found', response.json()['message'].lower())


# ===========================================================================
# Saved Wi-Fi profiles & password reveal
# ===========================================================================

FAKE_PROFILES_OUTPUT = """Profiles on interface Wi-Fi:
------------------------------------------------------------------------
Group policy profiles (read only)
---------------------------------
    <None>

User profiles
-------------
    All User Profile     : HomeWiFi
    All User Profile     : OfficeNet

Profiles on interface Wi-Fi 2:
------------------------------------------------------------------------
User profiles
-------------
    All User Profile     : GuestWifi
"""

FAKE_INTERFACES_OUTPUT = """
Name                   : Wi-Fi
SSID                   : OfficeNet
State                  : connected
"""

FAKE_PROFILE_HOMEWIFI = """Profile HomeWiFi on interface Wi-Fi:
-----------------------------------------------------------------------
Applied: All User Profile

Profile information
-------------------
    Name                   : HomeWiFi

Security settings
------------------
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Security key           : Present
"""

FAKE_PROFILE_OFFICE = """Profile OfficeNet on interface Wi-Fi:
-----------------------------------------------------------------------
Applied: All User Profile

Profile information
-------------------
    Name                   : OfficeNet

Security settings
------------------
    Authentication         : WPA3-Personal
    Cipher                 : GCMP
    Security key           : Present
"""

FAKE_PROFILE_GUEST = """Profile GuestWifi on interface Wi-Fi 2:
-----------------------------------------------------------------------
Applied: All User Profile

Profile information
-------------------
    Name                   : GuestWifi

Security settings
------------------
    Authentication         : Open
    Cipher                 : None
    Security key           : Absent
"""


def fake_netsh_output(args):
    """Simulate netsh output for the profile parsing unit tests."""
    command = ' '.join(args)
    if 'show interfaces' in command:
        return True, FAKE_INTERFACES_OUTPUT
    if 'show profiles' in command and 'profile ' not in command:
        return True, FAKE_PROFILES_OUTPUT
    if args and args[0] == 'wlan' and args[1] == 'show' and args[2] == 'profile':
        name_arg = next((a for a in args if a.startswith('name=')), None)
        name = name_arg.split('=', 1)[1] if name_arg else ''
        output = {
            'HomeWiFi': FAKE_PROFILE_HOMEWIFI,
            'OfficeNet': FAKE_PROFILE_OFFICE,
            'GuestWifi': FAKE_PROFILE_GUEST,
        }.get(name, '---\nName : not found\n')
        has_key_clear = 'key=clear' in command
        return True, output + ('\n    Key Content          : S3cr3t-Pass-99\n' if has_key_clear and name == 'HomeWiFi' else '')
    return False, ''


class WifiProfileServiceTests(TestCase):
    def setUp(self):
        wifi_profiles.invalidate_cache()

    def test_can_view_passwords_requires_admin(self):
        viewer = User.objects.create_user('viewer2', password='x' * 9)
        staff = User.objects.create_user('admin2', password='x' * 9, is_staff=True)
        self.assertFalse(can_view_passwords(None))
        self.assertFalse(can_view_passwords(viewer))
        self.assertTrue(can_view_passwords(staff))
        holder = User.objects.create_user('holder', password='x' * 9)
        from django.contrib.auth.models import Permission
        permission = Permission.objects.get(codename='view_wifi_passwords')
        holder.user_permissions.add(permission)
        self.assertTrue(can_view_passwords(holder))

    def test_enumerate_profile_names_parses_multiple_interfaces(self):
        with patch.object(wifi_profiles, '_run_netsh', return_value=(True, FAKE_PROFILES_OUTPUT)):
            profiles = wifi_profiles._enumerate_profile_names()
        names = [p['name'] for p in profiles]
        self.assertEqual(names, ['HomeWiFi', 'OfficeNet', 'GuestWifi'])
        self.assertEqual(profiles[0]['interface'], 'Wi-Fi')
        self.assertEqual(profiles[2]['interface'], 'Wi-Fi 2')

    def test_profile_details_parses_security_and_key_presence(self):
        with patch.object(wifi_profiles, '_run_netsh', return_value=(True, FAKE_PROFILE_HOMEWIFI)):
            details = wifi_profiles._profile_details('HomeWiFi')
        self.assertEqual(details['security'], 'WPA2-Personal')
        self.assertTrue(details['has_key_material'])
        self.assertTrue(details['found'])

    def test_list_saved_profiles_live(self):
        with patch.object(wifi_profiles, '_run_netsh', side_effect=fake_netsh_output):
            result = wifi_profiles.list_saved_profiles(force=True)
        profiles = {p['name']: p for p in result['profiles']}
        self.assertEqual(result['source'], 'live')
        self.assertEqual(len(result['profiles']), 3)
        self.assertTrue(profiles['HomeWiFi']['has_key_material'])
        self.assertFalse(profiles['GuestWifi']['has_key_material'])
        self.assertTrue(profiles['OfficeNet']['is_connected'])
        for item in result['profiles']:
            self.assertNotIn('password', item)
            self.assertNotIn('psk', item)

    def test_list_saved_profiles_persists_metadata_only(self):
        with patch.object(wifi_profiles, '_run_netsh', side_effect=fake_netsh_output):
            wifi_profiles.list_saved_profiles(force=True)
        row = SavedWiFiProfile.objects.get(name='HomeWiFi')
        self.assertTrue(row.has_key_material)
        self.assertEqual(row.security, 'WPA2-Personal')
        fields = [f.name for f in SavedWiFiProfile._meta.get_fields()]
        self.assertNotIn('password', fields)
        self.assertNotIn('psk', fields)
        payload = row.to_dict()
        self.assertNotIn('password', payload)

    def test_reveal_parses_key_content(self):
        with (
            patch.object(wifi_profiles, '_run_netsh', side_effect=fake_netsh_output),
            patch.object(wifi_profiles, 'list_saved_profiles',
                         return_value={'profiles': [{'name': 'HomeWiFi'}]}),
        ):
            result = wifi_profiles.reveal_profile_key('HomeWiFi')
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['password'], 'S3cr3t-Pass-99')

    def test_reveal_reports_no_saved_key(self):
        with (
            patch.object(wifi_profiles, '_run_netsh', return_value=(True, FAKE_PROFILE_GUEST + '\nIdentity: none')),
            patch.object(wifi_profiles, 'list_saved_profiles',
                         return_value={'profiles': [{'name': 'GuestWifi'}]}),
        ):
            result = wifi_profiles.reveal_profile_key('GuestWifi')
        self.assertEqual(result['status'], 'no_key')
        self.assertNotIn('password', result)

    def test_reveal_rejects_unknown_profile_without_calling_netsh(self):
        with (
            patch.object(wifi_profiles, '_run_netsh') as mock_run,
            patch.object(wifi_profiles, 'list_saved_profiles', return_value={'profiles': [{'name': 'HomeWiFi'}]}),
        ):
            result = wifi_profiles.reveal_profile_key('DoesNotExist')
        self.assertEqual(result['status'], 'invalid')
        mock_run.assert_not_called()

    def test_reveal_denied_when_windows_hides_key(self):
        with (
            patch.object(wifi_profiles, '_run_netsh',
                         return_value=(True, FAKE_PROFILE_OFFICE + '\nSecurity key : Present\n')),
            patch.object(wifi_profiles, 'list_saved_profiles',
                         return_value={'profiles': [{'name': 'OfficeNet'}]}),
        ):
            result = wifi_profiles.reveal_profile_key('OfficeNet')
        self.assertEqual(result['status'], 'denied')
        self.assertNotIn('password', result)

    def test_reveal_demo_mode_non_windows(self):
        with patch.object(wifi_profiles, 'is_windows', return_value=False):
            result = wifi_profiles.reveal_profile_key('Home_WiFi')
        self.assertEqual(result['status'], 'ok')
        self.assertTrue(result.get('demo'))
        denied = wifi_profiles.reveal_profile_key('DoesNotExist')
        self.assertEqual(denied['status'], 'invalid')

    def test_reveal_uses_argument_list_not_shell(self):
        captured = []
        def fake_run(args):
            captured.append(args)
            return True, FAKE_PROFILE_HOMEWIFI + '\n    Key Content   : xyz\n'
        with (
            patch.object(wifi_profiles, '_run_netsh', side_effect=fake_run),
            patch.object(wifi_profiles, 'list_saved_profiles',
                         return_value={'profiles': [{'name': 'HomeWiFi'}]}),
        ):
            result = wifi_profiles.reveal_profile_key('HomeWiFi')
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(captured[-1][-1], 'key=clear')
        self.assertEqual(captured[-1][0], 'wlan')
        self.assertIn('name=HomeWiFi', captured[-1])
        joined = ' '.join(captured[-1])
        for op in ('|', ';', '&&', '>', '`', '$('):
            self.assertNotIn(op, joined)


STAFF_PASSWORD = 'secret-pass-123'


class WifiPasswordEndpointTests(TestCase):
    def setUp(self):
        wifi_profiles.invalidate_cache()
        self.staff = User.objects.create_user('wifi-admin', password=STAFF_PASSWORD, is_staff=True)
        self.viewer = User.objects.create_user('wifi-viewer', password=STAFF_PASSWORD)
        self.client.login(username='wifi-admin', password=STAFF_PASSWORD)

    def test_wifi_dashboard_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse('wifi_dashboard'))
        self.assertIn(response.status_code, (302, 403))

    def test_wifi_dashboard_renders_for_logged_in_user(self):
        response = self.client.get(reverse('wifi_dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Saved Wi-Fi')
        self.assertContains(response, 'Password access audit')

    def test_saved_profiles_api_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse('api_saved_profiles'))
        self.assertIn(response.status_code, (302, 403))

    def test_saved_profiles_api_returns_metadata_only(self):
        with patch.object(
            wifi_profiles, 'list_saved_profiles',
            return_value={'profiles': [{'name': 'HomeWiFi', 'security': 'WPA2-Personal',
                                        'has_key_material': True, 'is_connected': True, 'interface': 'Wi-Fi'}],
                          'source': 'live', 'cached': False, 'message': ''},
        ):
            response = self.client.get(reverse('api_saved_profiles'))
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body['profiles'][0]['name'], 'HomeWiFi')
        self.assertNotIn('password', body)
        self.assertIn('can_reveal', body)

    def test_reveal_requires_authentication(self):
        self.client.logout()
        response = self.client.post(reverse('wifi_password_reveal'), {'profile': 'HomeWiFi'})
        self.assertIn(response.status_code, (302, 403))

    def test_reveal_requires_admin(self):
        self.client.logout()
        self.client.login(username='wifi-viewer', password=STAFF_PASSWORD)
        response = self.client.post(reverse('wifi_password_reveal'), {'profile': 'HomeWiFi'})
        self.assertEqual(response.status_code, 403)

    def test_reveal_requires_fresh_reauth(self):
        response = self.client.post(reverse('wifi_password_reveal'), {'profile': 'HomeWiFi'})
        self.assertEqual(response.status_code, 428)
        self.assertTrue(response.json()['reauth_required'])

    def test_reauth_rejects_wrong_password(self):
        response = self.client.post(reverse('wifi_password_reauth'), {'password': 'wrong-password'})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(response.json()['ok'])

    def test_reauth_then_reveal_flow(self):
        with patch.object(wifi_profiles, 'reveal_profile_key',
                          return_value={'status': 'ok', 'password': 'K3y-Material!', 'demo': False,
                                        'message': 'Key shown.'}):
            auth = self.client.post(reverse('wifi_password_reauth'), {'password': STAFF_PASSWORD})
            self.assertEqual(auth.status_code, 200)
            self.assertTrue(auth.json()['ok'])
            session = self.client.session
            self.assertIn(WIFI_REAUTH_SESSION_KEY, session)
            self.assertEqual(session[WIFI_REAUTH_SESSION_KEY]['user'], self.staff.pk)

            response = self.client.post(reverse('wifi_password_reveal'), {'profile': 'HomeWiFi'})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['ok'])
        self.assertEqual(data['password'], 'K3y-Material!')
        self.assertIn('no-store', response['Cache-Control'])
        self.assertIn('Pragma', response)

    def test_reveal_does_not_persist_or_log_password(self):
        secret = 'Never-Log-This-Pass!'
        with patch.object(wifi_profiles, 'reveal_profile_key',
                          return_value={'status': 'ok', 'password': secret, 'demo': False, 'message': 'Key shown.'}):
            self.client.post(reverse('wifi_password_reauth'), {'password': STAFF_PASSWORD})
            response = self.client.post(reverse('wifi_password_reveal'), {'profile': 'HomeWiFi'})
        self.assertEqual(response.status_code, 200)
        self.assertIn(secret, response.json()['password'])

        # The password must not appear anywhere in persistence layer or session.
        self.assertNotIn(secret, str(self.client.session))
        grants = PasswordAccessLog.objects.filter(status=PasswordAccessLog.STATUS_GRANTED)
        self.assertGreaterEqual(grants.count(), 2)  # reauth + reveal
        for log in PasswordAccessLog.objects.all():
            for field in ('profile_name', 'detail'):
                self.assertNotIn(secret, getattr(log, field))
        for row in SavedWiFiProfile.objects.all():
            self.assertNotIn(secret, str(row.to_dict()))
        for row in ConnectionLog.objects.all():
            self.assertNotIn(secret, str(row.to_dict()))
        for row in ScanHistory.objects.all():
            self.assertNotIn(secret, str(row.to_dict()))

    def test_reveal_rejects_remote_clients(self):
        response = self.client.post(
            reverse('wifi_password_reveal'), {'profile': 'HomeWiFi'}, REMOTE_ADDR='203.0.113.5'
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn('local machine', response.json()['message'].lower())

    def test_reveal_logs_denial_for_invalid_profile(self):
        with patch.object(wifi_profiles, 'reveal_profile_key',
                          return_value={'status': 'invalid', 'message': 'Profile not found.'}):
            self.client.post(reverse('wifi_password_reauth'), {'password': STAFF_PASSWORD})
            response = self.client.post(reverse('wifi_password_reveal'), {'profile': 'Nope'})
        self.assertEqual(response.status_code, 404)
        log = PasswordAccessLog.objects.filter(profile_name='Nope', status=PasswordAccessLog.STATUS_DENIED).first()
        self.assertIsNotNone(log)
