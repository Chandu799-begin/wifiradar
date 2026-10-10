from django.db import models
from django.contrib.auth.models import User


class WiFiNetwork(models.Model):
    """A Wi-Fi network observed during scanning. Passwords are never stored."""

    SIGNAL_CLASS_STRONG = 'strong'
    SIGNAL_CLASS_MEDIUM = 'medium'
    SIGNAL_CLASS_WEAK = 'weak'
    SIGNAL_CLASS_CHOICES = [
        (SIGNAL_CLASS_STRONG, 'Strong'),
        (SIGNAL_CLASS_MEDIUM, 'Medium'),
        (SIGNAL_CLASS_WEAK, 'Weak'),
    ]

    ssid = models.CharField(max_length=255, default='Hidden network')
    bssid = models.CharField(max_length=64, unique=True)
    signal_strength = models.PositiveSmallIntegerField(default=0)
    security_type = models.CharField(max_length=64, default='Open')
    frequency = models.CharField(max_length=32, blank=True, default='')
    channel = models.PositiveSmallIntegerField(null=True, blank=True)
    is_connected = models.BooleanField(default=False)
    is_hidden = models.BooleanField(default=False)
    last_seen = models.DateTimeField(auto_now=True)
    first_seen = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-signal_strength', 'ssid']
        permissions = [
            ('control_wifi', 'Can connect or disconnect Wi-Fi through the local agent'),
            ('export_scans', 'Can export scan history'),
        ]

    def __str__(self):
        return f'{self.ssid} ({self.signal_strength}%)'

    @property
    def signal_class(self):
        if self.signal_strength >= 75:
            return self.SIGNAL_CLASS_STRONG
        if self.signal_strength >= 40:
            return self.SIGNAL_CLASS_MEDIUM
        return self.SIGNAL_CLASS_WEAK

    def to_dict(self):
        return {
            'id': self.id,
            'ssid': self.ssid,
            'bssid': self.bssid,
            'signal_strength': self.signal_strength,
            'signal_class': self.signal_class,
            'security_type': self.security_type,
            'frequency': self.frequency,
            'channel': self.channel,
            'is_connected': self.is_connected,
            'is_hidden': self.is_hidden,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
        }


class ScanHistory(models.Model):
    """Aggregate record of a single scan pass. No passwords are ever stored."""

    scan_time = models.DateTimeField(auto_now_add=True)
    total_networks = models.PositiveIntegerField(default=0)
    strongest_signal = models.PositiveSmallIntegerField(default=0)
    weakest_signal = models.PositiveSmallIntegerField(default=0)
    connected_ssid = models.CharField(max_length=255, blank=True, default='')
    adapter = models.CharField(max_length=64, blank=True, default='')
    source = models.CharField(max_length=16, default='live')

    class Meta:
        ordering = ['-scan_time']

    def __str__(self):
        return f'Scan {self.scan_time:%Y-%m-%d %H:%M:%S} ({self.total_networks} networks)'

    def to_dict(self):
        return {
            'id': self.id,
            'scan_time': self.scan_time.isoformat(),
            'total_networks': self.total_networks,
            'strongest_signal': self.strongest_signal,
            'weakest_signal': self.weakest_signal,
            'connected_ssid': self.connected_ssid,
            'adapter': self.adapter,
            'source': self.source,
        }


class SavedWiFiProfile(models.Model):
    """Metadata for a Wi-Fi profile saved on the local computer.

    Only descriptive fields are stored here. The profile's key/passphrase is
    NEVER copied into this model (or any other table). ``has_key_material`` is
    a coarse "Windows reports a security key is present" flag used purely to
    render the UI indicator.
    """

    name = models.CharField(max_length=255, unique=True)
    security = models.CharField(max_length=64, blank=True, default='')
    has_key_material = models.BooleanField(default=False)
    is_connected = models.BooleanField(default=False)
    interface = models.CharField(max_length=128, blank=True, default='')
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        permissions = [
            ('view_wifi_passwords', 'Can reveal saved Wi-Fi passwords on this local machine'),
        ]

    def __str__(self):
        return self.name

    @property
    def is_secured(self):
        return (self.security or '').lower() not in ('', 'open', 'owe')

    def to_dict(self):
        return {
            'name': self.name,
            'security': self.security or 'Open',
            'has_key_material': self.has_key_material,
            'is_connected': self.is_connected,
            'interface': self.interface,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
        }


class PasswordAccessLog(models.Model):
    """Audit trail for attempts to reveal a saved Wi-Fi password.

    The password value is intentionally absent: this model can only ever hold
    who asked, for which profile, when, and the outcome.
    """

    ACTION_REVEAL = 'reveal'
    ACTION_REAUTH = 'reauth'
    ACTION_CHOICES = [
        (ACTION_REVEAL, 'Reveal attempt'),
        (ACTION_REAUTH, 'Re-authentication'),
    ]

    STATUS_GRANTED = 'granted'
    STATUS_DENIED = 'denied'
    STATUS_NO_KEY = 'no_key'
    STATUS_UNAVAILABLE = 'unavailable'
    STATUS_ERROR = 'error'
    STATUS_CHOICES = [
        (STATUS_GRANTED, 'Granted'),
        (STATUS_DENIED, 'Denied'),
        (STATUS_NO_KEY, 'No saved key'),
        (STATUS_UNAVAILABLE, 'Unavailable'),
        (STATUS_ERROR, 'Error'),
    ]

    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='wifi_password_logs')
    profile_name = models.CharField(max_length=255, blank=True, default='')
    action = models.CharField(max_length=16, choices=ACTION_CHOICES, default=ACTION_REVEAL)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_DENIED)
    detail = models.CharField(max_length=255, blank=True, default='')
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f'{self.action} {self.profile_name}: {self.status}'

    def to_dict(self):
        return {
            'id': self.id,
            'profile_name': self.profile_name,
            'action': self.action,
            'status': self.status,
            'detail': self.detail,
            'timestamp': self.timestamp.isoformat(),
        }


class ConnectionLog(models.Model):
    """Audit trail for connection attempts. Passwords are never persisted."""

    STATUS_SUCCESS = 'success'
    STATUS_FAILED = 'failed'
    STATUS_DISCONNECTED = 'disconnected'
    STATUS_PENDING_AGENT = 'pending_agent'
    STATUS_DENIED = 'denied'
    STATUS_CHOICES = [
        (STATUS_SUCCESS, 'Success'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_DISCONNECTED, 'Disconnected'),
        (STATUS_PENDING_AGENT, 'Pending agent'),
        (STATUS_DENIED, 'Denied'),
    ]

    network = models.ForeignKey(
        WiFiNetwork, null=True, blank=True, on_delete=models.SET_NULL, related_name='connection_logs'
    )
    ssid = models.CharField(max_length=255, default='')
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='wifi_connection_logs')
    connection_status = models.CharField(max_length=24, choices=STATUS_CHOICES, default=STATUS_PENDING_AGENT)
    detail = models.CharField(max_length=255, blank=True, default='')
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f'{self.ssid}: {self.connection_status}'

    def to_dict(self):
        return {
            'id': self.id,
            'ssid': self.ssid,
            'network': self.network_id,
            'connection_status': self.connection_status,
            'detail': self.detail,
            'timestamp': self.timestamp.isoformat(),
        }
