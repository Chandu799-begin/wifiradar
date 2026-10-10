from rest_framework import serializers

from .models import ConnectionLog, ScanHistory, WiFiNetwork


class WiFiNetworkSerializer(serializers.ModelSerializer):
    signal_class = serializers.CharField(read_only=True)

    class Meta:
        model = WiFiNetwork
        fields = [
            'id', 'ssid', 'bssid', 'signal_strength', 'signal_class',
            'security_type', 'frequency', 'channel', 'is_connected',
            'is_hidden', 'last_seen',
        ]
        read_only_fields = fields


class ScanHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanHistory
        fields = [
            'id', 'scan_time', 'total_networks', 'strongest_signal',
            'weakest_signal', 'connected_ssid', 'adapter', 'source',
        ]
        read_only_fields = fields


class ConnectionLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ConnectionLog
        fields = ['id', 'network', 'ssid', 'connection_status', 'detail', 'timestamp']
        read_only_fields = fields


class ConnectRequestSerializer(serializers.Serializer):
    ssid = serializers.CharField(max_length=255)
    password = serializers.CharField(
        max_length=64, required=False, allow_blank=True, write_only=True, trim_whitespace=False
    )

    def validate_ssid(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError('SSID is required.')
        if len(value) > 253:
            raise serializers.ValidationError('SSID is too long.')
        return value
