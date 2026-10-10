from django.contrib import admin

from .models import ConnectionLog, PasswordAccessLog, SavedWiFiProfile, ScanHistory, WiFiNetwork


@admin.register(SavedWiFiProfile)
class SavedWiFiProfileAdmin(admin.ModelAdmin):
    list_display = ('name', 'security', 'has_key_material', 'is_connected', 'interface', 'last_seen')
    list_filter = ('is_connected', 'has_key_material')
    search_fields = ('name', 'interface')
    ordering = ('name',)
    readonly_fields = ('name', 'security', 'has_key_material', 'is_connected', 'interface', 'first_seen', 'last_seen')


@admin.register(PasswordAccessLog)
class PasswordAccessLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'user', 'profile_name', 'action', 'status', 'detail')
    list_filter = ('action', 'status')
    search_fields = ('profile_name', 'detail', 'user__username')
    ordering = ('-timestamp',)
    readonly_fields = ('user', 'profile_name', 'action', 'status', 'detail', 'timestamp')


@admin.register(WiFiNetwork)
class WiFiNetworkAdmin(admin.ModelAdmin):
    list_display = ('ssid', 'bssid', 'signal_strength', 'signal_class', 'security_type', 'is_connected', 'last_seen')
    list_filter = ('security_type', 'is_connected')
    search_fields = ('ssid', 'bssid')
    ordering = ('-signal_strength',)


@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    list_display = ('scan_time', 'total_networks', 'strongest_signal', 'weakest_signal', 'connected_ssid', 'source')
    list_filter = ('source',)
    ordering = ('-scan_time',)


@admin.register(ConnectionLog)
class ConnectionLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'ssid', 'connection_status', 'user', 'detail')
    list_filter = ('connection_status',)
    search_fields = ('ssid', 'detail')
    ordering = ('-timestamp',)
