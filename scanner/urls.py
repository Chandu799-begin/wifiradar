from django.urls import path

from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('radar/', views.radar_page, name='radar'),
    path('networks/', views.networks_page, name='networks'),
    path('connected/', views.connected_page, name='connected'),
    path('analytics/', views.analytics_page, name='analytics'),
    path('history/', views.history_page, name='history'),
    path('settings/', views.settings_page, name='settings'),
    path('settings/save/', views.update_settings, name='update_settings'),
    path('wifi/', views.wifi_dashboard, name='wifi_dashboard'),
    path('wifi/passwords/reauth/', views.wifi_password_reauth, name='wifi_password_reauth'),
    path('wifi/passwords/reveal/', views.wifi_password_reveal, name='wifi_password_reveal'),
    path('history/export/', views.export_history, name='export_history'),

    path('api/wifi/scan/', views.ScanAPI.as_view(), name='api_scan'),
    path('api/wifi/networks/', views.NetworksAPI.as_view(), name='api_networks'),
    path('api/wifi/connected/', views.ConnectedAPI.as_view(), name='api_connected'),
    path('api/wifi/history/', views.HistoryAPI.as_view(), name='api_history'),
    path('api/wifi/saved-profiles/', views.saved_profiles_api, name='api_saved_profiles'),
    path('api/wifi/connect/', views.ConnectAPI.as_view(), name='api_connect'),
    path('api/wifi/disconnect/', views.DisconnectAPI.as_view(), name='api_disconnect'),
]
