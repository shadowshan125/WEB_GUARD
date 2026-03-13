from django.contrib import admin
from .models import ScanTarget, ReconData, ScanResult, Vulnerability


@admin.register(ScanTarget)
class ScanTargetAdmin(admin.ModelAdmin):
    list_display = ('url', 'domain', 'ip_address', 'created_at')
    search_fields = ('url', 'domain')


@admin.register(ReconData)
class ReconDataAdmin(admin.ModelAdmin):
    list_display = ('target', 'server_banner', 'last_updated')


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ('id', 'target', 'scan_type', 'status', 'started_at', 'completed_at')
    list_filter = ('status', 'scan_type')


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('name', 'severity', 'endpoint', 'parameter', 'discovered_at')
    list_filter = ('severity',)
    search_fields = ('name', 'endpoint', 'parameter')
