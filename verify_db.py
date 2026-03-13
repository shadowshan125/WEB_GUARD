import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'webguard.settings')
django.setup()

from scanner.models import ScanTarget, ReconData, ScanResult, Vulnerability

print("=== Targets ===")
for t in ScanTarget.objects.all():
    print(f"[{t.id}] {t.url} - {t.domain} (IP: {t.ip_address})")

print("\n=== Recon Data ===")
for r in ReconData.objects.all():
    print(f"[{r.id}] Target: {r.target.url} | Server: {r.server_banner} | DNS: {r.dns_records}")

print("\n=== Scan Results ===")
for sc in ScanResult.objects.all():
    print(f"[{sc.id}] Type: {sc.scan_type} | Status: {sc.status} | Vulnerabilities Found: {sc.vulnerabilities.count()}")

print("\n=== Vulnerabilities ===")
for v in Vulnerability.objects.all():
    print(f"[{v.id}] [{v.severity}] {v.name} at {v.endpoint}")
