from django.db import models

class ScanTarget(models.Model):
    url = models.URLField(unique=True, help_text="The base URL of the target")
    domain = models.CharField(max_length=255, blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url

class ReconData(models.Model):
    target = models.OneToOneField(ScanTarget, on_delete=models.CASCADE, related_name='recon_data')
    server_banner = models.CharField(max_length=255, blank=True, null=True)
    technologies = models.JSONField(default=list, blank=True, help_text="List of detected technologies")
    dns_records = models.JSONField(default=dict, blank=True, help_text="DNS resolution data")
    open_ports = models.JSONField(default=list, blank=True)
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Recon Data for {self.target.url}"

class ScanResult(models.Model):
    target = models.ForeignKey(ScanTarget, on_delete=models.CASCADE, related_name='scans')
    scan_type = models.CharField(max_length=50, help_text="e.g., 'full', 'recon', 'vuln'")
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    status = models.CharField(max_length=20, default='running', choices=[
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ])
    
    def __str__(self):
        return f"Scan {self.id} on {self.target}"

class Vulnerability(models.Model):
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
        ('INFO', 'Informational'),
    ]

    scan = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='vulnerabilities')
    name = models.CharField(max_length=255, help_text="Vulnerability Name (e.g., 'SQL Injection')")
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='INFO')
    endpoint = models.URLField(max_length=1024, help_text="The affected URL/Endpoint")
    parameter = models.CharField(max_length=255, blank=True, null=True, help_text="Vulnerable parameter if applicable")
    proof_of_concept = models.TextField(blank=True, null=True, help_text="Payload or response snippet")
    description = models.TextField(blank=True, null=True)
    remediation = models.TextField(blank=True, null=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.severity}] {self.name} on {self.endpoint}"
