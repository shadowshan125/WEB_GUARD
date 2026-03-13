from django.core.management.base import BaseCommand
from scanner.core.recon import ReconEngine
from scanner.core.crawler import CrawlerEngine
from scanner.engine.vulnerability_engine import VulnerabilityEngine
from scanner.engine.risk_scoring import RiskScoringEngine
from scanner.report.report_generator import ReportGenerator
from scanner.models import ScanTarget, ReconData, ScanResult, Vulnerability
from scanner.utils.logger import Logger
from django.utils import timezone

class Command(BaseCommand):
    help = 'Run a full vulnerability scan on a target URL'

    def add_arguments(self, parser):
        parser.add_argument('url', type=str, help='The target URL')
        parser.add_argument('--full-scan', action='store_true', help='Execute crawl and vulnerability scan')
        parser.add_argument('--depth', type=int, default=2, help='Crawling depth')
        parser.add_argument('--max-urls', type=int, default=100, help='Max URLs to crawl')

    def handle(self, *args, **kwargs):
        target_url = kwargs['url']
        full_scan = kwargs['full_scan']
        depth = kwargs['depth']
        max_urls = kwargs['max_urls']

        Logger.info(f"Starting WebGuard Security Scan on {target_url}...")

        # Initialize Target and Database Records
        target, _ = ScanTarget.objects.get_or_create(url=target_url)
        scan_record = ScanResult.objects.create(target=target, scan_type='full' if full_scan else 'recon')

        # Bug fix: wrap all scan phases so the record is always marked failed on error
        try:
            # Phase 1: Reconnaissance
            Logger.info("[Phase 1] Target Intelligence Gathering")
            recon_engine = ReconEngine(target_url)
            recon_results = recon_engine.run()

            target.domain = recon_results['domain']
            target.ip_address = recon_results['ip_address']
            target.save()

            ReconData.objects.update_or_create(
                target=target,
                defaults={
                    'server_banner': recon_results.get('server_banner'),
                    'technologies': recon_results.get('technologies', []),
                    'dns_records': recon_results.get('dns_records', {}),
                    'open_ports': recon_results.get('open_ports', [])
                }
            )
            Logger.success(f"Intel gathered. IP: {recon_results['ip_address']}, Technologies: {recon_results['technologies']}")

            if not full_scan:
                scan_record.status = 'completed'
                scan_record.completed_at = timezone.now()
                scan_record.save()
                Logger.info("Scan mode set to 'recon' only. Stopping.")
                return

            # Phase 2: Crawling
            Logger.info(f"\n[Phase 2] Web Crawling (Depth: {depth}, Max: {max_urls})")
            crawler = CrawlerEngine(target_url, max_depth=depth, max_urls=max_urls)
            endpoints, _ = crawler.run()
            Logger.success(f"Discovered {len(endpoints)} unique internal endpoints.")

            # If zero endpoints found by crawler, at least scan the root URL
            if not endpoints:
                endpoints = [target_url]

            # Phase 3: Vulnerability Scanning
            Logger.info("\n[Phase 3] Vulnerability Assessment")
            vuln_engine = VulnerabilityEngine(target_url, discovered_endpoints=endpoints)
            findings = vuln_engine.run()

            # Risk Scoring
            overall_risk, total_score = RiskScoringEngine.calculate_overall_risk(findings)
            Logger.info(f"Scan complete. Overall Risk Level: {overall_risk}")

            # Save findings to database
            for f in findings:
                Vulnerability.objects.create(
                    scan=scan_record,
                    name=f['name'],
                    severity=f['severity'],
                    endpoint=f['endpoint'],
                    parameter=f.get('parameter', ''),
                    description=f.get('description', ''),
                    remediation=f.get('remediation', ''),
                    proof_of_concept=f.get('proof_of_concept', '')
                )

            scan_record.status = 'completed'
            scan_record.completed_at = timezone.now()
            scan_record.save()

            # Phase 4: Reporting
            Logger.info("\n[Phase 4] Report Generation")
            report_gen = ReportGenerator(target_url, recon_results, findings)
            report_gen.generate_all()

            self.stdout.write(self.style.SUCCESS(f'\nScan successfully completed. View reports in the reports/ directory.'))

        except Exception as e:
            # Bug fix: always mark the scan as failed so stale 'running' records don't accumulate
            scan_record.status = 'failed'
            scan_record.completed_at = timezone.now()
            scan_record.save()
            Logger.error(f"Scan failed: {e}")
            raise
