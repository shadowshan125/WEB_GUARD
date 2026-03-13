from django.core.management.base import BaseCommand
from scanner.core.recon import ReconEngine
from scanner.models import ScanTarget, ReconData
from scanner.utils.logger import Logger

class Command(BaseCommand):
    help = 'Perform reconnaissance on a target URL'

    def add_arguments(self, parser):
        parser.add_argument('url', type=str, help='The target URL')

    def handle(self, *args, **kwargs):
        target_url = kwargs['url']
        Logger.info(f"Starting Reconnaissance on {target_url}...")

        # Run Recon Engine
        engine = ReconEngine(target_url)
        results = engine.run()

        # Save to Database
        target, created = ScanTarget.objects.get_or_create(
            url=target_url,
            defaults={'domain': results['domain'], 'ip_address': results['ip_address']}
        )

        ReconData.objects.update_or_create(
            target=target,
            defaults={
                'server_banner': results.get('server_banner'),
                'technologies': results.get('technologies', []),
                'dns_records': results.get('dns_records', {}),
                'open_ports': results.get('open_ports', [])
            }
        )

        Logger.success("Reconnaissance completed!")
        Logger.info(f"Domain: {results['domain']}")
        Logger.info(f"IP Address: {results['ip_address']}")
        Logger.info(f"Server Banner: {results['server_banner']}")
        Logger.info(f"Technologies: {', '.join(results['technologies'])}")
        
        self.stdout.write(self.style.SUCCESS('Successfully completed recon operation.'))
