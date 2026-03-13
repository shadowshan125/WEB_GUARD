from django.core.management.base import BaseCommand
from scanner.core.crawler import CrawlerEngine
from scanner.utils.logger import Logger

class Command(BaseCommand):
    help = 'Crawl a target URL to discover endpoints and forms'

    def add_arguments(self, parser):
        parser.add_argument('url', type=str, help='The target URL')
        parser.add_argument('--depth', type=int, default=2, help='Crawling depth')
        parser.add_argument('--max', type=int, default=100, help='Max URLs to visit')

    def handle(self, *args, **kwargs):
        target_url = kwargs['url']
        depth = kwargs['depth']
        max_urls = kwargs['max']
        
        Logger.info(f"Starting Web Crawler on {target_url} (Depth: {depth}, Max: {max_urls})...")

        # Run Crawler Engine
        engine = CrawlerEngine(target_url, max_depth=depth, max_urls=max_urls)
        endpoints, forms = engine.run()

        Logger.success(f"Crawling completed! Discovered {len(endpoints)} endpoints and {len(forms)} forms.")
        
        if endpoints:
            Logger.info("Sample Endpoints:")
            for ep in endpoints[:5]:
                print(f"  - {ep}")
            if len(endpoints) > 5:
                print(f"  ... and {len(endpoints)-5} more.")

        self.stdout.write(self.style.SUCCESS('Successfully completed crawl operation.'))
