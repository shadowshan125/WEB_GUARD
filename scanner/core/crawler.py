import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urldefrag, urlparse

class CrawlerEngine:
    def __init__(self, start_url, max_depth=2, max_urls=100):
        self.start_url = start_url
        self.domain = urlparse(start_url).netloc
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited = set()
        self.urls_to_visit = [(start_url, 0)]  # (url, depth)
        self.discovered_endpoints = set()
        self.forms_found = []

    async def fetch(self, session, url):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' in content_type:
                        return await response.text()
        except Exception:
            pass
        return None

    def extract_links_and_forms(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        
        # Extract links
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(base_url, href)
            full_url, _ = urldefrag(full_url)
            
            # Only stay within the domain
            if urlparse(full_url).netloc == self.domain:
                self.discovered_endpoints.add(full_url)
                
        # Extract basic forms
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = [{'name': i.get('name'), 'type': i.get('type')} for i in form.find_all('input') if i.get('name')]
            form_url = urljoin(base_url, action)
            
            self.forms_found.append({
                'url': form_url,
                'method': method,
                'inputs': inputs
            })

    async def crawl(self):
        # Bug fix: add start_url to discovered_endpoints so it's always in the return value
        self.discovered_endpoints.add(self.start_url)

        async with aiohttp.ClientSession() as session:
            while self.urls_to_visit and len(self.visited) < self.max_urls:
                current_batch = self.urls_to_visit[:10]  # Process 10 at a time
                self.urls_to_visit = self.urls_to_visit[10:]

                tasks = []
                for url, depth in current_batch:
                    if url not in self.visited and depth <= self.max_depth:
                        self.visited.add(url)
                        tasks.append((url, depth, asyncio.create_task(self.fetch(session, url))))

                for url, depth, task in tasks:
                    html = await task
                    if html:
                        # Bug fix: snapshot endpoints before extraction to detect only newly added ones
                        before = set(self.discovered_endpoints)
                        self.extract_links_and_forms(html, url)
                        newly_found = self.discovered_endpoints - before

                        # Bug fix: only queue newly discovered endpoints, not all endpoints every time
                        if depth < self.max_depth:
                            for endp in newly_found:
                                if endp not in self.visited:
                                    self.urls_to_visit.append((endp, depth + 1))

        return list(self.discovered_endpoints), self.forms_found

    def run(self):
        """Standard synchronous wrapper to run the async crawler."""
        return asyncio.run(self.crawl())
