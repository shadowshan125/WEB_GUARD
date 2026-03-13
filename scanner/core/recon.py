import socket
import dns.resolver
from urllib.parse import urlparse
import requests

class ReconEngine:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.domain = self.parsed_url.netloc.split(':')[0]
        self.results = {
            'domain': self.domain,
            'ip_address': None,
            'server_banner': None,
            'technologies': [],
            'dns_records': {},
            'open_ports': []
        }

    def resolve_ip(self):
        """Resolves the domain to an IP address."""
        try:
            self.results['ip_address'] = socket.gethostbyname(self.domain)
        except socket.gaierror:
            self.results['ip_address'] = None

    def fetch_dns_records(self):
        """Fetches common DNS records (A, MX, TXT, NS)."""
        records = ['A', 'MX', 'TXT', 'NS']
        for record_type in records:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                self.results['dns_records'][record_type] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
                self.results['dns_records'][record_type] = []

    def fetch_http_info(self):
        """Fetches basic HTTP information like Server banner and Headers."""
        try:
            # Setting a timeout and a generic User-Agent
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebGuard/1.0'}
            response = requests.get(self.target_url, headers=headers, timeout=10, allow_redirects=True)
            
            # Extract Server Banner
            server_header = response.headers.get('Server')
            if server_header:
                self.results['server_banner'] = server_header
                
            # Basic WAF/CDN detection heuristics
            if 'cloudflare' in str(server_header).lower():
                self.results['technologies'].append('Cloudflare')
            if 'x-powered-by' in response.headers:
                self.results['technologies'].append(response.headers['x-powered-by'])
                
        except requests.RequestException as e:
            pass # Keep it simple for the framework

    def run(self):
        """Executes all recon modules."""
        self.resolve_ip()
        self.fetch_dns_records()
        self.fetch_http_info()
        return self.results
