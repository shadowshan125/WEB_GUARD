import aiohttp
import asyncio

class HeadersScanner:
    def __init__(self, target_url):
        self.target_url = target_url

    async def _check_headers(self, session):
        findings = []
        try:
            async with session.get(self.target_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                headers = response.headers
                
                # Missing Security Headers check
                security_headers = {
                    'Strict-Transport-Security': 'Missing HSTS header makes the site vulnerable to downgrade attacks.',
                    'X-Frame-Options': 'Missing X-Frame-Options makes the site vulnerable to Clickjacking.',
                    'X-Content-Type-Options': 'Missing X-Content-Type-Options makes the site vulnerable to MIME-sniffing.',
                    'Content-Security-Policy': 'Missing CSP increases the risk and impact of XSS attacks.'
                }
                
                for header, description in security_headers.items():
                    if header not in headers:
                        findings.append({
                            'name': f'Missing Security Header: {header}',
                            'severity': 'LOW',
                            'endpoint': self.target_url,
                            'parameter': 'Header',
                            'description': description,
                            'remediation': f'Configure the server to include the {header} header.',
                            'proof_of_concept': f"Request to {self.target_url} returned headers: {list(headers.keys())}"
                        })
                        
                # Server Version Disclosure check
                server = headers.get('Server')
                if server and any(x in str(server).lower() for x in ['apache', 'nginx', 'iis', 'php']):
                    findings.append({
                        'name': 'Server Version Disclosure',
                        'severity': 'INFO',
                        'endpoint': self.target_url,
                        'parameter': 'Server Header',
                        'description': 'The server discloses its version which may help attackers identify specific vulnerabilities.',
                        'remediation': 'Configure the web server to obscure or remove the Server header.',
                        'proof_of_concept': f"Server: {server}"
                    })
                        
        except Exception:
            pass
        return findings

    async def scan(self, endpoints=None):
        """Scans the base target URL for HTTP header misconfigurations."""
        async with aiohttp.ClientSession() as session:
            return await self._check_headers(session)
