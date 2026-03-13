import aiohttp
import asyncio
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

class XSSScanner:
    def __init__(self, target_url, payloads_file="scanner/payloads/xss.txt"):
        self.target_url = target_url
        self.payloads = self._load_payloads(payloads_file)

    def _load_payloads(self, filepath):
        try:
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return ["<script>alert(1)</script>", "javascript:alert(1)"]

    def _inject_payload(self, url, param, payload):
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        # Inject payload into specific param
        query_params[param] = [payload]
        
        new_query = urlencode(query_params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    async def _test_param(self, session, url, param, payload):
        injected_url = self._inject_payload(url, param, payload)
        try:
            async with session.get(injected_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                content = await response.text()
                
                # Check if the payload is reflected in the source
                if payload in content:
                    return {
                        'name': 'Reflected Cross-Site Scripting (XSS)',
                        'severity': 'HIGH',
                        'endpoint': url,
                        'parameter': param,
                        'description': 'The application reflects user input unmodified back into the page response. This allows execution of arbitrary JavaScript in the victim\'s browser.',
                        'remediation': 'Implement context-aware output encoding. Validate all user input.',
                        'proof_of_concept': f"Payload: {payload}\nInjected URL: {injected_url}"
                    }
        except Exception:
            pass
        return None

    async def scan(self, endpoints):
        """Scans a list of endpoints with query parameters for Reflected XSS."""
        findings = []
        async with aiohttp.ClientSession() as session:
            tasks = []
            for ep in endpoints:
                parsed = urlparse(ep)
                params = parse_qs(parsed.query)
                for param in params.keys():
                    for payload in self.payloads:
                        tasks.append(self._test_param(session, ep, param, payload))
            
            # Run tasks concurrently
            if tasks:
                results = await asyncio.gather(*tasks)
                seen = set()
                for res in results:
                    if res:
                        # Bug fix: deduplicate by (endpoint, parameter) — the same vulnerable
                        # param found via multiple payloads is ONE finding, not many
                        key = (res['endpoint'], res['parameter'])
                        if key not in seen:
                            seen.add(key)
                            findings.append(res)
                        
        return findings
