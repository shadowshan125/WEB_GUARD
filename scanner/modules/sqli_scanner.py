import aiohttp
import asyncio
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

class SQLiScanner:
    def __init__(self, target_url, payloads_file="scanner/payloads/sqli.txt"):
        self.target_url = target_url
        self.payloads = self._load_payloads(payloads_file)

    def _load_payloads(self, filepath):
        try:
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return ["' OR '1'='1", "1' ORDER BY 1--+"]

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
                
                # Basic Error-based SQLi heuristics
                error_signatures = [
                    "you have an error in your sql syntax",
                    "warning: mysql",
                    "unclosed quotation mark after the character string",
                    "quoted string not properly terminated",
                    "pg_query(): query failed"
                ]
                
                if any(error in content.lower() for error in error_signatures):
                    return {
                        'name': 'SQL Injection (Error Based)',
                        'severity': 'CRITICAL',
                        'endpoint': url,
                        'parameter': param,
                        'description': 'An error indicating a database query failure was found, suggesting the parameter is vulnerable to SQL injection.',
                        'remediation': 'Use parameterized queries or prepared statements.',
                        'proof_of_concept': f"Payload: {payload}\nInjected URL: {injected_url}"
                    }
        except Exception:
            pass
        return None

    async def scan(self, endpoints):
        """Scans a list of endpoints with query parameters for SQLi."""
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
