import os
import yaml
import asyncio
import aiohttp
from scanner.utils.logger import Logger
from scanner.utils.helpers import normalize_url

class SignatureEngine:
    def __init__(self, templates_dir="scanner/payloads/templates"):
        self.templates_dir = templates_dir
        self.templates = self._load_templates()

    def _load_templates(self):
        templates = []
        if not os.path.exists(self.templates_dir):
            os.makedirs(self.templates_dir)
            return templates
            
        for filename in os.listdir(self.templates_dir):
            if filename.endswith(('.yaml', '.yml')):
                filepath = os.path.join(self.templates_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        template = yaml.safe_load(f)
                        if template and 'id' in template and 'requests' in template:
                            templates.append(template)
                except Exception as e:
                    Logger.error(f"Failed to load standard template {filename}: {e}")
        return templates

    async def _test_template(self, session, target_url, template):
        findings = []
        base_url = target_url.rstrip('/')
        
        for req in template.get('requests', []):
            method = req.get('method', 'GET').upper()
            paths = req.get('path', ['/'])
            
            for path in paths:
                # Interpolate URL
                url = normalize_url(base_url, path.replace('{{BaseURL}}', ''))
                
                try:
                    async with session.request(method, url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=False) as response:
                        content = await response.text()
                        status = response.status
                        headers = dict(response.headers)
                        
                        # Matchers
                        # Bug fix: ALL matchers must pass (AND logic between matchers),
                        # unless the template sets matchers-condition: or.
                        # Previously any single matcher passing would fire the alert,
                        # causing false positives (e.g. a 404 page containing "DB_PASSWORD").
                        matchers = req.get('matchers', [])
                        matchers_condition = req.get('matchers-condition', 'and')

                        if not matchers:
                            matched = False
                        else:
                            matcher_results = []
                            for matcher in matchers:
                                m_type = matcher.get('type')
                                words = matcher.get('words', [])
                                part = matcher.get('part', 'body')

                                target_data = content if part == 'body' else str(headers)
                                m_matched = False

                                if m_type == 'word':
                                    condition = matcher.get('condition', 'or')
                                    if condition == 'or':
                                        m_matched = any(w in target_data for w in words)
                                    elif condition == 'and':
                                        m_matched = all(w in target_data for w in words)
                                elif m_type == 'status':
                                    statuses = matcher.get('status', [])
                                    m_matched = status in statuses

                                matcher_results.append(m_matched)

                            if matchers_condition == 'or':
                                matched = any(matcher_results)
                            else:  # default: and
                                matched = all(matcher_results)
                                    
                        if matched:
                            severity = template.get('info', {}).get('severity', 'info').upper()
                            findings.append({
                                'name': template.get('id'),
                                'endpoint': url,
                                'severity': severity,
                                'description': template.get('info', {}).get('description', ''),
                                'remediation': template.get('info', {}).get('remediation', ''),
                                'proof_of_concept': f"Matched specific keywords or status code on {url}"
                            })
                            
                except Exception as e:
                    pass
        return findings

    async def scan(self, target_url):
        all_findings = []
        if not self.templates:
            return all_findings
            
        async with aiohttp.ClientSession() as session:
            tasks = [self._test_template(session, target_url, t) for t in self.templates]
            results = await asyncio.gather(*tasks)
            
            for res in results:
                all_findings.extend(res)
                
        return all_findings

    def run(self, target_url):
        return asyncio.run(self.scan(target_url))
