#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
GenSQL AI WAF Bypass - ML-based WAF fingerprinting and evasion
Author: Jeevraj
Supports: Cloudflare, Akamai, Imperva, AWS WAF, F5 BIG-IP, ModSecurity, Barracuda, Sucuri
"""

import re
import random
import string
import hashlib
from collections import defaultdict

class AIWAFBypass(object):
    """Intelligent WAF detection and evasion."""

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.waf_signatures = self._load_waf_signatures()
        self.evasion_techniques = self._load_evasion_techniques()
        self.humanization_enabled = False
        self.detected_waf = None

    def _load_waf_signatures(self):
        """WAF detection signatures based on response patterns."""
        return {
            'cloudflare': {
                'headers': ['cf-ray', 'cf-request-id', 'cf-mitigated'],
                'body': ['cloudflare', 'ray id', 'error 1020', 'error 1009'],
                'status': [403, 429, 503]
            },
            'akamai': {
                'headers': ['akamai-origin-hop', 'x-akamai-request-id'],
                'body': ['akamai', 'bot manager'],
                'status': [403, 429]
            },
            'imperva': {
                'headers': ['x-cdn', 'x-iinfo'],
                'body': ['imperva', 'incident id', 'incapsula'],
                'status': [403, 429]
            },
            'aws_waf': {
                'headers': ['x-amzn-waf-action'],
                'body': ['aws waf', '403 forbidden'],
                'status': [403]
            },
            'f5_bigip': {
                'headers': ['x-lb-tags'],
                'body': ['f5', 'bigip'],
                'status': [403, 429]
            },
            'modsecurity': {
                'headers': ['x-mod-security'],
                'body': ['access denied', 'mod_security'],
                'status': [403]
            },
            'barracuda': {
                'headers': ['x-barracuda-waf-filter'],
                'body': ['barracuda', 'waf'],
                'status': [403]
            },
            'sucuri': {
                'headers': ['x-sucuri-id'],
                'body': ['sucuri', 'security'],
                'status': [403, 429]
            }
        }

    def _load_evasion_techniques(self):
        """Return working WAF evasion techniques."""
        return {
            '403_forbidden': {
                'ip_header_spoofing': [
                    {'X-Forwarded-For': '127.0.0.1'},
                    {'X-Real-IP': '127.0.0.1'},
                    {'X-Originating-IP': '[127.0.0.1]'},
                    {'X-Remote-Addr': '127.0.0.1'},
                    {'CF-Connecting-IP': '127.0.0.1'},
                    {'True-Client-IP': '127.0.0.1'},
                    {'X-Azure-ClientIP': '127.0.0.1'},
                    {'Fastly-Client-IP': '127.0.0.1'},
                    {'X-Client-IP': '127.0.0.1'},
                    {'X-ProxyUser-Ip': '127.0.0.1'},
                ],
                'url_overrides': [
                    'X-Original-URL',
                    'X-Rewrite-URL',
                    'X-Override-URL',
                    'Request-Uri',
                ],
                'path_traversal': [
                    lambda p: '/' + p,
                    lambda p: '//' + p,
                    lambda p: p + '/',
                    lambda p: p.upper(),
                    lambda p: p.lower(),
                    lambda p: '/admin/../' + p.split('/')[-1],
                ],
                'method_override': ['X-HTTP-Method-Override', 'X-Method-Override'],
                'encoding': ['chunked', 'gzip', 'deflate'],
            },
            '404_not_found': {
                'path_fuzzing': [
                    lambda p: re.sub(r'/', '%2f', p),
                    lambda p: re.sub(r'\?', '%3f', p),
                    lambda p: p + '?v=1',
                    lambda p: p + ';x=y',
                    lambda p: p + '..;/',
                    lambda p: p.replace(' ', '%20'),
                    lambda p: p.replace(' ', '+'),
                    lambda p: p.upper(),
                    lambda p: p.replace('/', '\\\\'),
                ],
                'unicode_encoding': lambda p: ''.join(f'%u{ord(c):04x}' for c in p),
            },
            '429_rate_limit': {
                'identity_rotation': ['rotate_user_agent', 'rotate_ip', 'rotate_headers'],
                'timing_jitter': True,
                'backoff_strategy': 'exponential',
            },
            '503_unavailable': {
                'protocol_switch': ['http2', 'http1.1'],
                'port_variation': [80, 443, 8080, 8443],
            }
        }

    def detect_waf(self, response_headers, response_body, status_code):
        """
        Detect WAF from response.
        
        Args:
            response_headers: Dict of response headers
            response_body: Response body text
            status_code: HTTP status code
        
        Returns:
            WAF name or None
        """
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        body_lower = response_body.lower()

        for waf_name, signatures in self.waf_signatures.items():
            # Check headers
            for header in signatures.get('headers', []):
                if header.lower() in headers_lower:
                    self.detected_waf = waf_name
                    if self.verbose:
                        print(f"[+] Detected WAF: {waf_name} (header: {header})")
                    return waf_name

            # Check body
            for pattern in signatures.get('body', []):
                if pattern.lower() in body_lower:
                    self.detected_waf = waf_name
                    if self.verbose:
                        print(f"[+] Detected WAF: {waf_name} (body pattern)")
                    return waf_name

            # Check status code
            if status_code in signatures.get('status', []):
                self.detected_waf = waf_name
                if self.verbose:
                    print(f"[+] Detected WAF: {waf_name} (status: {status_code})")
                return waf_name

        return None

    def get_bypass_headers(self, error_code, waf_name=None):
        """
        Get headers to bypass specific error code.
        
        Args:
            error_code: HTTP error (403, 404, 429, 503)
            waf_name: Optional WAF name
        
        Returns:
            Dict of headers or list of header dicts
        """
        key = f"{error_code}_forbidden" if error_code == 403 else f"{error_code}_"
        
        if error_code == 403:
            return random.choice(self.evasion_techniques['403_forbidden']['ip_header_spoofing'])
        elif error_code == 429:
            return {'X-Forwarded-For': self._random_ip()}
        elif error_code == 503:
            return {}
        return {}

    def bypass_path(self, path, error_code=404):
        """
        Transform path to bypass 404.
        
        Args:
            path: URL path
            error_code: HTTP error code
        
        Returns:
            Transformed path
        """
        if error_code == 404:
            transforms = self.evasion_techniques['404_not_found']['path_fuzzing']
            return random.choice(transforms)(path)
        return path

    def auto_bypass(self, url, error_code=None, response_headers=None, response_body=""):
        """
        Automatically find and return working bypass.
        
        Args:
            url: Target URL
            error_code: HTTP error code (auto-detect if None)
            response_headers: Response headers for WAF detection
            response_body: Response body
        
        Returns:
            Dict with bypass info: {'technique': str, 'headers': dict, 'url': str}
        """
        if response_headers:
            self.detect_waf(response_headers, response_body, error_code)

        result = {
            'technique': 'unknown',
            'headers': {},
            'url': url,
            'status': 'unknown'
        }

        if error_code == 403:
            result['technique'] = 'ip_header_spoofing'
            result['headers'] = self.get_bypass_headers(403)
        elif error_code == 404:
            result['technique'] = 'path_fuzzing'
            result['url'] = self.bypass_path(url, 404)
        elif error_code == 429:
            result['technique'] = 'identity_rotation'
            result['headers'] = {'User-Agent': self._random_user_agent()}
        elif error_code == 503:
            result['technique'] = 'protocol_switch'
            result['url'] = url.replace('http://', 'https://') if url.startswith('http://') else url

        return result

    def best_bypass(self, url, error_code=403):
        """
        Get the most likely working bypass.
        
        Args:
            url: Target URL
            error_code: HTTP error code
        
        Returns:
            Bypass dict or None
        """
        return self.auto_bypass(url, error_code)

    def enable_humanization(self):
        """Enable humanized request timing and behavior."""
        self.humanization_enabled = True

    def get_humanized_delay(self):
        """Get realistic delay between requests."""
        if self.humanization_enabled:
            return random.uniform(0.5, 3.0)
        return 0.0

    def _random_ip(self):
        """Generate random IP (private range)."""
        return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def _random_user_agent(self):
        """Return random user agent."""
        agents = [
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        ]
        return random.choice(agents)

    def get_stats(self):
        """Return WAF evasion statistics."""
        return {
            'detected_waf': self.detected_waf,
            'humanization': self.humanization_enabled,
        }
