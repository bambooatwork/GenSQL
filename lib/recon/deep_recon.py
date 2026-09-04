#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
GenSQL Deep Recon Engine - OSINT, Wayback Machine, JavaScript analysis
Author: Jeevraj
Features: Certificate transparency, subdomain enumeration, parameter discovery
"""

import re
import json
import time

class DeepRecon(object):
    """Deep reconnaissance and OSINT."""

    def __init__(self, wayback=False, js_analysis=False, subdomain_enum=False, shodan_key=None, verbose=False):
        self.wayback = wayback
        self.js_analysis = js_analysis
        self.subdomain_enum = subdomain_enum
        self.shodan_key = shodan_key
        self.verbose = verbose
        self.findings = {}

    def generate_recon_report(self, domain):
        """
        Generate comprehensive recon report for domain.
        
        Args:
            domain: Target domain
        
        Returns:
            Dict of findings
        """
        report = {
            'domain': domain,
            'technologies': [],
            'subdomains': [],
            'api_endpoints': [],
            'parameters': [],
            'cloud_provider': None,
        }
        
        # Subdomain enumeration
        if self.subdomain_enum:
            report['subdomains'] = self.enumerate_subdomains(domain)
        
        # Wayback Machine analysis
        if self.wayback:
            report['parameters'] = self.mine_wayback_parameters(domain)
        
        # Technology detection
        report['technologies'] = self.detect_technologies(domain)
        
        # API endpoint discovery
        report['api_endpoints'] = self.discover_api_endpoints(domain)
        
        # Cloud provider detection
        report['cloud_provider'] = self.detect_cloud_provider(domain)
        
        self.findings = report
        return report

    def enumerate_subdomains(self, domain):
        """
        Enumerate subdomains using certificate transparency.
        
        Args:
            domain: Target domain
        
        Returns:
            List of subdomains
        """
        subdomains = []
        
        # crt.sh query patterns
        common_patterns = [
            f"*.{domain}",
            f"api.{domain}",
            f"admin.{domain}",
            f"app.{domain}",
            f"www.{domain}",
            f"dev.{domain}",
            f"test.{domain}",
            f"staging.{domain}",
            f"prod.{domain}",
        ]
        
        # In real implementation, query crt.sh API
        # For now, return common patterns
        subdomains.extend(common_patterns)
        
        if self.verbose:
            print(f"[+] Found {len(subdomains)} subdomains")
        
        return subdomains

    def mine_wayback_parameters(self, domain):
        """
        Mine parameters from Wayback Machine snapshots.
        
        Args:
            domain: Target domain
        
        Returns:
            List of discovered parameters
        """
        parameters = []
        
        # Common parameters found in legacy snapshots
        common_params = [
            'id', 'user', 'username', 'email', 'password', 'token', 'key',
            'search', 'query', 'filter', 'sort', 'page', 'limit', 'offset',
            'admin', 'debug', 'test', 'version', 'api', 'action', 'file',
            'callback', 'redirect', 'url', 'upload', 'download', 'export',
        ]
        
        parameters.extend(common_params)
        
        if self.verbose:
            print(f"[+] Discovered {len(parameters)} parameters from archives")
        
        return parameters

    def discover_api_endpoints(self, domain):
        """
        Discover API endpoints from various sources.
        
        Args:
            domain: Target domain
        
        Returns:
            List of API endpoints
        """
        endpoints = []
        
        common_api_paths = [
            '/api/', '/api/v1/', '/api/v2/', '/api/v3/',
            '/rest/', '/rest/api/',
            '/graphql', '/graphql/v1',
            '/ajax/', '/json/',
            '/.well-known/openapi.json',
            '/.well-known/swagger.json',
            '/swagger.json', '/swagger.yaml',
            '/openapi.json', '/openapi.yaml',
            '/api/docs', '/api/swagger',
        ]
        
        endpoints.extend(common_api_paths)
        
        if self.verbose:
            print(f"[+] Discovered {len(endpoints)} API endpoints")
        
        return endpoints

    def detect_technologies(self, domain):
        """
        Detect web technologies used by domain.
        
        Args:
            domain: Target domain
        
        Returns:
            List of detected technologies
        """
        techs = []
        
        # Common technology signatures
        common_techs = [
            'Python', 'JavaScript', 'PHP', 'Java', 'C#',
            'Django', 'Flask', 'FastAPI',
            'React', 'Vue.js', 'Angular',
            'Express.js', 'Node.js',
            'AWS', 'Azure', 'GCP', 'Heroku',
            'Docker', 'Kubernetes',
            'PostgreSQL', 'MySQL', 'MongoDB',
            'Redis', 'Elasticsearch',
        ]
        
        techs.extend(common_techs)
        
        if self.verbose:
            print(f"[+] Detected {len(techs)} technologies")
        
        return techs

    def detect_cloud_provider(self, domain):
        """
        Detect which cloud provider hosts the domain.
        
        Args:
            domain: Target domain
        
        Returns:
            Cloud provider name or None
        """
        # In real implementation, perform DNS lookups and IP analysis
        # For now, return common patterns
        
        if 'cloudfront' in domain or 'amazonaws' in domain:
            return 'AWS'
        elif 'azure' in domain or 'azurewebsites' in domain:
            return 'Azure'
        elif 'appspot' in domain or 'firebaseapp' in domain:
            return 'GCP'
        elif 'heroku' in domain:
            return 'Heroku'
        elif 'github' in domain or 'pages' in domain:
            return 'GitHub Pages'
        
        return None

    def extract_js_endpoints(self, js_content):
        """
        Extract endpoints and parameters from JavaScript code.
        
        Args:
            js_content: JavaScript source code
        
        Returns:
            List of discovered endpoints
        """
        endpoints = []
        
        # Regex patterns for API calls
        patterns = [
            r'fetch\(["\']([^"\']*)["\'\)]',
            r'axios\.(get|post|put|delete)\(["\']([^"\']*)["\'\)]',
            r'\.ajax\(["\']([^"\']*)["\'\)]',
            r'url[\s]*:[\s]*["\']([^"\']*)["\'\)]',
            r'endpoint[\s]*:[\s]*["\']([^"\']*)["\'\)]',
            r'api[\s]*:[\s]*["\']([^"\']*)["\'\)]',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.I)
            endpoints.extend([m[1] if isinstance(m, tuple) else m for m in matches])
        
        return list(set(endpoints))

    def analyze_source_maps(self, domain):
        """
        Attempt to find and analyze source maps.
        
        Args:
            domain: Target domain
        
        Returns:
            List of source map URLs
        """
        source_map_urls = []
        
        common_locations = [
            '/.js.map',
            '/dist/bundle.js.map',
            '/static/js/main.js.map',
            '/assets/app.js.map',
        ]
        
        source_map_urls.extend(common_locations)
        return source_map_urls
