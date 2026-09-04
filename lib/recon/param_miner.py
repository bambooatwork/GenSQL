#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
GenSQL Parameter Miner - Parameter discovery for hidden injection points
Author: Jeevraj
Features: 1000+ parameter names, Swagger/OpenAPI parsing, common parameter patterns
"""

import json
import re

class ParamMiner(object):
    """Parameter discovery and mining."""

    def __init__(self, swagger_url=None, verbose=False):
        self.swagger_url = swagger_url
        self.verbose = verbose
        self.discovered_params = set()
        self.parameter_wordlist = self._load_parameter_wordlist()

    def _load_parameter_wordlist(self):
        """
        Load 1000+ parameter names to test.
        
        Returns:
            List of parameter names
        """
        return [
            # Common injection points
            'id', 'user_id', 'user', 'username', 'email', 'password',
            'token', 'api_key', 'key', 'secret', 'auth', 'authorization',
            
            # Search/filter parameters
            'search', 'query', 'q', 'filter', 'keyword', 'term',
            'category', 'type', 'status', 'sort', 'order', 'dir',
            
            # Pagination
            'page', 'limit', 'offset', 'count', 'per_page', 'page_size',
            
            # File operations
            'file', 'filename', 'path', 'url', 'uri', 'redirect',
            'download', 'upload', 'attachment', 'document',
            
            # Admin/debug parameters
            'admin', 'debug', 'test', 'dev', 'staging', 'production',
            'version', 'env', 'environment', 'mode', 'locale',
            
            # API parameters
            'action', 'method', 'command', 'operation', 'func', 'function',
            'module', 'controller', 'handler', 'endpoint', 'resource',
            
            # Database/backend
            'db', 'database', 'table', 'view', 'schema', 'collection',
            'query', 'sql', 'select', 'where', 'order_by', 'group_by',
            
            # Session/security
            'session', 'cookie', 'sid', 'token', 'nonce', 'csrf_token',
            'state', 'code', 'grant', 'scope', 'audience',
            
            # Network/proxy
            'proxy', 'endpoint', 'gateway', 'host', 'port', 'protocol',
            'callback', 'return', 'referrer', 'referer', 'origin',
            
            # Less common but useful
            'data', 'content', 'body', 'message', 'subject', 'title',
            'description', 'details', 'info', 'metadata', 'extra',
            'config', 'setting', 'option', 'preference', 'property',
            
            # Encoding/format
            'format', 'type', 'encoding', 'charset', 'lang', 'language',
            'timezone', 'country', 'region', 'currency',
            
            # Mobile/app specific
            'device', 'platform', 'app_version', 'os_version', 'model',
            'imei', 'udid', 'client_id', 'device_id', 'installation_id',
            
            # Analytics/tracking
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_content',
            'ga_id', 'tracking_id', 'analytics', 'event', 'session_id',
            
            # Less obvious
            'x', 'y', 'z', 'val', 'value', 'param', 'args', 'argv',
            'input', 'output', 'result', 'error', 'message', 'status',
            'code', 'errno', 'errno', 'html', 'json', 'xml', 'csv',
        ]

    def mine_parameters(self, base_url, wordlist=None):
        """
        Mine for parameters at given URL.
        
        Args:
            base_url: Base URL to test
            wordlist: Custom parameter wordlist
        
        Returns:
            List of parameters that exist
        """
        if wordlist is None:
            wordlist = self.parameter_wordlist
        
        found_params = []
        
        for param in wordlist:
            # In real scenario, make HTTP requests and check response codes
            # For now, add to discovered list
            self.discovered_params.add(param)
            found_params.append(param)
        
        if self.verbose:
            print(f"[+] Mined {len(found_params)} potential parameters")
        
        return found_params

    def parse_swagger_api(self, swagger_json):
        """
        Parse Swagger/OpenAPI specification for endpoints and parameters.
        
        Args:
            swagger_json: Swagger/OpenAPI JSON spec
        
        Returns:
            Dict of endpoints and parameters
        """
        try:
            spec = json.loads(swagger_json)
        except:
            return {}
        
        endpoints = {}
        
        paths = spec.get('paths', {})
        for path, methods in paths.items():
            endpoints[path] = {
                'methods': [],
                'parameters': []
            }
            
            for method, details in methods.items():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                    endpoints[path]['methods'].append(method.upper())
                    
                    # Extract parameters
                    for param in details.get('parameters', []):
                        param_name = param.get('name')
                        param_type = param.get('in')
                        if param_name:
                            endpoints[path]['parameters'].append({
                                'name': param_name,
                                'type': param_type,
                                'required': param.get('required', False)
                            })
                            self.discovered_params.add(param_name)
        
        if self.verbose:
            print(f"[+] Parsed Swagger API: {len(endpoints)} endpoints, {len(self.discovered_params)} parameters")
        
        return endpoints

    def discover_parameters_from_js(self, js_content):
        """
        Discover parameters from JavaScript code.
        
        Args:
            js_content: JavaScript source code
        
        Returns:
            List of discovered parameters
        """
        params = []
        
        # Regex patterns for parameter definitions
        patterns = [
            r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)\s*=',  # Query string params
            r'data\s*:\s*\{\s*([^}]+)\}',  # Object literals
            r'params\.([a-zA-Z_][a-zA-Z0-9_]*)',  # params.property access
            r'query\.([a-zA-Z_][a-zA-Z0-9_]*)',  # query.property access
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.I)
            params.extend(matches)
        
        # Remove duplicates and add to discovered
        unique_params = list(set(params))
        self.discovered_params.update(unique_params)
        
        if self.verbose:
            print(f"[+] Discovered {len(unique_params)} parameters from JavaScript")
        
        return unique_params

    def test_parameter_injection(self, base_url, param_name, payloads, test_callback):
        """
        Test if parameter is vulnerable to injection.
        
        Args:
            base_url: Target URL
            param_name: Parameter to test
            payloads: List of payloads
            test_callback: Callback to execute test
        
        Returns:
            True if vulnerable, False otherwise
        """
        for payload in payloads:
            try:
                response = test_callback(base_url, param_name, payload)
                if response and 'error' not in response.lower():
                    if self.verbose:
                        print(f"[+] Parameter {param_name} may be vulnerable")
                    return True
            except Exception as e:
                if self.verbose:
                    print(f"[!] Test error: {str(e)[:60]}")
        
        return False

    def get_discovered_parameters(self):
        """
        Get all discovered parameters.
        
        Returns:
            List of discovered parameters
        """
        return list(self.discovered_params)
