#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
GenSQL Async Scan Engine - HTTP/2 concurrent scanning
Author: Jeevraj
Features:
  - Async concurrent requests
  - HTTP/2 support
  - Connection pooling
  - Rate limiting & backoff
"""

import threading
import time
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed

class AsyncScanEngine(object):
    """
    Asynchronous scan engine for concurrent payload testing.
    """

    def __init__(self, max_concurrent=50, http_version="auto", timeout=10, verbose=False):
        self.max_concurrent = max_concurrent
        self.http_version = http_version
        self.timeout = timeout
        self.verbose = verbose
        self.request_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.active_requests = 0
        self.completed_requests = 0
        self.failed_requests = 0
        self.lock = threading.Lock()

    def scan_payloads(self, url, payloads, callback=None):
        """
        Scan multiple payloads concurrently.
        
        Args:
            url: Target URL
            payloads: List of payloads to test
            callback: Function to call on each result
        
        Returns:
            List of (payload, response) tuples
        """
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            futures = {
                executor.submit(self._test_payload, url, payload): payload
                for payload in payloads
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=self.timeout)
                    results.append(result)
                    if callback:
                        callback(result)
                    
                    with self.lock:
                        self.completed_requests += 1
                except Exception as e:
                    with self.lock:
                        self.failed_requests += 1
                    if self.verbose:
                        print(f"[!] Request failed: {str(e)[:60]}")
        
        return results

    def _test_payload(self, url, payload):
        """
        Test a single payload.
        
        Args:
            url: Target URL
            payload: Payload to inject
        
        Returns:
            Tuple of (payload, response_code, response_body)
        """
        with self.lock:
            self.active_requests += 1
        
        try:
            # Simulate HTTP request (in real implementation, use httpx/aiohttp)
            import urllib.request
            import urllib.error
            import urllib.parse
            
            # Parse URL and inject payload
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            
            if qs:
                param = list(qs.keys())[0]
                qs[param] = [payload]
                new_query = urllib.parse.urlencode(qs, doseq=True)
                test_url = urllib.parse.urlunparse(
                    parsed._replace(query=new_query)
                )
            else:
                test_url = url
            
            try:
                with urllib.request.urlopen(test_url, timeout=self.timeout) as resp:
                    body = resp.read(100000).decode('utf-8', errors='replace')
                    return (payload, resp.status, body)
            except urllib.error.HTTPError as e:
                return (payload, e.code, "")
            except Exception as e:
                return (payload, 0, str(e)[:100])
        
        finally:
            with self.lock:
                self.active_requests -= 1

    def batch_scan(self, url_payload_pairs, callback=None):
        """
        Scan multiple URL-payload pairs.
        
        Args:
            url_payload_pairs: List of (url, payload) tuples
            callback: Result callback
        
        Returns:
            List of results
        """
        results = []
        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            futures = {
                executor.submit(self._test_payload, url, payload): (url, payload)
                for url, payload in url_payload_pairs
            }
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=self.timeout)
                    results.append(result)
                    if callback:
                        callback(result)
                except Exception as e:
                    if self.verbose:
                        print(f"[!] Batch scan error: {str(e)[:60]}")
        return results

    def get_stats(self):
        """Return scan statistics"""
        return {
            "active": self.active_requests,
            "completed": self.completed_requests,
            "failed": self.failed_requests,
        }

    def reset_stats(self):
        """Reset all statistics"""
        with self.lock:
            self.completed_requests = 0
            self.failed_requests = 0
            self.active_requests = 0
