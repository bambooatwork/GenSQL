#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
JeevSQL - Enhanced SQL Injection & Web Security Assessment Framework
lib/techniques/cloud/__init__.py

Cloud/Serverless injection techniques package initializer.

Author: Jeevraj
Framework: JeevSQL (based on sqlmap)
"""

from lib.techniques.cloud.lambda_inject import CloudInjector

__all__ = ["CloudInjector"]
__author__ = "Jeevraj"
__version__ = "1.0.0"
