# -*- coding: utf-8 -*-
"""Top-level package for f5mku."""
from .f5mku import decrypt, encrypt, extract_salt

__all__ = [
    "encrypt",
    "decrypt",
    "extract_salt",
]
__author__ = """Simon Kowallik"""
__email__ = "github@simonkowallik.com"
__version__ = "1.0.1"  # pyproject.toml
__projectname__ = "f5mkupy"
# pylint: disable=line-too-long
__description__ = "f5mkupy allows to encrypt and decrypt data using the format used in F5 BIG-IP bigip*.conf files with the key retrieved by f5mku -K."
__license__ = "ISC"
__homepage__ = "https://github.com/simonkowallik/f5mkupy"
