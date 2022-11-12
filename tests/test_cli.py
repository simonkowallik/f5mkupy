# -*- coding: utf-8 -*-
"""Test CLI interface"""

# pylint: disable=line-too-long,missing-function-docstring

import sys

import pytest  # pylint: disable=unused-import

from f5mkupy.cli import cli

from .testdata import EXAMPLE_DATASET, F5MKU_K


def test_cli_encrypt(monkeypatch, capfd):
    for example in EXAMPLE_DATASET:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "/path/to/program_name",
                "encrypt",
                "-k",
                F5MKU_K,
                "-s",
                example.get("salt"),
                example.get("plaintext"),
            ],
        )
        cli()
        cli_output, _ = capfd.readouterr()
        assert cli_output.rstrip() == example.get("ciphertext_raw")


def test_cli_decrypt(monkeypatch, capfd):
    for example in EXAMPLE_DATASET:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "/path/to/program_name",
                "decrypt",
                "-k",
                F5MKU_K,
                example.get("ciphertext_raw"),
            ],
        )
        cli()
        cli_output, _ = capfd.readouterr()
        assert cli_output.rstrip() == example.get("plaintext")


def test_cli_extract_salt(monkeypatch, capfd):
    for example in EXAMPLE_DATASET:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "/path/to/program_name",
                "extract_salt",
                example.get("ciphertext_raw"),
            ],
        )
        cli()
        cli_output, _ = capfd.readouterr()
        assert cli_output.rstrip() == example.get("salt")
