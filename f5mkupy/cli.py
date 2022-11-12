# -*- coding: utf-8 -*-
"""CLI for f5mkupy."""

# pylint: disable=line-too-long

import argparse

from . import __description__, __homepage__, __license__, __projectname__, __version__
from .f5mku import decrypt, encrypt, extract_salt


def _cli_arg_parser():
    """Build cli argument parser and return args object."""
    parser = argparse.ArgumentParser(
        prog=__projectname__,
        description=__description__,
        epilog=f"LICENSE: {__license__}, homepage: {__homepage__}",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    sub_parser = parser.add_subparsers(dest="function")
    sp_encrypt = sub_parser.add_parser(
        "encrypt", help="Encrypt plaintext string to F5 formatted ciphertext."
    )
    sp_decrypt = sub_parser.add_parser(
        "decrypt", help="Decrypt F5 formatted ciphertext to plaintext string."
    )
    sp_extract_salt = sub_parser.add_parser(
        "extract_salt", help="Extract salt from F5 formatted ciphertext."
    )
    sp_encrypt.add_argument(
        "-k",
        "--f5mku",
        type=str,
        required=True,
        help="f5mku base64 key, retrieved by: f5mku -K",
    )
    sp_encrypt.add_argument("-s", "--salt", type=str, help="Optional salt.")
    sp_encrypt.add_argument("plaintext", type=str, help="Plaintext string to encrypt.")

    sp_decrypt.add_argument(
        "-k",
        "--f5mku",
        type=str,
        required=True,
        help="f5mku base64 key, retrieved by: f5mku -K",
    )
    sp_decrypt.add_argument(
        "ciphertext",
        type=str,
        help="Ciphertext in F5 format (as listed in *.conf files).",
    )

    sp_extract_salt.add_argument(
        "ciphertext",
        type=str,
        help="Ciphertext in F5 format (as listed in *.conf files).",
    )

    return parser.parse_args()


def cli():
    """Handle CLI interaction."""
    args = _cli_arg_parser()
    if args.function == "encrypt":
        result = encrypt(plaintext=args.plaintext, f5mku=args.f5mku, salt=args.salt)
    elif args.function == "decrypt":
        result = decrypt(ciphertext=args.ciphertext, f5mku=args.f5mku)
    elif args.function == "extract_salt":
        result = extract_salt(ciphertext=args.ciphertext)

    print(result)
