#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import re
from f5mkupy import decrypt, encrypt, extract_salt

def _cli_arg_parser():
    """CLI argument parser"""
    parser = argparse.ArgumentParser(
        description="""This script parses `source-config-file` and decrypts found secrets using `source-f5mku`.
        It optionally re-encrypts the secret using `target-f5mku` and either prints to STDOUT or writes to `target-config-file`.""",
        epilog="License: ISC, homepage: https://github.com/simonkowallik/f5mkupy"
    )
    parser.add_argument(
        "-s",
        "--source-config-file",
        type=argparse.FileType("r"),
        required=True,
        help="Source bigip*.conf file",
    )
    parser.add_argument(
        "-t",
        "--target-config-file",
        type=argparse.FileType("w"),
        help="[Optional] Target bigip*.conf file",
    )
    parser.add_argument(
        "--source-f5mku", type=str, required=True, help="f5mku of source (used to decrypt)"
    )
    parser.add_argument("--target-f5mku", type=str, help="[Optional] f5mku for target (used to re-encrypt)")

    return parser.parse_args()


def search_ciphertext(string: str):
    """search for a secret within `string` and return it, otherwise return `None`."""
    # pattern to match secret format
    pattern = re.compile(r"\$M\$[a-zA-Z0-9]+\$[a-zA-Z0-9+/]+={0,2}$")
    re_match = re.search(pattern, string)
    if re_match:
        # return secret if found
        return re_match.group(0)
    return None


def migrate_config_secrets(args):
    """Iterate through source config line by line and decrypt secrets with optional re-encryption"""

    for source_config_line in args.source_config_file.readlines():
        # search for a ciphertext
        ciphertext = search_ciphertext(source_config_line)

        if ciphertext:
            # decrypt ciphertext
            plaintext = decrypt(
                ciphertext=ciphertext, f5mku=args.source_f5mku
            )
            if args.target_f5mku:
                # target f5mku specified, re-encrypt with new f5mku
                target_config_text = encrypt(
                    plaintext=plaintext, f5mku=args.target_f5mku
                )
            else:
                # write secret in plaintext
                target_config_text = plaintext

            # replace existing ciphertext with plaintext or new ciphertext
            source_config_line = source_config_line.replace(
                ciphertext, target_config_text
            )

        if args.target_config_file:
            # write to specified target config file
            args.target_config_file.write(source_config_line)
        else:
            # print to stdout
            print(source_config_line, end="")


if __name__ == "__main__":
    args = _cli_arg_parser()
    migrate_config_secrets(args)
