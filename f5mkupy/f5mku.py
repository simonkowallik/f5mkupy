# -*- coding: utf-8 -*-
"""Main functions for f5mkupy."""

import secrets
import string
from base64 import b64decode, b64encode
from collections import namedtuple
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

F5Ciphertext = namedtuple("F5Ciphertext", "salt ciphertext")
F5Plaintext = namedtuple("F5Plaintext", "salt plaintext")

__all__ = [
    "encrypt",
    "decrypt",
    "extract_salt",
]


def encrypt(plaintext: str, f5mku: str, salt: Optional[str] = None) -> str:
    """Encrypts `plaintext` with `f5mku` and optional `salt`.
    Examples:
        >>> encrypt("KEY45678", "BHDLd0bbao1VlwpTk1sioQ==")
        '$M$AF$03xWNNGWB3UeKSCKU0HNXw=='
        >>> encrypt("KEY45678", "BHDLd0bbao1VlwpTk1sioQ==", salt="ab")
        '$M$ab$mmIL9xEWGe7pbNtvS/QAQA=='
    Args:
        plaintext (str): plaintext string to encrypt.
        f5mku (str): f5mku base64 key.
        salt (str): Optional salt to use instead of generating a random salt.
    Returns:
        F5 formatted ciphertext as found in F5 config files.
    """
    _plaintext = _force_bytes(plaintext)
    _f5mku = _f5mku_decode(f5mku)

    f5plaintext = _salt_plaintext(plaintext=_plaintext, salt=salt)
    _ciphertext = _encryptor(salted_plaintext=f5plaintext.plaintext, key=_f5mku)

    return _format_ciphertext(ciphertext=_ciphertext, salt=f5plaintext.salt)


def decrypt(ciphertext: str, f5mku: str) -> str:
    """Decrypts `ciphertext` with `f5mku` key.
    Examples:
        >>> decrypt("$M$iP$rr0su9oHn9J9p1t3nRzydA==", "BHDLd0bbao1VlwpTk1sioQ==")
        'KEY45678'
    Args:
        ciphertext (str): F5 formatted ciphertext string to decrypt.
        f5mku (str): f5mku base64 key.
    Returns:
        Plaintext.
    """
    _f5_ciphertext = _deconstruct_ciphertext(ciphertext)
    _f5mku = _f5mku_decode(f5mku)
    _salted_plaintext = _decryptor(ciphertext=_f5_ciphertext.ciphertext, key=_f5mku)
    _plaintext = _remove_salt(plaintext=_salted_plaintext, salt=_f5_ciphertext.salt)
    return _force_str(_plaintext)


def extract_salt(ciphertext: str) -> str:
    """Extracts the salt from the F5 formatted `ciphertext` string.
    Examples:
        >>> extract_salt("$M$iP$rr0su9oHn9J9p1t3nRzydA==")
        'iP'
    Args:
        ciphertext (str): F5 formatted ciphertext string as found in the conf files.
    Returns:
        The salt string.
    """
    f5ciphertext = _deconstruct_ciphertext(ciphertext)
    return _force_str(f5ciphertext.salt)


def _encryptor(salted_plaintext: bytes, key: bytes) -> bytes:
    """Performs cryptographic operation of encrypting the `salted_plaintext` with given `key`."""
    encryptor = Cipher(
        algorithm=algorithms.AES(key), mode=modes.ECB(), backend=default_backend()
    ).encryptor()
    padder = padding.PKCS7(algorithms.AES(key).block_size).padder()
    padded_data = padder.update(salted_plaintext) + padder.finalize()
    encrypted_text = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_text


def _decryptor(ciphertext: bytes, key: bytes) -> bytes:
    """Performs cryptographic operation of decrypting the `ciphertext` with given `key`."""
    decryptor = Cipher(
        algorithm=algorithms.AES(key), mode=modes.ECB(), backend=default_backend()
    ).decryptor()
    unpadder = padding.PKCS7(algorithms.AES(key).block_size).unpadder()
    decrypted_data = decryptor.update(ciphertext)
    unpadded = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded


def _f5mku_decode(f5mku: str) -> bytes:
    """Decodes base64 encoded F5MKU key."""
    try:
        _f5mku = b64decode(f5mku)
        _ = algorithms.AES(_f5mku)  # test if provided f5mku key is a valid AES key

    except Exception as exc:
        # pylint: disable=line-too-long
        raise ValueError(
            "decoding of f5mku failed. Make sure you are using the base64 formatted key returned by command: f5mku -K"
        ) from exc

    return _f5mku


def _generate_salt(length: Optional[int] = 2) -> bytes:
    """Generates a salt (alpha characters)."""
    _salt = "".join(secrets.choice(string.ascii_letters) for i in range(length))
    return _force_bytes(_salt)


def _remove_salt(plaintext: bytes, salt: bytes) -> bytes:
    """Removes given salt from plaintext."""
    if plaintext.startswith(salt):
        return plaintext[len(salt):]

    raise ValueError(f"Plaintext ({plaintext}) does not start with salt {salt}")


def _salt_plaintext(plaintext: bytes, salt: Optional[str] = None) -> F5Plaintext:
    """Either uses provided `salt` or generates new salt to add to `plaintext`."""
    if salt is None:
        _salt = _generate_salt()
    else:
        _salt = _force_bytes(salt)
    return F5Plaintext(_salt, _salt + plaintext)


def _deconstruct_ciphertext(ciphertext: str) -> F5Ciphertext:
    """Deconstructs the F5 formatted ciphertext as found in F5 configuration files."""
    # "$M$iP$rr0su9oHn9J9p1t3nRzydA==" -> ['', 'M', 'iP', 'rr0su9oHn9J9p1t3nRzydA==']
    try:
        (_f5start, _f5type, _salt, _ciphertext) = ciphertext.split("$")
    except ValueError as exc:
        # pylint: disable=line-too-long
        raise ValueError(
            f"Unrecognized ciphertext: Ciphertext is to have 4 elements, separated by '$' char. provided ciphertext has:{ciphertext.count('$')}"
        ) from exc

    if (_f5start, _f5type) != ("", "M"):
        raise ValueError(
            "Unrecognized ciphertext: Ciphertext is expected to start with '$M'."
        )
    if _salt == "":
        raise ValueError("Unrecognized ciphertext: Empty salt is not supported.")
    if _ciphertext == "":
        raise ValueError("Unrecognized ciphertext: Empty ciphertext is not supported.")

    _salt = _force_bytes(_salt)
    _ciphertext = b64decode(_ciphertext)

    return F5Ciphertext(_salt, _ciphertext)


def _format_ciphertext(ciphertext: bytes, salt: bytes) -> str:
    """Creates F5 format of `ciphertext` and `salt`."""
    _ciphertext = b64encode(ciphertext)
    _ciphertext = _force_str(_ciphertext)
    _salt = _force_str(salt)
    return "$".join(["", "M", _salt, _ciphertext])


def _force_bytes(value) -> bytes:
    """force `s` to bytes"""
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return bytes(value)
    return str(value).encode("utf-8")


def _force_str(value) -> str:
    """force `s` to str"""
    if issubclass(type(value), str):
        return value
    if isinstance(value, bytes):
        value = str(value, "utf-8")
    else:
        value = str(value)
    return value
