# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,missing-module-docstring,missing-function-docstring,missing-class-docstring,invalid-name
import base64
from base64 import b64decode, b64encode

import pytest

from f5mkupy.f5mku import (
    _deconstruct_ciphertext,
    _decryptor,
    _encryptor,
    _f5mku_decode,
    _force_bytes,
    _force_str,
    _format_ciphertext,
    _generate_salt,
    _remove_salt,
    _salt_plaintext,
)

from .testdata import EXAMPLE_DATASET, F5MKU_K


class Test__f5mku_decode:
    def test_function(self):
        assert _f5mku_decode(F5MKU_K) == b64decode(F5MKU_K)

    def test_invalid_key(self):
        with pytest.raises(ValueError) as e_info:
            _f5mku_decode("invalid_key")
        assert (
            str(e_info.value)
            == "decoding of f5mku failed. Make sure you are using the base64 formatted key returned by command: f5mku -K"
        )


class Test__force_:
    def test_force_bytes(self):
        assert _force_bytes("test") == b"test"
        assert _force_bytes(b"test") == b"test"
        assert _force_bytes(memoryview(bytearray("test", "utf-8"))) == b"test"

    def test_force_str(self):
        assert _force_str("test") == "test"
        assert _force_str(b"test") == "test"
        assert _force_str(5) == "5"


class Test_deconstruct_ciphertext:
    def test_types(self):
        assert isinstance(_deconstruct_ciphertext("$M$salt$Y2lwaGVydGV4dA=="), tuple)

    def test_function(self):
        # base64.b64encode(b'ciphertext').decode() == 'Y2lwaGVydGV4dA=='
        assert _deconstruct_ciphertext("$M$salt$Y2lwaGVydGV4dA==") == (
            b"salt",
            b"ciphertext",
        )

    def test_ciphertest_check_start(self):
        with pytest.raises(ValueError) as e_info:
            _deconstruct_ciphertext(
                "".join(["$", "X", "$", "salt", "$", "Y2lwaGVydGV4dA=="])
            )
        assert (
            str(e_info.value)
            == "Unrecognized ciphertext: Ciphertext is expected to start with '$M'."
        )

    def test_ciphertest_check_salt(self):
        with pytest.raises(ValueError) as e_info:
            _deconstruct_ciphertext(
                "".join(["$", "M", "$", "", "$", "Y2lwaGVydGV4dA=="])
            )
        assert (
            str(e_info.value) == "Unrecognized ciphertext: Empty salt is not supported."
        )

    def test_ciphertest_check_ciphertext(self):
        with pytest.raises(ValueError) as e_info:
            _deconstruct_ciphertext("".join(["$", "M", "$", "salt", "$", ""]))
        assert (
            str(e_info.value)
            == "Unrecognized ciphertext: Empty ciphertext is not supported."
        )

    def test_ciphertest_check_element_count(self):
        with pytest.raises(ValueError) as e_info:
            _deconstruct_ciphertext(
                "".join(
                    [
                        "$",
                        "M",
                        "$",
                        "salt",
                        "$",
                        "Y2lwaGVydGV4dA==",
                        "$",
                        "too_many_elements",
                    ]
                )
            )
        assert (
            "Unrecognized ciphertext: Ciphertext is to have 4 elements, separated by '$' char."
            in str(e_info.value)
        )

        with pytest.raises(ValueError) as e_info:
            _deconstruct_ciphertext("too_few_elements")
        assert (
            "Unrecognized ciphertext: Ciphertext is to have 4 elements, separated by '$' char."
            in str(e_info.value)
        )

    def test_ciphertest_check_base64(self):
        with pytest.raises(base64.binascii.Error) as e_info:
            _deconstruct_ciphertext(
                "".join(["$", "M", "$", "salt", "$", "this ain't base 64 :-)"])
            )
            assert isinstance(e_info.type, base64.binascii.Error)


class Test_remove_salt:
    def test_types(self):
        assert isinstance(
            _remove_salt(
                plaintext=b"SaltPlaintext",
                salt=b"Salt",
            ),
            bytes,
        )

    def test_expected_result(self):
        assert _remove_salt(plaintext=b"SaltPlaintext", salt=b"Salt") == b"Plaintext"

    def test_wrong_salt(self):
        with pytest.raises(ValueError) as e_info:
            _remove_salt(plaintext=b"PepperPlaintext", salt=b"Salt")
        assert "does not start with salt" in str(e_info.value)


class Test_generate_salt:
    def test_types(self):
        assert isinstance(_generate_salt(), bytes)

    def test_len_default(self):
        assert len(_generate_salt()) == 2

    def test_len_custom(self):
        assert len(_generate_salt(4)) == 4

    def test_salt_isalnum(self):
        _salt = _generate_salt(100)
        _salt = _salt.decode()
        assert _salt.isalnum()


class Test__format_ciphertext:
    def test_function(self):
        for example in EXAMPLE_DATASET:
            _ciphertext = _encryptor(
                salted_plaintext=example.get("salt").encode()
                + example.get("plaintext").encode(),
                key=b64decode(F5MKU_K),
            )
            assert _format_ciphertext(
                ciphertext=_ciphertext, salt=example.get("salt").encode()
            ) == example.get("ciphertext_raw")

    def test_types(self):
        example = EXAMPLE_DATASET[1]
        _ciphertext = _encryptor(
            salted_plaintext=example.get("plaintext").encode(), key=b64decode(F5MKU_K)
        )
        _ciphertext = _format_ciphertext(
            ciphertext=_ciphertext, salt=example.get("salt").encode()
        )
        assert isinstance(_ciphertext, str)


class Test__salt_plaintext:
    def test_function(self):
        for example in EXAMPLE_DATASET:
            _plaintext = _salt_plaintext(
                plaintext=example.get("plaintext").encode(), salt=example.get("salt")
            )
            assert _plaintext == (
                example.get("salt").encode(),
                example.get("salt").encode() + example.get("plaintext").encode(),
            )

    def test_function_random_salt(self):
        for example in EXAMPLE_DATASET:
            _plaintext = _salt_plaintext(plaintext=example.get("plaintext").encode())
            (_salt, _salt_and_plaintext) = _plaintext
            assert _salt_and_plaintext.decode().endswith(example.get("plaintext"))
            assert _salt_and_plaintext.decode() == _salt.decode() + example.get(
                "plaintext"
            )

    def test_types(self):
        example = EXAMPLE_DATASET[1]
        _plaintext = _salt_plaintext(
            plaintext=example.get("plaintext").encode(), salt=example.get("salt")
        )
        assert isinstance(_plaintext, tuple)
        assert isinstance(_plaintext[0], bytes)
        assert isinstance(_plaintext[1], bytes)

    def test_types_random_salt(self):
        example = EXAMPLE_DATASET[1]
        _plaintext = _salt_plaintext(plaintext=example.get("plaintext").encode())
        assert isinstance(_plaintext, tuple)
        assert isinstance(_plaintext[0], bytes)
        assert isinstance(_plaintext[1], bytes)


class Test__decryptor:
    def test_function(self):
        for example in EXAMPLE_DATASET:
            _plaintext = _decryptor(
                ciphertext=b64decode(example.get("ciphertext")), key=b64decode(F5MKU_K)
            )
            assert _plaintext.decode() == example.get("salt") + example.get("plaintext")

    def test_types(self):
        example = EXAMPLE_DATASET[1]
        _plaintext = _decryptor(
            ciphertext=b64decode(example.get("ciphertext")), key=b64decode(F5MKU_K)
        )
        assert isinstance(_plaintext, bytes)


class Test__encryptor:
    def test_function(self):
        for example in EXAMPLE_DATASET:
            _ciphertext = _encryptor(
                salted_plaintext=example.get("salt").encode()
                + example.get("plaintext").encode(),
                key=b64decode(F5MKU_K),
            )
            assert b64encode(_ciphertext).decode() == example.get("ciphertext")

    def test_types(self):
        example = EXAMPLE_DATASET[1]
        _ciphertext = _encryptor(
            salted_plaintext=example.get("plaintext").encode(), key=b64decode(F5MKU_K)
        )
        assert isinstance(_ciphertext, bytes)
