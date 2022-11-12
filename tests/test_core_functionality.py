# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,missing-module-docstring,missing-function-docstring,missing-class-docstring,invalid-name
from f5mkupy.f5mku import decrypt, encrypt, extract_salt

from .testdata import EXAMPLE_DATASET, F5MKU_K


class Test_Extract_Salt:
    def test_types(self):
        assert isinstance(extract_salt("$M$salt$Y2lwaGVydGV4dA=="), str)

    def test_function(self):
        assert extract_salt("$M$salt$Y2lwaGVydGV4dA==") == "salt"


class Test_Encrypt:
    def test_function_predefined_salt(self):
        for example in EXAMPLE_DATASET:
            _ciphertext = encrypt(
                plaintext=example.get("plaintext"),
                f5mku=F5MKU_K,
                salt=example.get("salt"),
            )
            assert _ciphertext == example.get("ciphertext_raw")

    def test_function_random_salt(self):
        """Can't use pre build ciphertexts to compare to,
        use decrypt to validate proper formatting and salt generation"""
        for example in EXAMPLE_DATASET:
            _ciphertext = encrypt(
                plaintext=example.get("plaintext"),
                f5mku=F5MKU_K,
            )
            _plaintext = decrypt(ciphertext=_ciphertext, f5mku=F5MKU_K)
            assert _plaintext == example.get("plaintext")

    def test_types(self):
        example = EXAMPLE_DATASET[1]
        _ciphertext = encrypt(
            plaintext=example.get("plaintext"), f5mku=F5MKU_K, salt=example.get("salt")
        )
        assert isinstance(_ciphertext, str)


class Test_Decrypt:
    def test_function(self):
        for example in EXAMPLE_DATASET:
            _plaintext = decrypt(
                ciphertext=example.get("ciphertext_raw"),
                f5mku=F5MKU_K,
            )
            assert _plaintext == example.get("plaintext")

    def test_types(self):
        example = EXAMPLE_DATASET[1]
        _plaintext = decrypt(ciphertext=example.get("ciphertext_raw"), f5mku=F5MKU_K)
        assert isinstance(_plaintext, str)
