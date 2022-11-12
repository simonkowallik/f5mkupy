# f5mkuPy

[![CI Pipeline](https://github.com/simonkowallik/f5mkupy/actions/workflows/ci-pipeline.yaml/badge.svg)](https://github.com/simonkowallik/f5mkupy/actions/workflows/ci-pipeline.yaml)
[![Maintainability](https://api.codeclimate.com/v1/badges/aed3f2ca1e1bb196e692/maintainability)](https://codeclimate.com/github/simonkowallik/f5mkupy/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/aed3f2ca1e1bb196e692/test_coverage)](https://codeclimate.com/github/simonkowallik/f5mkupy/test_coverage)

_f5mkupy allows to `encrypt` and `decrypt` data using the format found in F5 BIG-IP `bigip*.conf` files with the key retrieved by `f5mku -K`._

- Free software: ISC license
- Works with Python 3.8 and up (and probably before)

## What can f5mkuPy help you with?

`f5mkuPy` helps you to:

- decrypt
- encrypt
- and compare

secrets stored inline within `bigip*.conf` files.

This can be helpful in various scenarios, for example during migrations or idempotent desired state checks.

`f5mkuPy` offers a command line interface and can be used as a python module as well.

Have a look in the [examples/](examples/) folder for details.

## Usage

### A quick command line walk-through.

```bash
# f5mku -K
F5MKU_KEY='BHDLd0bbao1VlwpTk1sioQ=='

# secret within a bigip*.conf file
BIGIP_CONF_CIPHERTEXT='$M$bn$btwo4IWf6ZpYap4QWG8DsJqnB2xW9HLv1VOAmMeIa0U='

# expected plaintext of that secret
PLAINTEXT_SECRET='secret_encryption_key'


# decryption
plaintext=$(
    f5mkupy decrypt -k $F5MKU_KEY $BIGIP_CONF_CIPHERTEXT
)
[[ "$plaintext" == "$PLAINTEXT_SECRET" ]] && echo true
# true

# encryption with random salt
ciphertext=$(
    f5mkupy encrypt -k $F5MKU_KEY $PLAINTEXT_SECRET
)
[[ ! "$ciphertext" == "$BIGIP_CONF_CIPHERTEXT" ]] && echo true
# true

# encryption using same salt as used in the bigip*.conf ciphertext
salt=$(f5mkupy extract_salt $BIGIP_CONF_CIPHERTEXT)
ciphertext=$(
    f5mkupy encrypt -k $F5MKU_KEY -s $salt $PLAINTEXT_SECRET
)
[[ "$ciphertext" == "$BIGIP_CONF_CIPHERTEXT" ]] && echo true
# true

```

### A quick python module walk-through.

```python
from f5mkupy import decrypt, encrypt, extract_salt

# f5mku -K
F5MKU_KEY='BHDLd0bbao1VlwpTk1sioQ=='

# secret within a bigip*.conf file
BIGIP_CONF_CIPHERTEXT='$M$bn$btwo4IWf6ZpYap4QWG8DsJqnB2xW9HLv1VOAmMeIa0U='

# expected plaintext of that secret
PLAINTEXT_SECRET='secret_encryption_key'

# decryption
plaintext = decrypt(
        ciphertext=BIGIP_CONF_CIPHERTEXT,
        f5mku=F5MKU_KEY
    )
assert plaintext == PLAINTEXT_SECRET

# encryption with random salt
ciphertext = encrypt(
        plaintext=PLAINTEXT_SECRET,
        f5mku=F5MKU_KEY
    )
assert not ( ciphertext == BIGIP_CONF_CIPHERTEXT ) # what are the odds? :)

# encryption using same salt as used in the bigip*.conf ciphertext
ciphertext = encrypt(
        plaintext=PLAINTEXT_SECRET,
        f5mku=F5MKU_KEY,
        salt=extract_salt(ciphertext=BIGIP_CONF_CIPHERTEXT)
    )
assert ciphertext == BIGIP_CONF_CIPHERTEXT
```

## Disclaimer

f5mkupy is not a commercial product and is not covered by any form of support, there is no contract nor SLA. Please read, understand and adhere to the license before use.
