# f5mkuPy examples

This directory contains the below examples:

- [example.ipynb](example.ipynb) - iphython notebook with cli and python examples.
- [tmconf_migrate_secrets.py](tmconf_migrate_secrets.py) - python script to migrate bigip*.conf files from one f5mku to a new f5mku key.

## tmconf_migrate_secrets.py


Partial bigip.conf:

```sh
cat <<'EOF' > partial_bigip.conf
ltm profile http http_encrypted_cookie {
    encrypt-cookie-secret $M$a5$aN5T54P8HpAU6tjBWSFcFQ==
    encrypt-cookies { CookieName }
}
ltm persistence cookie encrypted_cookie_persistence {
    cookie-encryption required
    cookie-encryption-passphrase $M$0R$qWOqGDNDRFsadpueQtUXxwBDMV17KJUEP4uDVuJE3Ls=
}
sys snmp {
    users {
        snmp_user {
            auth-password $M$94$JoV46NWhBTc2/C8iEiq+bQ==
            auth-protocol sha256
            privacy-password $M$oR$W698cPIUCI6u73Go0qXhTA==
            privacy-protocol aes256
            username snmp_user
        }
    }
}
sys file ssl-key rsa.key {
    checksum SHA1:1766:7a1a1fb0aa1e73d0a298f9cf673bad33967b80bc
    key-size 2048
    mode 33184
    passphrase $M$ot$tjQRL4+Md7egq3uxcYIN8g==
    revision 1
    security-type password
    size 1766
}
EOF
```


Run tmconf_migrate_secrets.py to decrypt secrets:

```sh
export F5MKU="BHDLd0bbao1VlwpTk1sioQ=="
tmconf_migrate_secrets.py -s partial_bigip.conf --source-f5mku $F5MKU
```

Run tmconf_migrate_secrets.py to re-encrypt secrets with a new F5 MKU key:

```sh
export F5MKU="BHDLd0bbao1VlwpTk1sioQ=="
export NEW_F5MKU="ukDKiN3j4YfWPI8FPbZLoA=="
tmconf_migrate_secrets.py -s partial_bigip.conf --source-f5mku $F5MKU --target-f5mku $NEW_F5MKU
```