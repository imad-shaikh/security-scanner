# This file is intentionally vulnerable for testing the scanner.

import hashlib


def hash_password(password):
    return hashlib.md5(password.encode("utf-8")).hexdigest()
