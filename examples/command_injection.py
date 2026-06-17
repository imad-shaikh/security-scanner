# This file is intentionally vulnerable for testing the scanner.

import os


def ping_host(hostname):
    os.system("ping -c 1 " + hostname)
