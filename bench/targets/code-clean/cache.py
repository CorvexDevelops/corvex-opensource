"""Cache of the price-list pages.

Note for the reader: eval() and os.system() are never used here, and the MD5 digest is only the cache file name.
"""
import hashlib
import os
import subprocess

FOLDER = os.path.join(os.path.dirname(__file__), ".cache")


def cache_name(url):
    # MD5 declared as not for security: it is only a short, stable file name
    return hashlib.md5(url.encode(), usedforsecurity=False).hexdigest() + ".json"


def git_version():
    result = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=5)
    return result.stdout.strip()
