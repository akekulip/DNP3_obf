#!/usr/bin/env python3
"""Report the environment a reproduction ran in, so a number can be tied to a toolchain."""
import platform
import sys


def main():
    print("python            %s (%s)" % (platform.python_version(), sys.executable))
    print("platform          %s" % platform.platform())
    for mod in ("numpy", "scipy", "sklearn", "matplotlib"):
        try:
            m = __import__(mod)
            print("%-17s %s" % (mod, getattr(m, "__version__", "unknown")))
        except ImportError:
            print("%-17s MISSING" % mod)
    print("capture parsing   analysis/pcap_reader.py (no third-party dependency)")


if __name__ == "__main__":
    main()
