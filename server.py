#!/usr/bin/env python3
"""Root entry so `python3 server.py` and the systemd unit keep working."""

from sag.server import main

if __name__ == "__main__":
    main()
