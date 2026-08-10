#!/usr/bin/env python3
"""Launch the HA Proxy Panel desktop app."""

import sys

from ha_proxy_panel_app import main, run_bundled_esphome


if __name__ == "__main__":
    if "--esphome-cli" in sys.argv:
        raise SystemExit(run_bundled_esphome())
    main()
