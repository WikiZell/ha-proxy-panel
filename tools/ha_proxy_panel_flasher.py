#!/usr/bin/env python3
"""Launch the HA Proxy Panel desktop app or its bundled ESPHome runtime."""

import runpy
import os
import sys
from pathlib import Path


def run_bundled_python_script() -> bool:
    """Execute helper scripts spawned by ESPHome from the frozen runtime."""
    if len(sys.argv) < 2:
        return False
    script = Path(sys.argv[1])
    if script.suffix.casefold() != ".py" or not script.is_file():
        return False
    for directory in reversed(os.environ.get("PYTHONPATH", "").split(os.pathsep)):
        if directory and directory not in sys.path:
            sys.path.insert(0, directory)
    sys.argv = sys.argv[1:]
    runpy.run_path(str(script), run_name="__main__")
    return True


if __name__ == "__main__":
    if run_bundled_python_script():
        raise SystemExit(0)
    from ha_proxy_panel_app import main, run_bundled_esphome

    if "--esphome-cli" in sys.argv:
        raise SystemExit(run_bundled_esphome())
    main()
