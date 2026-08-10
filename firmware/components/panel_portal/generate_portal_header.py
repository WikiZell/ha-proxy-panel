#!/usr/bin/env python3
"""Build the deterministic gzip byte array embedded in the ESP32 firmware."""

from __future__ import annotations

import gzip
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "portal.html"
TARGET = ROOT / "portal_index.h"


def main() -> None:
    compressed = gzip.compress(SOURCE.read_bytes(), compresslevel=9, mtime=0)
    rows = []
    for offset in range(0, len(compressed), 16):
        chunk = compressed[offset : offset + 16]
        rows.append("  " + ", ".join(f"0x{byte:02x}" for byte in chunk) + ",")
    target = """#pragma once
#include <cstdint>
#include "esphome/core/hal.h"

namespace esphome::panel_portal {
constexpr uint8_t PORTAL_INDEX_GZ[] PROGMEM = {
%s
};
}  // namespace esphome::panel_portal
""" % "\n".join(rows)
    TARGET.write_text(target, encoding="utf-8", newline="\n")
    print(f"Generated {TARGET.name}: {len(compressed)} bytes")


if __name__ == "__main__":
    main()
