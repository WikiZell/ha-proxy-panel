# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_all

esphome_datas, esphome_binaries, esphome_hiddenimports = collect_all("esphome")

a = Analysis(
    ["ha_proxy_panel_flasher.py"],
    pathex=["."],
    binaries=esphome_binaries,
    datas=esphome_datas,
    hiddenimports=esphome_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="HA-Proxy-Panel-Manager",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
