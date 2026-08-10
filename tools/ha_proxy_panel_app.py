#!/usr/bin/env python3
"""Desktop manager, discovery tool, and flasher for HA Proxy Panel."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import http.server
import json
import os
import queue
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from vendor.qrcodegen import QrCode


APP_NAME = "HA Proxy Panel"
APP_VERSION = "1.1.0"
APP_ROOT = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share")) / "HAProxyPanel"
SETTINGS_FILE = APP_ROOT / "settings.json"
SECURE_FILE = APP_ROOT / "secure.bin"
GITHUB_REPOSITORY = "WikiZell/ha-proxy-panel"
GITHUB_PAGE = "https://github.com/WikiZell/ha-proxy-panel"
PROJECT_PAGE = "https://wikizell.github.io/ha-proxy-panel/"
KOFI_PAGE = "https://ko-fi.com/wikizell"
DEVICE_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
ENTITY_ID_RE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")


def yaml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def random_api_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def random_password(length: int = 24) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


class SecureStore:
    """Encrypt secrets for the current Windows user with DPAPI."""

    def __init__(self, path: Path) -> None:
        self.path = path

    @property
    def available(self) -> bool:
        return sys.platform == "win32"

    def _crypt(self, data: bytes, protect: bool) -> bytes:
        if not self.available:
            raise RuntimeError("Encrypted storage currently requires Windows DPAPI.")
        source_buffer = ctypes.create_string_buffer(data)
        source = DataBlob(len(data), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_byte)))
        result = DataBlob()
        flags = 0x1
        if protect:
            ok = ctypes.windll.crypt32.CryptProtectData(
                ctypes.byref(source), APP_NAME, None, None, None, flags, ctypes.byref(result)
            )
        else:
            ok = ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(source), None, None, None, None, flags, ctypes.byref(result)
            )
        if not ok:
            raise ctypes.WinError()
        try:
            return ctypes.string_at(result.pbData, result.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(result.pbData)

    def save(self, values: dict[str, object]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        encrypted = self._crypt(json.dumps(values).encode("utf-8"), True)
        self.path.write_bytes(encrypted)

    def load(self) -> dict[str, object]:
        if not self.path.exists():
            return {}
        return json.loads(self._crypt(self.path.read_bytes(), False).decode("utf-8"))


class HomeAssistantClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def request(self, path: str, data: dict[str, object] | None = None) -> object:
        body = json.dumps(data).encode("utf-8") if data is not None else None
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=12) as response:
            payload = response.read()
        return json.loads(payload) if payload else {}

    def states(self) -> list[dict[str, object]]:
        result = self.request("/api/states")
        return result if isinstance(result, list) else []

    def service(self, domain: str, service: str, data: dict[str, object]) -> object:
        return self.request(f"/api/services/{domain}/{service}", data)


class FirmwareManager:
    def __init__(self, root: Path) -> None:
        self.root = root

    def download(self) -> tuple[Path, str]:
        headers = {"User-Agent": "HA-Proxy-Panel-App", "Accept": "application/vnd.github+json"}
        request = urllib.request.Request(
            f"https://api.github.com/repos/{GITHUB_REPOSITORY}/commits/main", headers=headers
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            commit = json.load(response)
        sha = str(commit["sha"])
        raw_url = f"https://raw.githubusercontent.com/{GITHUB_REPOSITORY}/{sha}/firmware/ha-proxy-panel.yaml"
        request = urllib.request.Request(raw_url, headers={"User-Agent": "HA-Proxy-Panel-App"})
        with urllib.request.urlopen(request, timeout=20) as response:
            firmware = response.read()
        text = firmware.decode("utf-8")
        for marker in ("substitutions:", "bluetooth_proxy:", "display:", "api:"):
            if marker not in text:
                raise ValueError(f"Downloaded firmware is missing required marker: {marker}")
        destination = self.root / sha
        destination.mkdir(parents=True, exist_ok=True)
        path = destination / "ha-proxy-panel.yaml"
        path.write_bytes(firmware)
        (destination / "metadata.json").write_text(
            json.dumps(
                {
                    "repository": GITHUB_REPOSITORY,
                    "commit": sha,
                    "sha256": hashlib.sha256(firmware).hexdigest(),
                    "downloaded_at": int(time.time()),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return path, sha


@dataclass
class Panel:
    key: str
    name: str
    ip: str = ""
    source: str = "LAN"
    status: str = "unknown"
    signal: str = ""
    entities: dict[str, str] = field(default_factory=dict)
    values: dict[str, str] = field(default_factory=dict)
    node_name: str = ""


def esphome_command() -> list[str]:
    executable = shutil.which("esphome")
    return [executable] if executable else [sys.executable, "-m", "esphome"]


class ProxyPanelApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("HA Proxy Panel Manager")
        self.geometry("960x820")
        self.minsize(860, 700)
        APP_ROOT.mkdir(parents=True, exist_ok=True)
        for stale_secret in (APP_ROOT / "work").glob("*/secrets.yaml"):
            try: stale_secret.unlink()
            except OSError: pass

        self.secure_store = SecureStore(SECURE_FILE)
        self.firmware_manager = FirmwareManager(APP_ROOT / "firmware-cache")
        self.log_queue: queue.Queue[str] = queue.Queue()
        self.ui_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.worker: threading.Thread | None = None
        self.panels: dict[str, Panel] = {}
        self.settings = self._load_json(SETTINGS_FILE)
        try:
            self.secure = self.secure_store.load()
        except Exception:
            self.secure = {}

        self.ha_url = tk.StringVar(value=str(self.settings.get("ha_url", "http://homeassistant.local:8123")))
        self.ha_token = tk.StringVar(value=str(self.secure.get("ha_token", "")))
        self.ha_refresh_token = str(self.secure.get("ha_refresh_token", ""))
        self.ha_client_id = str(self.secure.get("ha_client_id", ""))
        self.remember = tk.BooleanVar(value=bool(self.settings.get("remember", True)))
        self.ha_status = tk.StringVar(value="Not connected")
        self.device_name = tk.StringVar(value=str(self.settings.get("device_name", "ha-proxy-panel")))
        self.friendly_name = tk.StringVar(value=str(self.settings.get("friendly_name", "HA Proxy Panel")))
        self.display_title = tk.StringVar(value=str(self.settings.get("display_title", "HA PROXY PANEL")))
        self.temperature_entity = tk.StringVar(value=str(self.settings.get("temperature_entity", "sensor.your_temperature_sensor")))
        self.humidity_entity = tk.StringVar(value=str(self.settings.get("humidity_entity", "sensor.your_humidity_sensor")))
        self.display_mode = tk.StringVar(value=str(self.settings.get("display_mode", "Climate")))
        self.display_rotation = tk.StringVar(value=str(self.settings.get("display_rotation", "Normal")))
        self.wifi_ssid = tk.StringVar(value=str(self.settings.get("wifi_ssid", "")))
        self.wifi_password = tk.StringVar(value=str(self.secure.get("wifi_password", "")))
        self.api_key = tk.StringVar(value=str(self.secure.get("api_key", random_api_key())))
        self.ota_password = tk.StringVar(value=str(self.secure.get("ota_password", random_password())))
        self.fallback_password = tk.StringVar(value=str(self.secure.get("fallback_password", random_password(16))))
        self.serial_port = tk.StringVar()
        self.ota_target = tk.StringVar(value=str(self.settings.get("ota_target", "ha-proxy-panel.local")))
        self.firmware_version = tk.StringVar(value="Not downloaded")
        self.live_mode = tk.StringVar(value="Climate")
        self.live_rotation = tk.StringVar(value="Normal")
        self.status = tk.StringVar(value="Ready")

        self._build_ui()
        self._install_edit_bindings()
        self.after(100, self._drain_queues)
        self.after(250, self.detect_ports)
        if self.ha_token.get().strip() or self.ha_refresh_token:
            self.after(700, self.connect_home_assistant)

    @staticmethod
    def _load_json(path: Path) -> dict[str, object]:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _build_ui(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.enable_traversal()
        self.notebook = notebook
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        self.setup_tab = ttk.Frame(notebook, padding=14)
        self.devices_tab = ttk.Frame(notebook, padding=14)
        self.flash_tab = ttk.Frame(notebook, padding=14)
        self.logs_tab = ttk.Frame(notebook, padding=10)
        self.about_tab = ttk.Frame(notebook, padding=22)
        notebook.add(self.setup_tab, text="1. Setup")
        notebook.add(self.devices_tab, text="2. Devices")
        notebook.add(self.flash_tab, text="3. Flash and Update")
        notebook.add(self.logs_tab, text="Logs")
        notebook.add(self.about_tab, text="About")
        self._build_setup()
        self._build_devices()
        self._build_flash()
        self._build_logs()
        self._build_about()
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", padx=14, pady=(0, 8))

    def _entry(self, parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, show: str = "") -> int:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=5)
        ttk.Entry(parent, textvariable=variable, show=show).grid(row=row, column=1, sticky="ew", pady=5)
        return row + 1

    def _build_setup(self) -> None:
        tab = self.setup_tab
        tab.columnconfigure(1, weight=1)
        ttk.Label(tab, text="Home Assistant connection", font=("Segoe UI", 15, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 12)
        )
        row = self._entry(tab, 1, "Home Assistant URL", self.ha_url)
        row = self._entry(tab, row, "Manual access token", self.ha_token, "*")
        ttk.Checkbutton(tab, text="Remember login and device secrets encrypted for this Windows user", variable=self.remember).grid(
            row=row, column=1, sticky="w", pady=4
        )
        row += 1
        buttons = ttk.Frame(tab)
        buttons.grid(row=row, column=1, sticky="w", pady=8)
        ttk.Button(buttons, text="Login in Home Assistant", command=self.browser_login).pack(side="left", padx=(0, 6))
        ttk.Button(buttons, text="Connect with token", command=self.connect_home_assistant).pack(side="left", padx=6)
        ttk.Button(buttons, text="Save setup", command=self.save_settings).pack(side="left", padx=6)
        ttk.Button(buttons, text="Forget encrypted login", command=self.forget_login).pack(side="left", padx=6)
        row += 1
        ttk.Label(tab, textvariable=self.ha_status, foreground="#176b3a").grid(row=row, column=1, sticky="w", pady=5)
        row += 1
        ttk.Separator(tab).grid(row=row, column=0, columnspan=3, sticky="ew", pady=16)
        row += 1
        ttk.Label(tab, text="How login works", font=("Segoe UI", 12, "bold")).grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1
        ttk.Label(
            tab,
            text=(
                "The Login button opens Home Assistant's own sign-in page. Your username, password, and MFA code "
                "stay with Home Assistant. This app receives only an access token after successful login. On Windows, "
                "saved tokens and device secrets are encrypted with DPAPI and cannot be decrypted by another Windows user."
            ),
            wraplength=800,
            justify="left",
        ).grid(row=row, column=0, columnspan=3, sticky="w", pady=8)
        row += 1
        onboarding = ttk.LabelFrame(tab, text="Phone setup for a preflashed panel", padding=12)
        onboarding.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(18, 0))
        onboarding.columnconfigure(0, weight=1)
        ttk.Label(
            onboarding,
            text=(
                "If the panel cannot join the configured Wi-Fi, it starts its own setup network after 30 seconds. "
                "Show the QR code, scan it with a phone, then follow the captive portal to choose the home Wi-Fi."
            ),
            wraplength=760,
            justify="left",
        ).grid(row=0, column=0, sticky="w", padx=(0, 12))
        ttk.Button(onboarding, text="Show phone setup QR", command=self.show_onboarding_qr).grid(row=0, column=1)

    def _build_devices(self) -> None:
        tab = self.devices_tab
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        bar = ttk.Frame(tab)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(bar, text="Search LAN and Home Assistant", command=self.refresh_devices).pack(side="left")
        ttk.Button(bar, text="Open HA integrations", command=self.open_home_assistant).pack(side="left", padx=8)
        pane = ttk.Panedwindow(tab, orient="horizontal")
        pane.grid(row=1, column=0, sticky="nsew")
        left = ttk.LabelFrame(pane, text="Discovered panels", padding=8)
        right = ttk.Frame(pane, padding=(12, 0, 0, 0))
        pane.add(left, weight=1); pane.add(right, weight=3)
        left.rowconfigure(0, weight=1); left.columnconfigure(0, weight=1)
        self.device_tree = ttk.Treeview(left, columns=("ip", "status"), show="tree headings", height=18)
        self.device_tree.heading("#0", text="Panel"); self.device_tree.column("#0", width=180, anchor="w")
        self.device_tree.heading("ip", text="IP"); self.device_tree.column("ip", width=92, anchor="w")
        self.device_tree.heading("status", text="Status"); self.device_tree.column("status", width=65, anchor="w")
        self.device_tree.grid(row=0, column=0, sticky="nsew")
        self.device_tree.bind("<<TreeviewSelect>>", self._device_selected)
        right.columnconfigure(0, weight=1); right.rowconfigure(3, weight=1)
        self.selected_panel_title = tk.StringVar(value="Select a panel")
        ttk.Label(right, textvariable=self.selected_panel_title, font=("Segoe UI", 16, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 8))
        info = ttk.LabelFrame(right, text="Panel information", padding=10)
        info.grid(row=1, column=0, sticky="ew"); info.columnconfigure(1, weight=1); info.columnconfigure(3, weight=1)
        self.device_detail_vars: dict[str, tk.StringVar] = {}
        detail_fields = (
            ("IP address", "ip"), ("Node name", "node_name"), ("Connection", "source"), ("Status", "status"),
            ("Wi-Fi signal", "signal"), ("Uptime", "uptime"), ("Firmware", "firmware_version"),
            ("Displayed temperature", "display_temperature"), ("Displayed humidity", "display_humidity"),
        )
        for index, (label, key) in enumerate(detail_fields):
            grid_row, pair = divmod(index, 2); column = pair * 2
            variable = tk.StringVar(value="-"); self.device_detail_vars[key] = variable
            ttk.Label(info, text=f"{label}:").grid(row=grid_row, column=column, sticky="w", padx=(0, 5), pady=3)
            ttk.Label(info, textvariable=variable).grid(row=grid_row, column=column + 1, sticky="w", padx=(0, 16), pady=3)

        controls = ttk.LabelFrame(right, text="Live display controls", padding=10)
        controls.grid(row=2, column=0, sticky="ew", pady=8)
        ttk.Label(controls, text="Screen").grid(row=0, column=0, padx=4)
        ttk.Combobox(controls, textvariable=self.live_mode, values=("Climate", "Temperature", "Humidity", "Proxy Status"), state="readonly", width=16).grid(row=0, column=1, padx=4)
        ttk.Label(controls, text="Rotation").grid(row=0, column=2, padx=4)
        ttk.Combobox(controls, textvariable=self.live_rotation, values=("Normal", "Rotated 180"), state="readonly", width=14).grid(row=0, column=3, padx=4)
        ttk.Button(controls, text="Apply", command=self.apply_live_settings).grid(row=0, column=4, padx=5)
        ttk.Button(controls, text="Restart", command=self.restart_selected).grid(row=0, column=5, padx=5)

        lower = ttk.Panedwindow(right, orient="vertical")
        lower.grid(row=3, column=0, sticky="nsew")
        sources = ttk.LabelFrame(lower, text="Climate data sources", padding=10)
        entities = ttk.LabelFrame(lower, text="Home Assistant entities", padding=8)
        lower.add(sources, weight=1); lower.add(entities, weight=2)
        sources.columnconfigure(1, weight=1)
        self.selected_temp_source = tk.StringVar(); self.selected_hum_source = tk.StringVar()
        ttk.Label(sources, text="Temperature").grid(row=0, column=0, sticky="w", pady=3)
        self.selected_temp_box = ttk.Combobox(sources, textvariable=self.selected_temp_source, state="normal")
        self.selected_temp_box.grid(row=0, column=1, sticky="ew", pady=3)
        ttk.Label(sources, text="Humidity").grid(row=1, column=0, sticky="w", pady=3)
        self.selected_hum_box = ttk.Combobox(sources, textvariable=self.selected_hum_source, state="normal")
        self.selected_hum_box.grid(row=1, column=1, sticky="ew", pady=3)
        source_actions = ttk.Frame(sources); source_actions.grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Button(source_actions, text="Load HA sensors", command=self.load_sensors).pack(side="left")
        ttk.Button(source_actions, text="Prepare sensor change by OTA", command=self.prepare_sensor_change).pack(side="left", padx=6)
        ttk.Label(sources, text="Sensor-source changes require an OTA firmware update.", foreground="#555555").grid(row=3, column=0, columnspan=2, sticky="w", pady=(5, 0))
        entities.rowconfigure(0, weight=1); entities.columnconfigure(0, weight=1)
        self.entity_tree = ttk.Treeview(entities, columns=("role", "entity", "state"), show="headings", height=6)
        for column, title, width in (("role", "Role", 125), ("entity", "Entity ID", 285), ("state", "State", 100)):
            self.entity_tree.heading(column, text=title); self.entity_tree.column(column, width=width, anchor="w")
        self.entity_tree.grid(row=0, column=0, sticky="nsew")

    def _combo(self, parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, attribute: str) -> int:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=5)
        box = ttk.Combobox(parent, textvariable=variable, state="normal")
        box.grid(row=row, column=1, sticky="ew", pady=5)
        box.bind("<<ComboboxSelected>>", lambda _e, var=variable: var.set(var.get().split(" | ", 1)[0]))
        setattr(self, attribute, box)
        return row + 1

    def _build_flash(self) -> None:
        tab = self.flash_tab
        tab.columnconfigure(1, weight=1)
        ttk.Label(tab, text="Panel configuration", font=("Segoe UI", 14, "bold")).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))
        row = self._entry(tab, 1, "Device name", self.device_name)
        row = self._entry(tab, row, "Friendly name", self.friendly_name)
        row = self._entry(tab, row, "OLED title", self.display_title)
        row = self._combo(tab, row, "Temperature entity", self.temperature_entity, "temperature_box")
        row = self._combo(tab, row, "Humidity entity", self.humidity_entity, "humidity_box")
        ttk.Button(tab, text="Load sensor dropdowns from Home Assistant", command=self.load_sensors).grid(row=row, column=1, sticky="w", pady=5)
        row += 1
        ttk.Label(tab, text="Initial display").grid(row=row, column=0, sticky="w", pady=5)
        defaults = ttk.Frame(tab)
        defaults.grid(row=row, column=1, sticky="ew")
        ttk.Combobox(defaults, textvariable=self.display_mode, values=("Climate", "Temperature", "Humidity", "Proxy Status"), state="readonly").pack(side="left", fill="x", expand=True, padx=(0, 4))
        ttk.Combobox(defaults, textvariable=self.display_rotation, values=("Normal", "Rotated 180"), state="readonly").pack(side="left", fill="x", expand=True, padx=(4, 0))
        row += 1
        ttk.Separator(tab).grid(row=row, column=0, columnspan=3, sticky="ew", pady=10)
        row += 1
        row = self._entry(tab, row, "Wi-Fi SSID", self.wifi_ssid)
        row = self._entry(tab, row, "Wi-Fi password", self.wifi_password, "*")
        row = self._entry(tab, row, "API encryption key", self.api_key, "*")
        ttk.Button(tab, text="Copy API key", command=lambda: self.copy_value(self.api_key.get())).grid(row=row - 1, column=2, padx=6)
        ttk.Label(tab, text="Serial port").grid(row=row, column=0, sticky="w", pady=5)
        ports = ttk.Frame(tab)
        ports.grid(row=row, column=1, sticky="ew")
        ports.columnconfigure(0, weight=1)
        self.port_box = ttk.Combobox(ports, textvariable=self.serial_port)
        self.port_box.grid(row=0, column=0, sticky="ew")
        ttk.Button(ports, text="Detect", command=self.detect_ports).grid(row=0, column=1, padx=(6, 0))
        row += 1
        row = self._entry(tab, row, "LAN host or IP", self.ota_target)
        ttk.Label(tab, text="Official firmware").grid(row=row, column=0, sticky="w", pady=5)
        firmware = ttk.Frame(tab)
        firmware.grid(row=row, column=1, columnspan=2, sticky="ew")
        ttk.Label(firmware, textvariable=self.firmware_version).pack(side="left")
        ttk.Button(firmware, text="Download from GitHub", command=self.download_firmware).pack(side="right")
        row += 1
        actions = ttk.Frame(tab)
        actions.grid(row=row, column=0, columnspan=3, sticky="ew", pady=14)
        for column in range(3): actions.columnconfigure(column, weight=1)
        ttk.Button(actions, text="Validate", command=lambda: self.start_esphome("config")).grid(row=0, column=0, sticky="ew", padx=4)
        ttk.Button(actions, text="Flash by USB", command=lambda: self.start_esphome("usb")).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(actions, text="Update over LAN", command=lambda: self.start_esphome("ota")).grid(row=0, column=2, sticky="ew", padx=4)
        row += 1
        ttk.Label(tab, text="Firmware is downloaded from the official GitHub commit before every flash or update.", foreground="#555555").grid(row=row, column=0, columnspan=3, sticky="w")

    def _build_logs(self) -> None:
        self.log = scrolledtext.ScrolledText(self.logs_tab, state="disabled", font=("Consolas", 9))
        self.log.pack(fill="both", expand=True)
        ttk.Button(self.logs_tab, text="Copy logs", command=lambda: self.copy_value(self.log.get("1.0", "end-1c"))).pack(anchor="e", pady=(6, 0))

    def _build_about(self) -> None:
        ttk.Label(self.about_tab, text="HA Proxy Panel", font=("Segoe UI", 22, "bold")).pack(anchor="w")
        ttk.Label(self.about_tab, text=f"Manager version {APP_VERSION}").pack(anchor="w", pady=(2, 0))
        ttk.Label(self.about_tab, text="Bluetooth proxy, climate display, device manager, and secure flasher for Home Assistant.", wraplength=760).pack(anchor="w", pady=(6, 20))
        ttk.Button(self.about_tab, text="Project website", command=lambda: webbrowser.open(PROJECT_PAGE)).pack(anchor="w", pady=4)
        ttk.Button(self.about_tab, text="Source code on GitHub", command=lambda: webbrowser.open(GITHUB_PAGE)).pack(anchor="w", pady=4)
        ttk.Button(self.about_tab, text="Support WikiZell on Ko-fi", command=lambda: webbrowser.open(KOFI_PAGE)).pack(anchor="w", pady=4)
        ttk.Label(self.about_tab, text="This independent community project is not affiliated with Home Assistant, ESPHome, or Nabu Casa.", foreground="#555555", wraplength=760).pack(anchor="w", pady=(24, 0))

    def _install_edit_bindings(self) -> None:
        menu = tk.Menu(self, tearoff=False)
        target: dict[str, tk.Widget | None] = {"widget": None}
        for label, event in (("Cut", "<<Cut>>"), ("Copy", "<<Copy>>"), ("Paste", "<<Paste>>")):
            menu.add_command(label=label, command=lambda e=event: target["widget"] and target["widget"].event_generate(e))
        menu.add_separator()
        menu.add_command(label="Select all", command=lambda: self._select_all(target["widget"]))
        def popup(event: tk.Event) -> str:
            target["widget"] = event.widget
            event.widget.focus_set()
            menu.tk_popup(event.x_root, event.y_root)
            return "break"
        for cls in ("TEntry", "TCombobox", "Entry", "Text"):
            self.bind_class(cls, "<Button-3>", popup, add="+")
            self.bind_class(cls, "<Control-a>", lambda e: self._select_all(e.widget), add="+")

    @staticmethod
    def _select_all(widget: tk.Widget | None) -> str:
        if widget is None: return "break"
        try:
            if isinstance(widget, tk.Text): widget.tag_add("sel", "1.0", "end")
            else: widget.selection_range(0, "end")  # type: ignore[attr-defined]
        except tk.TclError: pass
        return "break"

    def copy_value(self, value: str) -> None:
        self.clipboard_clear(); self.clipboard_append(value); self.status.set("Copied to clipboard")

    @staticmethod
    def _wifi_qr_payload(ssid: str, password: str) -> str:
        def escape(value: str) -> str:
            for character in ("\\", ";", ",", ":"):
                value = value.replace(character, f"\\{character}")
            return value
        return f"WIFI:T:WPA;S:{escape(ssid)};P:{escape(password)};H:false;;"

    @staticmethod
    def _qr_image(payload: str, maximum_size: int = 290) -> tk.PhotoImage:
        qr = QrCode.encode_text(payload, QrCode.Ecc.MEDIUM)
        border = 4; modules = qr.get_size() + border * 2
        scale = max(3, maximum_size // modules); pixels = modules * scale
        image = tk.PhotoImage(width=pixels, height=pixels)
        image.put("white", to=(0, 0, pixels, pixels))
        for y in range(qr.get_size()):
            for x in range(qr.get_size()):
                if qr.get_module(x, y):
                    left = (x + border) * scale; top = (y + border) * scale
                    image.put("black", to=(left, top, left + scale, top + scale))
        return image

    def show_onboarding_qr(self, password: str | None = None) -> None:
        ssid = "HA Proxy Panel Fallback"; fallback_password = password or self.fallback_password.get()
        if not fallback_password:
            messagebox.showerror("Password unavailable", "Generate or load the panel profile first."); return
        window = tk.Toplevel(self); window.title("Phone setup QR"); window.resizable(False, False)
        frame = ttk.Frame(window, padding=18); frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Connect your phone to the panel", font=("Segoe UI", 15, "bold")).pack()
        ttk.Label(frame, text="Wait about 30 seconds after power-on, then scan this QR code.", wraplength=380).pack(pady=(4, 10))
        image = self._qr_image(self._wifi_qr_payload(ssid, fallback_password)); window.qr_image = image  # type: ignore[attr-defined]
        ttk.Label(frame, image=image).pack()
        ttk.Label(frame, text=f"Network: {ssid}").pack(pady=(8, 2))
        ttk.Label(frame, text=f"Password: {fallback_password}").pack(pady=2)
        ttk.Label(frame, text="The phone should open the setup portal automatically. If it does not, open http://192.168.4.1.", wraplength=400, justify="center").pack(pady=8)
        actions = ttk.Frame(frame); actions.pack(pady=(4, 0))
        ttk.Button(actions, text="Copy password", command=lambda: self.copy_value(fallback_password)).pack(side="left", padx=4)
        ttk.Button(actions, text="Open setup portal", command=lambda: webbrowser.open("http://192.168.4.1")).pack(side="left", padx=4)
        ttk.Button(actions, text="Close", command=window.destroy).pack(side="left", padx=4)
        window.transient(self); window.grab_set()

    def save_settings(self) -> None:
        settings = {
            "ha_url": self.ha_url.get().strip(), "remember": self.remember.get(),
            "device_name": self.device_name.get().strip(), "friendly_name": self.friendly_name.get().strip(),
            "display_title": self.display_title.get().strip(), "temperature_entity": self.temperature_entity.get().strip(),
            "humidity_entity": self.humidity_entity.get().strip(), "display_mode": self.display_mode.get(),
            "display_rotation": self.display_rotation.get(), "wifi_ssid": self.wifi_ssid.get(),
            "ota_target": self.ota_target.get().strip(),
        }
        SETTINGS_FILE.write_text(json.dumps(settings, indent=2), encoding="utf-8")
        if self.remember.get():
            self.secure_store.save({
                "ha_token": self.ha_token.get().strip(), "wifi_password": self.wifi_password.get(),
                "ha_refresh_token": self.ha_refresh_token, "ha_client_id": self.ha_client_id,
                "api_key": self.api_key.get(), "ota_password": self.ota_password.get(),
                "fallback_password": self.fallback_password.get(),
            })
            self.status.set(f"Setup saved. Secrets encrypted in {SECURE_FILE}")
        else:
            self.status.set("Non-secret setup saved. Secrets remain in memory only.")

    def forget_login(self) -> None:
        self.ha_token.set("")
        self.ha_refresh_token = ""; self.ha_client_id = ""
        if SECURE_FILE.exists(): SECURE_FILE.unlink()
        self.status.set("Encrypted login and stored device secrets removed")

    def connect_home_assistant(self) -> None:
        base_url = self.ha_url.get().strip()
        token = self.ha_token.get().strip()
        if self.ha_refresh_token and self.ha_client_id:
            self._background("Refreshing Home Assistant login", lambda: self._refresh_worker(base_url))
        else:
            self._background("Connecting to Home Assistant", lambda: self._connect_worker(base_url, token))

    def _connect_worker(self, base_url: str, token: str) -> None:
        client = HomeAssistantClient(base_url, token)
        result = client.request("/api/")
        self.ui_queue.put(("ha_connected", result))

    def _refresh_worker(self, base_url: str) -> None:
        body = urllib.parse.urlencode({
            "grant_type": "refresh_token", "refresh_token": self.ha_refresh_token,
            "client_id": self.ha_client_id,
        }).encode()
        with urllib.request.urlopen(urllib.request.Request(f"{base_url.rstrip('/')}/auth/token", data=body), timeout=15) as response:
            token = json.load(response)
        token["_client_id"] = self.ha_client_id
        token["_from_refresh"] = True
        self.ui_queue.put(("oauth_token", token))

    def browser_login(self) -> None:
        base = self.ha_url.get().strip().rstrip("/")
        if not base:
            messagebox.showerror("Home Assistant URL required", "Enter the Home Assistant URL first.")
            return
        state = secrets.token_urlsafe(24)
        result_queue: queue.Queue[tuple[str, str]] = queue.Queue()
        class Callback(http.server.BaseHTTPRequestHandler):
            def do_GET(callback_self) -> None:
                query = urllib.parse.parse_qs(urllib.parse.urlparse(callback_self.path).query)
                code = query.get("code", [""])[0]
                returned_state = query.get("state", [""])[0]
                result_queue.put((code, returned_state))
                body = b"<html><body><h2>HA Proxy Panel login complete</h2><p>You can close this tab.</p></body></html>"
                callback_self.send_response(200); callback_self.send_header("Content-Type", "text/html")
                callback_self.send_header("Content-Length", str(len(body))); callback_self.end_headers(); callback_self.wfile.write(body)
            def log_message(self, _format: str, *_args: object) -> None: pass
        server = http.server.HTTPServer(("127.0.0.1", 0), Callback)
        redirect = f"http://127.0.0.1:{server.server_port}/"
        params = urllib.parse.urlencode({"client_id": redirect, "redirect_uri": redirect, "state": state})
        webbrowser.open(f"{base}/auth/authorize?{params}")
        self.status.set("Complete login in the Home Assistant browser tab")
        threading.Thread(target=self._oauth_waiter, args=(server, result_queue, base, redirect, state), daemon=True).start()

    def _oauth_waiter(self, server: http.server.HTTPServer, results: queue.Queue[tuple[str, str]], base: str, redirect: str, state: str) -> None:
        server.timeout = 180; server.handle_request(); server.server_close()
        try: code, returned_state = results.get_nowait()
        except queue.Empty:
            self.ui_queue.put(("error", "Home Assistant login timed out.")); return
        if not code or returned_state != state:
            self.ui_queue.put(("error", "Home Assistant login response was invalid.")); return
        body = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "client_id": redirect}).encode()
        try:
            with urllib.request.urlopen(urllib.request.Request(f"{base}/auth/token", data=body), timeout=15) as response:
                token = json.load(response)
            token["_client_id"] = redirect
            self.ui_queue.put(("oauth_token", token))
        except Exception as exc: self.ui_queue.put(("error", f"Could not complete Home Assistant login: {exc}"))

    def load_sensors(self) -> None:
        base_url = self.ha_url.get().strip()
        token = self.ha_token.get().strip()
        self._background("Loading Home Assistant sensors", lambda: self._sensor_worker(base_url, token))

    def _sensor_worker(self, base_url: str, token: str) -> None:
        states = HomeAssistantClient(base_url, token).states()
        temperature: list[tuple[str, str]] = []; humidity: list[tuple[str, str]] = []
        for item in states:
            entity_id = str(item.get("entity_id", "")); attrs = item.get("attributes") or {}
            if not entity_id.startswith("sensor.") or not isinstance(attrs, dict): continue
            name = str(attrs.get("friendly_name") or entity_id); unit = attrs.get("unit_of_measurement"); dc = attrs.get("device_class")
            record = (name.casefold(), f"{entity_id} | {name}")
            if dc == "temperature" or unit in ("°C", "°F"): temperature.append(record)
            if dc == "humidity" or (unit == "%" and "humidity" in f"{entity_id} {name}".casefold()): humidity.append(record)
        self.ui_queue.put(("sensors", ([x[1] for x in sorted(temperature)], [x[1] for x in sorted(humidity)])))

    def detect_ports(self) -> None:
        try:
            from serial.tools import list_ports
            ports = [f"{p.device} | {p.description}" for p in list_ports.comports()]
        except ImportError: ports = []
        self.port_box["values"] = ports
        if ports and self.serial_port.get() not in ports: self.serial_port.set(ports[-1])
        self.status.set(f"Detected {len(ports)} serial port(s)")

    def refresh_devices(self) -> None:
        base_url = self.ha_url.get().strip()
        token = self.ha_token.get().strip()
        self._background("Searching LAN and Home Assistant", lambda: self._discovery_worker(base_url, token))

    def _discovery_worker(self, base_url: str = "", token: str = "") -> None:
        panels: dict[str, Panel] = {}
        if token:
            states = HomeAssistantClient(base_url, token).states()
            panels.update(self._panels_from_states(states))
        try:
            from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf
            discovered: list[Panel] = []
            class Listener(ServiceListener):
                def add_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
                    info: ServiceInfo | None = zc.get_service_info(service_type, name, timeout=1500)
                    if not info: return
                    props = {k.decode(errors="ignore"): v.decode(errors="ignore") for k, v in info.properties.items()}
                    node = props.get("name", name.split(".")[0]); friendly = props.get("friendly_name", node)
                    project = props.get("project_name", "")
                    text = f"{node} {friendly} {project}".casefold()
                    if not any(word in text for word in ("ha-proxy-panel", "proxy panel", "bluetooth proxy")): return
                    addresses = info.parsed_addresses(); ip = addresses[0] if addresses else ""
                    discovered.append(Panel(f"lan:{node}", friendly, ip, "LAN", "discovered", node_name=node))
                def update_service(self, zc: Zeroconf, service_type: str, name: str) -> None: self.add_service(zc, service_type, name)
                def remove_service(self, _zc: Zeroconf, _service_type: str, _name: str) -> None: pass
            zc = Zeroconf(); browser = ServiceBrowser(zc, "_esphomelib._tcp.local.", Listener()); time.sleep(4); browser.cancel(); zc.close()
            for panel in discovered:
                match = next((p for p in panels.values() if p.ip and p.ip == panel.ip), None)
                if match: match.source = "HA + LAN"; match.node_name = panel.node_name
                else: panels[panel.key] = panel
        except ImportError: self.log_queue.put("LAN discovery needs the zeroconf package included with ESPHome.\n")
        self.ui_queue.put(("devices", panels))

    @staticmethod
    def _panels_from_states(states: list[dict[str, object]]) -> dict[str, Panel]:
        panels: dict[str, Panel] = {}
        by_id = {str(state.get("entity_id", "")): state for state in states}
        suffixes = {
            "display_content": "select", "display_rotation": "select", "status": "binary_sensor",
            "ip_address": "sensor", "wi_fi_signal": "sensor", "uptime": "sensor", "restart": "button",
            "firmware_version": "sensor", "temperature_source": "sensor", "humidity_source": "sensor",
            "display_temperature": "sensor", "display_humidity": "sensor",
        }
        for item in states:
            entity_id = str(item.get("entity_id", "")); attrs = item.get("attributes") or {}
            if not isinstance(attrs, dict) or not entity_id.startswith("select.") or not entity_id.endswith("_display_content"):
                continue
            friendly = str(attrs.get("friendly_name") or entity_id)
            base_id = entity_id.removeprefix("select.").removesuffix("_display_content")
            panel = Panel(f"ha:{base_id}", friendly.removesuffix(" Display Content"), source="Home Assistant", status="online")
            for key, domain in suffixes.items():
                candidate = f"{domain}.{base_id}_{key}"
                if candidate not in by_id: continue
                panel.entities[key] = candidate
                value = str(by_id[candidate].get("state", "")); panel.values[key] = value
                if key == "status": panel.status = value
                elif key == "ip_address": panel.ip = value
                elif key == "wi_fi_signal": panel.signal = value
            panels[panel.key] = panel
        return panels

    def _selected_panel(self) -> Panel | None:
        selection = self.device_tree.selection()
        return self.panels.get(selection[0]) if selection else None

    def _device_selected(self, _event: object = None) -> None:
        panel = self._selected_panel()
        if not panel: return
        self.selected_panel_title.set(panel.name)
        if panel.ip: self.ota_target.set(panel.ip)
        if panel.values.get("display_content"): self.live_mode.set(panel.values["display_content"])
        if panel.values.get("display_rotation"): self.live_rotation.set(panel.values["display_rotation"])
        uptime = panel.values.get("uptime", "")
        try:
            seconds = float(uptime); uptime = f"{seconds / 86400:.1f} days" if seconds >= 86400 else f"{seconds / 3600:.1f} hours"
        except ValueError: pass
        details = {
            "ip": panel.ip or "Not reported", "node_name": panel.node_name or "Not reported",
            "source": panel.source, "status": panel.status, "signal": f"{panel.signal} dBm" if panel.signal else "Not reported",
            "uptime": uptime or "Not reported", "firmware_version": panel.values.get("firmware_version", "Not reported"),
            "display_temperature": panel.values.get("display_temperature", "Not reported"),
            "display_humidity": panel.values.get("display_humidity", "Not reported"),
        }
        for key, variable in self.device_detail_vars.items(): variable.set(details.get(key, "Not reported"))
        self.selected_temp_source.set(panel.values.get("temperature_source", ""))
        self.selected_hum_source.set(panel.values.get("humidity_source", ""))
        for item in self.entity_tree.get_children(): self.entity_tree.delete(item)
        for role, entity_id in sorted(panel.entities.items()):
            self.entity_tree.insert("", "end", values=(role.replace("_", " ").title(), entity_id, panel.values.get(role, "")))

    def prepare_sensor_change(self) -> None:
        panel = self._selected_panel()
        if not panel:
            messagebox.showinfo("Select a panel", "Select the panel whose climate sources you want to change."); return
        temperature = self.selected_temp_source.get().split(" | ", 1)[0].strip()
        humidity = self.selected_hum_source.get().split(" | ", 1)[0].strip()
        if not ENTITY_ID_RE.fullmatch(temperature) or not ENTITY_ID_RE.fullmatch(humidity):
            messagebox.showerror("Sensor sources required", "Choose or type valid temperature and humidity entity IDs."); return
        self.temperature_entity.set(temperature); self.humidity_entity.set(humidity)
        self.friendly_name.set(panel.name)
        if panel.node_name: self.device_name.set(panel.node_name)
        if panel.ip: self.ota_target.set(panel.ip)
        self.display_mode.set(self.live_mode.get()); self.display_rotation.set(self.live_rotation.get())
        self.notebook.select(self.flash_tab)
        self.status.set("Sensor changes prepared. Review the profile, then choose Update over LAN.")

    def apply_live_settings(self) -> None:
        panel = self._selected_panel()
        if not panel or "display_content" not in panel.entities:
            messagebox.showinfo("Paired panel required", "Select a panel discovered through Home Assistant."); return
        base_url = self.ha_url.get().strip(); token = self.ha_token.get().strip()
        mode = self.live_mode.get(); rotation = self.live_rotation.get(); entities = dict(panel.entities)
        def task() -> None:
            client = HomeAssistantClient(base_url, token)
            client.service("select", "select_option", {"entity_id": entities["display_content"], "option": mode})
            if "display_rotation" in entities:
                client.service("select", "select_option", {"entity_id": entities["display_rotation"], "option": rotation})
            self.ui_queue.put(("message", "Live display settings applied"))
        self._background("Applying live settings", task)

    def restart_selected(self) -> None:
        panel = self._selected_panel()
        if not panel or "restart" not in panel.entities:
            messagebox.showinfo("Restart unavailable", "Select a paired panel with a Restart entity."); return
        base_url = self.ha_url.get().strip(); token = self.ha_token.get().strip(); restart_entity = panel.entities["restart"]
        self._background("Restarting panel", lambda: HomeAssistantClient(base_url, token).service("button", "press", {"entity_id": restart_entity}))

    def use_selected_for_ota(self) -> None:
        panel = self._selected_panel()
        if panel and panel.ip: self.ota_target.set(panel.ip); self.status.set(f"LAN update target set to {panel.ip}")

    def download_firmware(self) -> None:
        self._background("Downloading official firmware", self._download_worker)

    def _download_worker(self) -> None:
        path, sha = self.firmware_manager.download(); self.ui_queue.put(("firmware", (path, sha)))

    def _values(self) -> dict[str, str]:
        values = {
            "device_name": self.device_name.get().strip(), "friendly_name": self.friendly_name.get().strip(),
            "display_title": self.display_title.get().strip(), "temperature_entity": self.temperature_entity.get().split(" | ", 1)[0].strip(),
            "humidity_entity": self.humidity_entity.get().split(" | ", 1)[0].strip(), "display_mode_default": self.display_mode.get(),
            "display_rotation_default": self.display_rotation.get(), "wifi_ssid": self.wifi_ssid.get(),
            "wifi_password": self.wifi_password.get(), "api_encryption_key": self.api_key.get(),
            "ota_password": self.ota_password.get(), "fallback_ap_password": self.fallback_password.get(),
        }
        values["fallback_ap_qr"] = self._wifi_qr_payload(
            "HA Proxy Panel Fallback", values["fallback_ap_password"]
        )
        if not DEVICE_NAME_RE.fullmatch(values["device_name"]): raise ValueError("Invalid device name.")
        if not ENTITY_ID_RE.fullmatch(values["temperature_entity"]) or not ENTITY_ID_RE.fullmatch(values["humidity_entity"]): raise ValueError("Choose or type valid Home Assistant entity IDs.")
        if not values["wifi_ssid"] or not values["wifi_password"]: raise ValueError("Wi-Fi SSID and password are required.")
        if len(base64.b64decode(values["api_encryption_key"], validate=True)) != 32: raise ValueError("Invalid API encryption key.")
        return values

    def start_esphome(self, mode: str) -> None:
        if self.worker and self.worker.is_alive(): messagebox.showinfo("Busy", "Wait for the current task to finish."); return
        try: values = self._values()
        except Exception as exc: messagebox.showerror("Configuration error", str(exc)); return
        device = ""
        if mode == "usb": device = self.serial_port.get().split(" | ", 1)[0].strip()
        elif mode == "ota": device = self.ota_target.get().strip()
        if mode in ("usb", "ota") and not device: messagebox.showerror("Target required", "Select a serial port or LAN target."); return
        self.worker = threading.Thread(target=self._esphome_worker, args=(mode, values, device), daemon=True); self.worker.start()

    def _esphome_worker(self, mode: str, values: dict[str, str], device: str) -> None:
        work = APP_ROOT / "work" / values["device_name"]; work.mkdir(parents=True, exist_ok=True)
        secrets_path = work / "secrets.yaml"
        try:
            base, sha = self.firmware_manager.download()
            self.ui_queue.put(("firmware", (base, sha)))
            shutil.copy2(base, work / "ha-proxy-panel-base.yaml")
            substitutions = "\n".join(f"  {k}: {yaml_string(values[k])}" for k in ("device_name", "friendly_name", "display_title", "temperature_entity", "humidity_entity", "display_mode_default", "display_rotation_default"))
            (work / "device.yaml").write_text(f"substitutions:\n{substitutions}\n\npackages:\n  panel: !include ha-proxy-panel-base.yaml\n", encoding="utf-8")
            secrets_path.write_text("\n".join(f"{k}: {yaml_string(values[k])}" for k in ("wifi_ssid", "wifi_password", "api_encryption_key", "ota_password", "fallback_ap_password", "fallback_ap_qr")) + "\n", encoding="utf-8")
            command = esphome_command() + (["config"] if mode == "config" else ["run"]) + [str(work / "device.yaml")]
            if device: command += ["--device", device]
            self.log_queue.put(f"Using official GitHub firmware commit {sha[:12]}.\n")
            process = subprocess.Popen(command, cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
            assert process.stdout
            for line in process.stdout: self.log_queue.put(self._redact(line, values))
            code = process.wait(); self.ui_queue.put(("message", "ESPHome task completed" if code == 0 else f"ESPHome failed with code {code}"))
            if code == 0 and mode == "usb":
                self.ui_queue.put(("onboarding", values["fallback_ap_password"]))
        except Exception as exc: self.ui_queue.put(("error", f"Could not prepare or flash firmware: {exc}"))
        finally:
            try: secrets_path.unlink(missing_ok=True)
            except OSError: pass

    def _redact(self, text: str, values: dict[str, str] | None = None) -> str:
        secret_values = (
            (values.get("wifi_password", ""), values.get("api_encryption_key", ""),
             values.get("ota_password", ""), values.get("fallback_ap_password", ""),
             values.get("fallback_ap_qr", ""))
            if values else ()
        )
        for value in secret_values:
            if value: text = text.replace(value, "[redacted]")
        return text

    def _background(self, label: str, function: object) -> None:
        if self.worker and self.worker.is_alive(): messagebox.showinfo("Busy", "Wait for the current task to finish."); return
        self.status.set(label)
        def runner() -> None:
            try: function()  # type: ignore[operator]
            except urllib.error.HTTPError as exc: self.ui_queue.put(("error", "Home Assistant rejected the request." if exc.code in (401, 403) else f"HTTP error {exc.code}"))
            except Exception as exc: self.ui_queue.put(("error", str(exc)))
        self.worker = threading.Thread(target=runner, daemon=True); self.worker.start()

    def _drain_queues(self) -> None:
        try:
            while True: self._write_log(self.log_queue.get_nowait())
        except queue.Empty: pass
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                if kind == "error": self.status.set(str(payload)); self._write_log(f"Error: {payload}\n")
                elif kind == "message": self.status.set(str(payload)); self._write_log(f"{payload}\n")
                elif kind == "ha_connected":
                    self.ha_status.set("Connected to Home Assistant"); self.status.set("Home Assistant connection successful")
                    if self.remember.get(): self.save_settings()
                    self.after(400, self.load_sensors); self.after(2000, self.refresh_devices)
                elif kind == "oauth_token":
                    token = payload if isinstance(payload, dict) else {}
                    self.ha_token.set(str(token.get("access_token", "")))
                    if token.get("refresh_token"): self.ha_refresh_token = str(token["refresh_token"])
                    if token.get("_client_id"): self.ha_client_id = str(token["_client_id"])
                    self.ha_status.set("Browser login successful")
                    base_url = self.ha_url.get().strip(); access_token = self.ha_token.get().strip()
                    self.status.set("Connecting to Home Assistant")
                    self.worker = threading.Thread(
                        target=self._connect_worker, args=(base_url, access_token), daemon=True
                    )
                    self.worker.start()
                elif kind == "sensors":
                    temperature, humidity = payload  # type: ignore[misc]
                    self.temperature_box["values"] = temperature; self.humidity_box["values"] = humidity
                    self.selected_temp_box["values"] = temperature; self.selected_hum_box["values"] = humidity
                    self.status.set(f"Loaded {len(temperature)} temperature and {len(humidity)} humidity sensors")
                elif kind == "devices":
                    self.panels = payload if isinstance(payload, dict) else {}
                    for item in self.device_tree.get_children(): self.device_tree.delete(item)
                    for key, panel in self.panels.items():
                        self.device_tree.insert("", "end", iid=key, text=panel.name, values=(panel.ip, panel.status))
                    if self.panels:
                        first = next(iter(self.panels)); self.device_tree.selection_set(first); self.device_tree.focus(first); self._device_selected()
                    self.status.set(f"Found {len(self.panels)} HA Proxy Panel device(s)")
                elif kind == "firmware":
                    _path, sha = payload  # type: ignore[misc]
                    self.firmware_version.set(f"GitHub commit {sha[:12]}"); self.status.set("Official firmware downloaded and verified")
                elif kind == "onboarding":
                    self.show_onboarding_qr(str(payload))
        except queue.Empty: pass
        self.after(100, self._drain_queues)

    def _write_log(self, text: str) -> None:
        self.log.configure(state="normal"); self.log.insert("end", text); self.log.see("end"); self.log.configure(state="disabled")

    def open_home_assistant(self) -> None:
        base = self.ha_url.get().strip().rstrip("/"); webbrowser.open(f"{base}/config/integrations")


def main() -> None:
    ProxyPanelApp().mainloop()


if __name__ == "__main__":
    main()
