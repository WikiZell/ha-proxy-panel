from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from ha_proxy_panel_app import (  # noqa: E402
    HomeAssistantClient,
    device_builder_project,
    is_replaceable_device_builder_import,
    merge_yaml_secrets,
    version_key,
)


class FakeHomeAssistantClient(HomeAssistantClient):
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        super().__init__("http://homeassistant.local:8123", "test-token")
        self.responses = responses
        self.calls: list[tuple[str, dict[str, object] | None]] = []

    def request(self, path: str, data: dict[str, object] | None = None) -> object:
        self.calls.append((path, data))
        if not self.responses:
            raise AssertionError("Unexpected Home Assistant request")
        return self.responses.pop(0)


class HomeAssistantConfigFlowTests(unittest.TestCase):
    def test_adds_encrypted_esphome_panel(self) -> None:
        client = FakeHomeAssistantClient([
            {"type": "form", "flow_id": "flow-1", "step_id": "user"},
            {"type": "form", "flow_id": "flow-1", "step_id": "encryption_key"},
            {"type": "create_entry", "title": "1st Floor Bluetooth Proxy"},
        ])

        result = client.add_esphome("192.0.2.75", "secure-api-key")

        self.assertEqual(result["status"], "added")
        self.assertEqual(client.calls[1][1], {"host": "192.0.2.75", "port": 6053})
        self.assertEqual(client.calls[2][1], {"noise_psk": "secure-api-key"})

    def test_accepts_key_already_known_by_home_assistant(self) -> None:
        client = FakeHomeAssistantClient([
            {"type": "form", "flow_id": "flow-2", "step_id": "user"},
            {"type": "create_entry", "title": "HA Proxy Panel"},
        ])

        result = client.add_esphome("ha-proxy-panel.local", "unused-key")

        self.assertEqual(result["status"], "added")
        self.assertEqual(len(client.calls), 2)

    def test_treats_existing_entry_as_success(self) -> None:
        client = FakeHomeAssistantClient([
            {"type": "form", "flow_id": "flow-3", "step_id": "user"},
            {"type": "abort", "reason": "already_configured"},
        ])

        result = client.add_esphome("192.0.2.75", "secure-api-key")

        self.assertEqual(result["status"], "already_configured")

    def test_treats_existing_entry_update_as_success(self) -> None:
        client = FakeHomeAssistantClient([
            {"type": "form", "flow_id": "flow-5", "step_id": "user"},
            {"type": "abort", "reason": "already_configured_updates"},
        ])

        result = client.add_esphome("198.51.100.61", "secure-api-key")

        self.assertEqual(result["status"], "already_configured")

    def test_reports_invalid_encryption_key(self) -> None:
        client = FakeHomeAssistantClient([
            {"type": "form", "flow_id": "flow-4", "step_id": "user"},
            {"type": "form", "flow_id": "flow-4", "step_id": "encryption_key"},
            {"type": "form", "flow_id": "flow-4", "step_id": "encryption_key", "errors": {"base": "invalid_psk"}},
        ])

        with self.assertRaisesRegex(RuntimeError, "does not match"):
            client.add_esphome("192.0.2.75", "wrong-key")


class DeviceBuilderProjectTests(unittest.TestCase):
    def test_recognizes_only_matching_adopted_proxy_panel_project(self) -> None:
        adopted = """substitutions:
  name: first-floor-bluetooth-proxy
packages:
  panel: github://WikiZell/ha-proxy-panel/firmware/ha-proxy-panel.yaml@main
"""
        self.assertTrue(is_replaceable_device_builder_import(
            "first-floor-bluetooth-proxy.yaml", adopted
        ))
        self.assertFalse(is_replaceable_device_builder_import(
            "second-floor-bluetooth-proxy.yaml", adopted
        ))
        self.assertFalse(is_replaceable_device_builder_import(
            "first-floor-bluetooth-proxy.yaml", "esphome:\n  name: first-floor-bluetooth-proxy\n"
        ))

    def test_merges_namespaced_secrets_without_touching_existing_values(self) -> None:
        existing = "wifi_ssid: \"Existing\"\nother_key: keep-me\n"
        merged = merge_yaml_secrets(existing, {
            "hpp_first_floor_wifi_ssid": "My Wi-Fi",
            "hpp_first_floor_api_encryption_key": "private-key",
        })

        self.assertIn('wifi_ssid: "Existing"', merged)
        self.assertIn("other_key: keep-me", merged)
        self.assertIn('hpp_first_floor_wifi_ssid: "My Wi-Fi"', merged)
        self.assertIn('hpp_first_floor_api_encryption_key: "private-key"', merged)

    def test_generated_project_references_secrets_without_exposing_them(self) -> None:
        values = {
            "device_name": "first-floor-bluetooth-proxy",
            "friendly_name": "1st Floor Bluetooth Proxy",
            "display_title": "A LONG FIRST FLOOR TITLE",
            "temperature_entity": "sensor.average_temp_1_floor",
            "humidity_entity": "sensor.average_humidity_1_floor",
            "display_mode_default": "Climate",
            "display_rotation_default": "Rotated 180",
            "display_brightness_default": "65",
            "oled_care_restore_mode": "RESTORE_DEFAULT_ON",
            "wifi_ssid": "Private Wi-Fi",
            "wifi_password": "private-wifi-password",
            "api_encryption_key": "private-api-key",
            "ota_password": "private-ota-password",
            "fallback_ap_password": "private-fallback-password",
            "fallback_ap_qr": "private-fallback-qr",
        }

        project, secrets_update = device_builder_project(values, "abc123")

        self.assertIn("# Managed by HA Proxy Panel Manager", project)
        self.assertIn("key: !secret hpp_first_floor_bluetooth_proxy_api_encryption_key", project)
        self.assertNotIn("private-api-key", project)
        self.assertNotIn("private-wifi-password", project)
        self.assertEqual(
            secrets_update["hpp_first_floor_bluetooth_proxy_ota_password"],
            "private-ota-password",
        )

    def test_version_comparison_ignores_labels(self) -> None:
        self.assertGreater(version_key("v1.5.1-beta"), version_key("1.5.0"))
        self.assertEqual(version_key("not-a-version"), ())


if __name__ == "__main__":
    unittest.main()
