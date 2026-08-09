# Contributing

Thanks for helping improve HA Proxy Panel.

## Before opening an issue

Please include:

- ESP32 board model
- OLED controller, size, and I2C address
- ESPHome version
- Relevant logs with passwords, keys, IP addresses, MAC addresses, and Wi-Fi names removed
- A clear description of the expected and actual behavior

## Pull requests

1. Fork the repository and create a focused branch.
2. Do not commit `firmware/secrets.yaml` or generated firmware binaries.
3. Validate the firmware with a temporary secrets file.
4. Test the website at desktop and mobile widths when changing files under `docs/`.
5. Explain the hardware and Home Assistant impact in the pull request.

Keep changes small enough to review. Avoid introducing board-specific assumptions without documenting them.
