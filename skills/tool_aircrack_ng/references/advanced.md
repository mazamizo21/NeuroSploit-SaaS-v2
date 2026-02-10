# Advanced Techniques

## Suite Scope
- Aircrack-ng is a suite that covers monitoring, attacking, testing, and cracking of Wi‑Fi networks.
- Use the minimal tool/step required for the objective (capture, validate, then crack).

## Monitor Mode Control
- Use `airmon-ng start <iface> [channel]` to enable monitor mode and fix channel.
- Use `airmon-ng check kill` to stop interfering processes when injection/capture fails.
