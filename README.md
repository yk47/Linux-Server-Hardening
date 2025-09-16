# Linux-Server-Hardening
Capture and analyze live network traffic to identify credentials or suspicious activity.

- clear preparation steps
- exact commands (copy/paste)
- capture & analysis commands (tcpdump / tshark / Wireshark filters)
- hardening steps (disable root, enforce key auth)
- UFW + fail2ban configuration and checks
- Deliverables template: what to collect (before/after summary, applied commands list, and screenshots) and example outputs you can paste into a report.

***strong legal/ethical reminder:***
Do this only on systems/networks you own or are explicitly authorized to test.

**Preparation / prerequisites (one-liners)**
```bash
# update & install tools
sudo apt update && sudo apt install -y tcpdump tshark wireshark ufw fail2ban jq scrot
# (If using a headless server and want to capture screenshots, scrot is a CLI tool.)
```

