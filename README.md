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
<img width="1020" height="677" alt="Update_Install(prep)" src="https://github.com/user-attachments/assets/4d79f3c6-96c8-4064-956c-fb43542ffb72" />

## 1.Collect before state (what to capture for your deliverables)
***Run and save these outputs before making changes.***
```bash
# System info
hostnamectl > before-system-info.txt
uname -a >> before-system-info.txt
```
<img width="966" height="623" alt="System_Info" src="https://github.com/user-attachments/assets/f5d626f3-28b5-454e-b391-c96dbceb1af9" />
<img width="952" height="799" alt="before_sys_info" src="https://github.com/user-attachments/assets/cc2e1e8a-9d48-4459-ac04-868d2fc95cf7" />

```bash
# Network interfaces & IPs
ip -c a > before-ip.txt
```
<img width="966" height="623" alt="Network_interface_ _IP" src="https://github.com/user-attachments/assets/29af739f-52e2-4e82-829f-79249677b733" />
<img width="952" height="799" alt="before_ip" src="https://github.com/user-attachments/assets/fddcebdf-d397-4dba-92f7-e3b4f6ae4857" />

```bash
# Listening ports and owners
sudo ss -tulpen > before-listening.txt
```
<img width="1200" height="749" alt="before_listning" src="https://github.com/user-attachments/assets/a300de94-ec92-4e78-897a-e7f1bf364d2f" />

```bash
# UFW status (before)
sudo ufw status verbose | tee before-ufw.txt
```
<img width="1200" height="749" alt="before_ufw" src="https://github.com/user-attachments/assets/0fa74eaf-38fe-4875-9a7e-1e3e0c7d98b1" />

```bash
# iptables/nftables rules
sudo iptables -L -n -v > before-iptables.txt || true
sudo nft list ruleset > before-nft.txt || true
```
<img width="1850" height="1053" alt="before_iptables" src="https://github.com/user-attachments/assets/dbc8b485-5f4d-469a-9359-5329bd6a5565" />

```bash
# SSHD config snapshot
sudo cp /etc/ssh/sshd_config before-sshd_config
```

```bash
# fail2ban status
sudo systemctl is-active fail2ban > before-fail2ban-service.txt
sudo fail2ban-client status > before-fail2ban-status.txt || true
```
<img width="1850" height="1053" alt="fail2ban_start" src="https://github.com/user-attachments/assets/195e73e2-8a83-4cf8-9e10-1c80786c835f" />
<img width="1850" height="1053" alt="ssh_key" src="https://github.com/user-attachments/assets/d95ba69c-7422-455a-864c-3803d8060d1e" />


```bash
# Current authorized SSH keys (for the user you're testing)
cat ~/.ssh/authorized_keys > before-authorized_keys || true
```

<img width="1850" height="1053" alt="before_authorized_keys" src="https://github.com/user-attachments/assets/8747a324-8143-44d7-a288-f6b795cfb480" />

## 2.Start live traffic capture (tcpdump) — save to pcap for later analysis

Choose the interface: find it with ```ip -c a``` (e.g. ```eth0``` or ```ens33```).

Minimal live capture (all traffic) — **WARNING:** large files:
```bash
sudo tcpdump -i ens33 -s 0 -w capture_full.pcap
# Ctrl+C to stop
```
<img width="1850" height="1053" alt="capture_pcap" src="https://github.com/user-attachments/assets/16cd62f2-a6aa-4cd9-833a-ad022080945c" />

Better: targeted capture (common cleartext auth protocols & suspicious ports):

```bash
sudo tcpdump -i ens33 -s 0 -w capture_auth.pcap \
  'tcp port 21 or tcp port 23 or tcp port 25 or tcp port 110 or tcp port 143 or tcp port 80 or tcp port 110 or tcp port 143 or tcp port 389 or tcp port 3306 or port 3389'
```
<img width="1850" height="1053" alt="cap_auth" src="https://github.com/user-attachments/assets/afb46d6d-ec0d-497a-8ef6-d5da78a445cb" />

- ```-W 10 -C 100``` keeps up to 10 files of 100MB each.


