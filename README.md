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
- Try to loging when capturing traffic
  <img width="1920" height="1080" alt="login" src="https://github.com/user-attachments/assets/f4bf3d72-5613-44be-b44d-71c0a54a86c7" />
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


## 3.Quick scans while capture is running — look for suspicious behavior



1.High connection counts (possible scanning / brute force):
```bash
sudo ss -tanp | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -n 30 > connection_counts.txt
```
<img width="1850" height="1053" alt="high_connection_counts" src="https://github.com/user-attachments/assets/deb375e5-200b-458e-a0cb-27910e1a42eb" />

2.Check auth logs for failed logins (SSH, others):
```bash
sudo journalctl -u ssh -n 200 --no-pager > ssh_journal_recent.txt
sudo grep -i 'failed\|invalid' /var/log/auth.log | tail -n 200 > auth_failed_tail.txt
```
<img width="1850" height="1053" alt="ssh_journal_txt" src="https://github.com/user-attachments/assets/eda0f0d1-7414-475f-9a18-dfe248f49aa1" />
<img width="1850" height="1053" alt="auth_failed_tail" src="https://github.com/user-attachments/assets/8a19ca91-d6e0-4b55-9ce5-05053352719f" />


3.Live netstat-style counts by IP:
```bash
sudo ss -tn state established '( sport = :22 or sport = :80 or sport = :443 )' | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr > established_by_ip.txt
```
<img width="1850" height="1053" alt="established_by_ip" src="https://github.com/user-attachments/assets/bcbb18ff-6099-4bc9-8868-550b0551c1b9" />


## 4.Offline analysis of pcap to find credentials (tshark / Wireshark)

**Important:** If the traffic is encrypted (HTTPS, SSH, TLS), you will not be able to recover credentials.

Useful tshark commands:

- Extract HTTP ```Authorization``` headers (Basic auth):
```bash
tshark -r /tmp/capture_auth.pcap -Y 'http.authorization' -T fields -e ip.src -e http.host -e http.request.uri -e http.authorization | tee http_auth_headers.txt
```
<img width="1850" height="1053" alt="extract_http" src="https://github.com/user-attachments/assets/1aa1766e-df82-4081-83a6-cb5ee3fb6f71" />

- Extract HTTP form fields and posted data (may contain creds in plain POST bodies):
```bash
# Show HTTP POST URIs and content
tshark -r /tmp/capture_auth.pcap -Y 'http.request.method == "POST"' -T fields -e ip.src -e http.host -e http.request.uri -e http.file_data | tee http_posts.txt
```
<img width="1850" height="1053" alt="creds" src="https://github.com/user-attachments/assets/0683afd5-dde5-484f-8d2d-0e66a3dbc538" />


## 5.SSH hardening: disable root login, enforce key-only auth, and rate-limit

1. Generate key (on your admin workstation):
```bash
# on your local admin machine
ssh-keygen -t ed25519 -C "yash@yourhost"
ssh-copy-id -i ~/.ssh/id_ed25519.pub youruser@target-host
# OR manually append the public key to ~/.ssh/authorized_keys on the server
```
<img width="1850" height="1053" alt="ssh_key_gen" src="https://github.com/user-attachments/assets/b7a5cf1b-83ea-4fe8-ba7a-d23904fa6cc8" />

2. **Edit** ```/etc/ssh/sshd_config``` (backup first) and apply recommended changes:

 ```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || echo 'PermitRootLogin no' | sudo tee -a /etc/ssh/sshd_config
sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config
# Optional: allow only specific user(s)
sudo sed -i '/^AllowUsers/ d' /etc/ssh/sshd_config
echo 'AllowUsers youruser' | sudo tee -a /etc/ssh/sshd_config
# restart ssh
sudo systemctl restart sshd
# verify
sudo ss -tnlp | grep sshd
```
<img width="1850" height="1053" alt="edit" src="https://github.com/user-attachments/assets/982076c4-980f-4e6d-93b3-2f475a303679" />

If you need password login temporarily, **do not** disable password auth until you've successfully added a key and tested new login in another session.

   
3. Add a UFW rule to rate-limit SSH and allow only key-based connections
```bash
sudo ufw allow OpenSSH     # ensures port 22 allowed
sudo ufw limit OpenSSH     # enables rate limiting (6 connections / 30s default)
sudo ufw status verbose
```
<img width="1850" height="1053" alt="Add_UFW_rule" src="https://github.com/user-attachments/assets/5d52b3d5-3572-4c39-b7c0-4802b6226e6f" />

## 6.fail2ban configuration to block repeated SSH attempts

Create or edit a jail local file:
```bash
sudo tee /etc/fail2ban/jail.d/ssh-custom.conf > /dev/null <<'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

# reload fail2ban
sudo systemctl restart fail2ban
sudo fail2ban-client status sshd
```
<img width="1850" height="1053" alt="fail2ban_start" src="https://github.com/user-attachments/assets/853c1a73-3e39-47c2-964a-0f552f09efe8" />
<img width="1850" height="1053" alt="create_jail_local" src="https://github.com/user-attachments/assets/8cf3464b-040f-4213-a50b-d4500cc8338e" />

Check banned IPs:
```bash
sudo fail2ban-client status sshd
# or:
sudo iptables -L -n -v | grep f2b-sshd -A 5
```
<img width="1850" height="1053" alt="check_banned_ip" src="https://github.com/user-attachments/assets/d7d0fb42-2723-4787-a933-492e8db3b906" />


## 7.UFW baseline rules (block unused ports; only open what you need)

Example minimal policy:
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing

# allow SSH (already shown), HTTP/HTTPS if webserver:
sudo ufw allow 22/tcp         # or use 'OpenSSH'
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# drop everything else
sudo ufw enable
sudo ufw status verbose
```
<img width="1850" height="1053" alt="Edit_minimal_policy" src="https://github.com/user-attachments/assets/2d2dedea-0e8e-4cae-97b9-eaf632a625ef" />

```bash
sudo ufw deny 3306/tcp   # deny MySQL from outside
```
<img width="1850" height="1053" alt="block_port" src="https://github.com/user-attachments/assets/c46c2e33-85a5-4f28-9a66-70760fd8873c" />

## 8.After changes — collect after state (what to include in deliverables)

Run the same commands as “before” to capture the new state and save them (suffix _after):
```bash
hostnamectl > after-system-info.txt
ip -c a > after-ip.txt
sudo ss -tulpen > after-listening.txt
sudo ufw status verbose | tee after-ufw.txt
sudo iptables -L -n -v > after-iptables.txt || true
sudo nft list ruleset > after-nft.txt || true
sudo cp /etc/ssh/sshd_config after-sshd_config
sudo fail2ban-client status > after-fail2ban-status.txt || true
cat ~/.ssh/authorized_keys > after-authorized_keys || true
```
<img width="1850" height="1053" alt="before" src="https://github.com/user-attachments/assets/f92e528a-16f1-4b10-8f2e-e4a43fe38593" />

- ```sudo ufw status verbose``` (after)
- ```sudo fail2ban-client status sshd``` (after)
- successful ```ssh -i ~/.ssh/id_ed25519 youruser@target-host``` login (show terminal session establishing)


## 9.Deliverables checklist & example report snippets

**Deliverable A — Before/After state summary (example format)**
```bash
System: target-host.example.com
Test Date: 2025-09-16

BEFORE:
- Listening services (excerpt): 
  tcp   LISTEN 0      128    0.0.0.0:22      0.0.0.0:*    users:(("sshd",pid=1234))
  tcp   LISTEN 0      128    0.0.0.0:80      0.0.0.0:*    users:(("nginx",pid=2345))
- UFW: Status: active, default deny incoming, allowed: OpenSSH, 80/tcp, 443/tcp
- fail2ban: disabled / no active jails
- SSH: PermitRootLogin yes, PasswordAuthentication yes (from /etc/ssh/sshd_config)

AFTER:
- Listening services (excerpt): same as before (no unnecessary new services)
- UFW: Status: active, default deny incoming; allowed: 22 (rate-limited), 80, 443
- fail2ban: active, jail: sshd (maxretry 5, bantime 3600)
- SSH: PermitRootLogin no, PasswordAuthentication no, AllowUsers youruser
- Notes: SSH access confirmed working with public key authentication from admin workstation.
```
**Deliverable B — Applied commands list (example format)**

Provide a plain text file applied_commands.txt containing chronological commands you executed. Example:
sudo apt update && sudo apt install -y tcpdump tshark wireshark ufw fail2ban scrot
sudo tcpdump -i eth0 -s 0 -w /tmp/capture_auth.pcap 'tcp port 21 or tcp port 80 or tcp port 110'
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
echo 'AllowUsers youruser' | sudo tee -a /etc/ssh/sshd_config
sudo systemctl restart sshd
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw limit OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo tee /etc/fail2ban/jail.d/ssh-custom.conf <<'EOF'
[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
EOF
sudo systemctl restart fail2ban
sudo fail2ban-client status sshd
```

```bash



