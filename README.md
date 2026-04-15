![ike-cazador](.cazador.png)
# ike-cazador
tool for discovering and validating IKE Aggressive Mode on target hosts and capturing PSK hashes for offline cracking. Built for use during authorized PenTests against client VPN infrastructure.
## What it does
this tool runs in two phases:
**Phase 1** scans your target list or specified host and identifies which hosts have IKE Aggressive Mode enabled, what transforms they accept, and whether they're configured with wildcard VPN profiles (read more about that here: https://docs.paloaltonetworks.com/network-security/ipsec-vpn/administration/set-up-site-to-site-vpn/set-up-an-ike-gateway).
**Phase 2** brute-forces group IDs against confirmed hosts using a wordlist (default wordlist is built-in but you can provide your own), captures PSK hashes in hashcat-ready format, and flags wildcard-configured devices.
## Requirements
pip3 install -r requirements.txt
Requires root (binds to UDP source port 500).
## Usage
```bash
sudo python3 ike-cazador.py targets.txt
sudo python3 ike-cazador.py targets.txt wordlist.txt
sudo python3 ike-cazador.py targets.txt wordlist.txt --conservative
sudo python3 ike-cazador.py --resume ike-cazador-results/20260414_161904 new-wordlist.txt
targets — single IP, hostname, URL, or a file with one target per line (IPv4/IPv6/FQDN supported)
wordlist — group ID wordlist for Phase 2 (defaults to wordlists/default-ike-wordlist.txt)
Output
Results are written to a timestamped directory under ike-cazador-results/:
- hashes/hashcat_ready_5400.txt — SHA1 hashes, feed directly to hashcat
- hashes/hashcat_ready_5300.txt — MD5 hashes
- hashes/psk_crack_ready.txt — all hashes, compatible with psk-crack (handles large DH groups)
- hashes/all_hashes.txt — annotated format with host/group/transform context
- summary.txt — full scan summary including ike-scan validation commands
- logs/scan.log — timestamped event log
- results.json — machine-readable results
Cracking
hashcat -m 5400 ike-cazador-results/<run>/hashes/hashcat_ready_5400.txt rockyou.txt
psk-crack -d rockyou.txt ike-cazador-results/<run>/hashes/psk_crack_ready.txt
Options
Run sudo python3 ike-cazador.py -h for the full list of flags including timing controls, interface selection, conservative mode, and more. The help output also includes a Notify Messages Cheat Sheet explaining what each (tested and accounted for)  IKE response code means.
---
