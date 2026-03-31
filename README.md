<img width="574" height="570" alt="cazador" src="https://github.com/user-attachments/assets/2a1a2b05-569a-4677-9e64-edfc76f9f721" />

# IKE-CAZADOR

**VPN Group ID Discovery Tool for IKE Aggressive Mode Enumeration**
Version 1.1.0
️ **Version Notice:** This is v1.1.0 - a complete rewrite with enhanced validation, modular architecture. Legacy version (v1.0) probably in here somewhere but also probably broken.

Version 1.0.0

---

## Overview

IKE-CAZADOR is a professional penetration testing tool designed to discover valid VPN Group IDs through enumeration of IKE/IPsec VPN endpoints configured with Aggressive Mode. The tool provides accurate, reliable results with robust false positive detection.

### Key Features

- **Two-Phase Operation:** Group ID discovery followed by optional PSK hash capture
- **False Positive Detection:** Statistical validation using random junk strings
- **Multi-Target Support:** Efficient scanning of enterprise-scale networks
- **Stealth Features:** Jitter timing and round-robin request distribution
- **Professional Output:** Color-coded terminal display with comprehensive logging

---

## Requirements

- **Python 3.8+**
- **ike-scan** (must be installed)
- **Root/sudo privileges** (required for ike-scan raw socket access)

### Install ike-scan

**Debian/Kali:**
```bash
sudo apt-get install ike-scan
```

**macOS:**
```bash
brew install ike-scan
```

---

## Installation

```bash
git clone <repo-url> ike-cazador
cd ike-cazador
```

No additional Python dependencies required - uses standard library only.

---

## Usage

### Basic Usage

```bash
# Single target with default wordlist
sudo ./ike-cazador.py 192.168.1.1

# Multiple targets from file
sudo ./ike-cazador.py targets.txt

# Custom wordlist
sudo ./ike-cazador.py 192.168.1.1 custom_wordlist.txt
```

### Advanced Options

```bash
# With jitter and round-robin for stealth
sudo ./ike-cazador.py targets.txt -j -r

# Custom port (sometimes IKE on 4500)
sudo ./ike-cazador.py 192.168.1.1 -p 4500

# Quiet mode for automation
sudo ./ike-cazador.py targets.txt -q

# Verbose mode for debugging
sudo ./ike-cazador.py 192.168.1.1 -v
```

### Command-Line Arguments

```
positional arguments:
  target                Target IP, hostname, or file with targets (one per line)
  wordlist              Group ID wordlist (default: bundled 450 IDs)

optional arguments:
  -p PORT, --port PORT  Destination port (default: 500)
  -j, --jitter          Enable jitter timing for stealth (500ms ±200ms)
  -r, --rotate          Round-robin mode (rotate between targets)
  -v, --verbose         Verbose output
  -q, --quiet           Quiet mode (minimal output)
  --no-color            Disable colored output
  --timeout SECONDS     ike-scan timeout in seconds (default: 10)
  -h, --help            Show help message
  --version             Show version
```

---

## How It Works

### Phase 1: Group ID Discovery

1. Tests each Group ID from wordlist against target VPN endpoints
2. Identifies potential valid Group IDs based on IKE Aggressive Mode handshake
3. Validates results using statistical false positive detection:
   - Tests 5 random junk strings appended to suspected valid ID
   - If 3+ random IDs succeed → FALSE POSITIVE (misconfigured VPN)
   - If 2 random IDs succeed → SUSPICIOUS (manual verification needed)
   - If 0-1 random IDs succeed → TRUE POSITIVE (validated)

### Phase 2: PSK Hash Capture

1. For each validated Group ID, captures full IKE handshake with `-P` flag
2. Extracts transform set details (encryption, hash algorithm, DH group)
3. Saves captured data for offline PSK cracking
4. Generates hashcat commands with correct modes

---

## Output

### Terminal Output

- **Color-coded results:** Green for valid, Red for errors, Yellow for suspicious
- **Progress tracking:** Real-time progress with ETA
- **Validation details:** Shows each random test during validation

### Log Files

All output saved to timestamped session directory: `captures/scan_YYYYMMDD_HHMMSS/`

```
captures/scan_20260331_143000/
├── phase1_full_log.txt     # Every command + response
├── errors.txt              # All errors with timestamps
└── <target>_<groupid>.txt  # PSK captures (Phase 2)
```

---

## Example Workflow

```bash
# 1. Run Group ID discovery against VPN
sudo ./ike-cazador.py vpn.company.com

# Output shows validated Group IDs:
# [+] 192.168.1.1 : admin → TRUE POSITIVE (validated)

# 2. Tool prompts for Phase 2 PSK capture
# User chooses Y to automatically capture

# 3. Tool generates hashcat commands:
# hashcat -m 5400 -a 0 captures/.../192.168.1.1_admin.txt wordlist.txt

# 4. Crack PSK offline with hashcat
hashcat -m 5400 -a 0 captures/scan_20260331_143000/192.168.1.1_admin.txt passwords.txt
```

---

## Stealth Considerations

### Detection Risk

IKE Aggressive Mode enumeration generates noticeable traffic and may trigger:
- IDS/IPS alerts
- Rate limiting
- IP blocking

### Mitigation

- Use `-j` flag for jitter timing (randomized delays)
- Use `-r` flag for round-robin mode (spreads requests across targets)
- Consider scanning during business hours (blends with legitimate traffic)

---

## Legal Disclaimer

**⚠️ IMPORTANT: AUTHORIZED USE ONLY**

This tool is intended for **authorized security assessments and penetration testing only**. Unauthorized access to computer systems is illegal.

**Users are responsible for:**
- Ensuring proper authorization before use
- Compliance with all applicable laws and regulations
- Any consequences of misuse

The authors assume no liability for misuse or damage caused by this tool.

---

## Technical Details

### Default Wordlist

Includes 450 common Group IDs:
- Cisco defaults (DefaultRAGroup, DefaultL2LGroup, etc.)
- Common patterns (vpn, admin, remote, etc.)
- Vendor-specific patterns (asa_vpn, pix_vpn, etc.)

Location: `wordlists/group-id-wordlist.txt`

### Hash Algorithm Detection

Automatically extracts hash algorithm from transform set:
- **MD5:** Hashcat mode 5300
- **SHA1:** Hashcat mode 5400
- **SHA256+:** Check hashcat documentation

### Validation Algorithm

Uses statistical sampling to detect false positives:
- Generates 5 random test IDs: `<valid_id>_<15_random_chars>`
- Tests each against target
- Calculates confidence based on success rate

---

## Troubleshooting

### "ike-scan not found"

Install ike-scan (see Requirements section)

### "This tool requires root privileges"

Run with sudo: `sudo ./ike-cazador.py ...`

### "Wordlist not found"

Ensure wordlist file exists or use default bundled wordlist

### No valid Group IDs found

- Try custom wordlist with company-specific terms
- Check if target is actually running IKE Aggressive Mode
- Verify network connectivity to target

---

## Development

### Project Structure

```
ike-cazador/
├── ike-cazador.py              # Main executable
├── lib/ike_cazador/            # Python package
│   ├── ike_tester.py           # ike-scan wrapper
│   ├── scanner.py              # Scanning orchestration
│   ├── validator.py            # False positive detection
│   ├── output.py               # Display and logging
│   └── utils.py                # Utilities and colors
├── wordlists/                  # Default wordlist
├── captures/                   # Generated at runtime
└── TECHNICAL_DESIGN.md         # Comprehensive design doc
```

### Testing

Unit tests to be added in `tests/` directory.

---

## Credits

Developed for professional security assessments.

Built with guidance from comprehensive technical specifications.

---

## Version History

**v1.0.0** (2026-03-31)
- Initial release
- Two-phase operation (discovery + PSK capture)
- Statistical false positive detection
- Multi-target support with stealth features

---

## License

[To be determined]

---

## Support

For issues, questions, or contributions, please refer to the repository.

---

**Remember:** Always obtain proper authorization before testing any systems you do not own.
