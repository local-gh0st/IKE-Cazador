<img width="574" height="570" alt="cazador" src="https://github.com/user-attachments/assets/2a1a2b05-569a-4677-9e64-edfc76f9f721" />


# IKE-Cazador: A Group-ID Brute-Force Script

Brute force Group IDs for network devices configured with IKE Aggressive mode. 

  # License/Disclaimer:
  This script is for educational and/or
  ethical use only.
Do not redistribute for monetary gain.
Do not use for malicious purposes or against networks for which you do not have authorization to test.
Unauthorized use is prohibited.



# Why this tool is potentially useful:

Tool has a "group-first" rotation feature.
When enabled, the script will brute force by group ID in a round-robin fashion.
Instead of testing all group IDs against one host before moving to the next host, it will:
- Take the first group ID from the wordlist and try it against every host in your target list.
- Move to the next group ID and repeat the process for all hosts.
- This continues until all group IDs have been tested against all hosts.
- This approach spreads requests across multiple hosts, which can help avoid rate-limiting or
detection by not hammering a single host with all group IDs at once.
(Think "password spraying" versus "brute forcing".)


# Install and Usage
```

bash
1. git clone
2. chmod +x ike-cazador.sh
3. ./ike-cazador.sh <target_ip OR targets_list.txt> <groupid_wordlist.txt

python
python3 ike-cazador.py targets words

**Optional Flags**
(but good iea to use)
[-r] = Use 'Group-first' rotation: tries each group ID against all hosts before moving to the next group ID (round-robin). Helps avoid hammering a single host and can bypass rate limits.
[-j] = Add a 'delay' of .3-.99 seconds per attempt, should emulate more realistic user behavior
[-p] = Destination port. Specify the IKE port with -p <x> (default: 500)
[-q] = quiet mode if you don't want to see live output displayed on screen
