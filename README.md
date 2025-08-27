# IKE-Cazador
Brute force Group IDs for network devices configured with IKE Aggressive mode. 

**Why this is potentially useful**
Tool has a "group-first" rotation feature.
When enabled, the script will brute force by group ID in a round-robin fashion.
Instead of testing all group IDs against one host before moving to the next host, it will:
- Take the first group ID from the wordlist and try it against every host in your target list.
- Move to the next group ID and repeat the process for all hosts.
- This continues until all group IDs have been tested against all hosts.
- This approach spreads requests across multiple hosts, which can help avoid rate-limiting or
detection by not hammering a single host with all group IDs at once.
*Think "password spraying" versus "brute forcing". 


     IKE-Cazador
     Group-ID Brute-Force Script
     local-gh0st

  License/Disclaimer:
  This script is for educational and/or
  ethical use only.

  Do not redistribute for monetary gain.
  Do not use for malicious purposes or
  against networks for which you do not have
  authorization to test.

  Unauthorized use is prohibited.


**Install and Usage**
```

1. git pull
2. chmod +x IKE-Cazador.sh
3. ./IKE-Cazador.sh <target_ip OR targets_list.txt> <groupid_wordlist.txt

**Optional Flags**
[-j]    adds a delay between requests of .3-.99 seconds. Meant to emulate real user behavior. Useful for when targeting 1-2 devices and iterating through a large wordlist.
[-r]    uses a Group-first rotation: Tries each group ID against all hosts before moving to the next group ID (round-robin). Helps avoid hammering a single host and can bypass rate-limiting
