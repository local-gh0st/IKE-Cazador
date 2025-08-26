# IKE-Cazador
Brute force Group IDs for network devices configured with IKE Aggressive mode. 

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
[-r]    uses a Group-rotation method which iterates through each provided target with the first GroupID in a wordlist. Particularly useful when targeting multiple devices (with target_lists.txt file).
