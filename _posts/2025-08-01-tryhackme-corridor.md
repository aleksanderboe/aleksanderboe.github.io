---
title: TryHackMe - Corridor
categories: [CTF Challenges]
tags: [TryHackMe, Web Exploitation, IDOR, Hash Cracking, Python Scripting]
date: 2025-08-01
---

Description of TryHackMe [Corridor](https://tryhackme.com/room/corridor) from [TryHackMe](https://tryhackme.com/)

> Can you escape the Corridor?
> 
> You have found yourself in a strange corridor. Can you find your way back to where you came?
> 
> In this challenge, you will explore potential IDOR vulnerabilities. Examine the URL endpoints you access as you navigate the website and note the hexadecimal values you find (they look an awful lot like a hash, don't they?). This could help you uncover website locations you were not expected to access.

![img-description](/assets/img/thm-corridor-banner.png)

## Initial Reconnaissance

Starting with a standard nmap scan of the provided IP address to identify open ports and services.

![img-description](/assets/img/thm-corridor-nmap.png)

The scan revealed a web service running on the target machine. Visiting the website, I was presented with an image of a corridor with multiple doors.

![img-description](/assets/img/thm-corridor-website.png)

## Website Analysis

Hovering over the doors revealed that they were clickable (cursor changed to a hand), indicating interactive elements. Clicking on the first door took me to a new endpoint with a hexadecimal value in the URL.

![img-description](/assets/img/thm-corridor-website-door-1.png)

The URL structure was: `http://10.10.227.8/c4ca4238a0b923820dcc509a6f75849b`

This hexadecimal value looked suspiciously like a hash, which aligned with the challenge hint: "they look an awful lot like a hash, don't they?"

## Hash Analysis

I used CrackStation to identify the hash `c4ca4238a0b923820dcc509a6f75849b`, which was revealed to be an MD5 hash of the value "1".

![img-description](/assets/img/thm-corridor-crackstation.png)

Investigating further, I discovered that all the door hashes corresponded to sequential numbers (1-13), with each door using its number's MD5 hash as the URL endpoint.

## Automated Enumeration

To find all possible doors and potentially hidden endpoints, I wrote a Python script that hashed values from 0 to 100 and checked if the resulting URLs were valid:

```python
import hashlib
import requests

BASE_URL = "http://10.10.227.8/"

for i in range(100): 
    md5_hash = hashlib.md5(str(i).encode()).hexdigest()
    url = BASE_URL + md5_hash
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"[+] {i} → {md5_hash} Door found: {url}")
        else:
            print(f"[-] {i} → {md5_hash}: status {response.status_code}")
    except requests.RequestException as e:
        print(f"[!] Request to {url} failed: {e}")
```

![img-description](/assets/img/thm-corridor-script-output.png)

## Flag Discovery

The script successfully identified all valid doors, including a hidden door at hash value 0. This secret door revealed the flag.

![img-description](/assets/img/thm-corridor-flag-censored.png)

## Conclusion

This challenge demonstrates an IDOR (Insecure Direct Object Reference) vulnerability where the application uses predictable hash values (MD5 of sequential numbers) as URL endpoints. By understanding the pattern and systematically enumerating possible values, it was possible to discover hidden endpoints that were not intended to be accessible through normal navigation.
