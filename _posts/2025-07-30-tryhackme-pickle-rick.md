---
title: TryHackMe - Pickle Rick
date: 2025-07-30
categories: [CTF Challenges]
tags:
  [
    Web Exploitation,
    TryHackMe,
    Directory Enumeration,
    Command Injection,
    File Upload,
    Web Security,
  ]
---

Description of CTF [Pickle Rick](https://tryhackme.com/room/picklerick) from [TryHackMe](https://tryhackme.com/)

> A Rick and Morty CTF. Help turn Rick back into a human!

![img-description](/assets/img/thm-pickle-rick-banner.png)

## Overview

This CTF challenge is themed around the popular TV show Rick and Morty. The goal is to help turn Rick back into a human by finding three secret ingredients for his potion. This involves web enumeration, credential discovery, and command execution.

## Initial Reconnaissance

Starting with a standard nmap scan to identify open ports and services running on the target machine.

![img-description](/assets/img/thm-pickle-rick-nmap.png)

The scan revealed that port 80 is open, indicating a web server is running. I proceeded to visit the website to analyze its content.

## Website Analysis

The main website displays a Rick and Morty themed page. Upon inspecting the page source using browser developer tools, I discovered a hidden HTML comment containing valuable information.

![img-description](/assets/img/thm-pickle-rick-website.png)

The HTML comment revealed a username: **R1ckRul3s**

![img-description](/assets/img/thm-pickle-rick-website-inspect.png)

## Directory Enumeration

Using gobuster to enumerate hidden directories and files on the web server.

![img-description](/assets/img/thm-pickle-rick-gobuster.png)

The scan discovered a `robots.txt` file. I used curl to retrieve its contents.

![img-description](/assets/img/thm-pickle-rick-curl-robotstxt.png)

The robots.txt file contained the string **Wubbalubbadubdub**, which I identified as a potential password.

## Finding the Login Portal

Performing another gobuster scan with the `-x php` option to specifically look for PHP files.

![img-description](/assets/img/thm-pickle-rick-gobuster-php.png)

This scan revealed both `login.php` and `portal.php` files. The portal.php file simply redirected to login.php, so I focused on the login page.

## Gaining Access

Using the discovered credentials:

- Username: R1ckRul3s
- Password: Wubbalubbadubdub

I successfully logged into the system and gained access to a command panel.

![img-description](/assets/img/thm-pickle-rick-website-cmd-panel.png)

## Finding the First Ingredient

Executing the `ls` command to list files in the current directory.

![img-description](/assets/img/thm-pickle-rick-website-cmd-panel-ls.png)

I discovered a file named `Sup3rS3cretPickl3Ingred.txt` which likely contained the first ingredient. However, the `cat` command was blocked by the system.

![img-description](/assets/img/thm-pickle-rick-website-cmd-panel-cat-blocked.png)

Fortunately, I was able to read the file using the `less` command instead.

![img-description](/assets/img/thm-pickle-rick-website-cmd-panel-less.png)

## Finding the Second Ingredient

After finding the first ingredient, I noticed there was a `clue.txt` file in the current directory. I read this file to get a hint for finding the next ingredient.

![img-description](/assets/img/thm-pickle-rick-website-cmd-panel-cluetxt.png)

The clue.txt file contained the message: **"Look around the file system for the other ingredient."**

This hint suggested that I needed to explore the file system to find the second ingredient. I used the `find` command to search through the `/home` directory for any files that might contain the ingredient.

![img-description](/assets/img/thm-pickle-rick-website-cmd-panel-find-home.png)

The find command revealed a file located at `/home/rick/second ingredient`. I then read this file to obtain the second ingredient.

![img-description](/assets/img/thm-pickle-rick-website-second-ingredient.png)

## Finding the Third Ingredient

In CTF challenges, there are often user flags and root flags, with the final flag typically located in the `/root` directory. To assess privilege escalation possibilities, I used the `sudo -l` command to check what sudo privileges were available.

![img-description](/assets/img/thm-pickle-rick-cmd-panel-sudo-list.png)

The output revealed that the current user had full root access:

```
Matching Defaults entries for www-data on ip-10-10-99-151:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-10-99-151:
    (ALL) NOPASSWD: ALL
```

This configuration allows the user to run any command as root without requiring a password. With this elevated access, I used `sudo ls /root -al` to explore the root directory and locate the final ingredient.

Within the `/root` directory, I found the file `3rd.txt` containing the third and final ingredient.

![img-description](/assets/img/thm-pickle-rick-website-third-ingredient.png)
