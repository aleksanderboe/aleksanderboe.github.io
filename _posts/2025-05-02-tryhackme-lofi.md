---
title: TryHackMe - Lo-Fi
date: 2025-05-02
categories: [CTF Challenges]
tags:
  [
    Web Exploitation,
    Path Traversal,
    TryHackMe,
    Directory Traversal,
    Apache,
    Network Analysis,
  ]
---

Description of CTF [Lo-Fi
](https://tryhackme.com/room/lofi) from [TryHackMe](https://tryhackme.com/)

> Want to hear some lo-fi beats, to relax or study to? We've got you covered! Navigate to the following URL using the AttackBox: http://MACHINE_IP and find the flag in the root of the filesystem.

![img-description](/assets/img/thm-lofi-banner.png)

Visiting the website provided we are presented with this.
![img-description](/assets/img/thm-lofi-website.png)

The description hints towards using path traversal and that the file is in the root of the filesystem. In linux this would be `/`

By clicking any of the links and inspecting the network request, we see that the there is a parameter that specifies a file
`http://10.10.67.232/?page=relax.php`
This opens up for path traversal as we can edit the parameter. Also looking at the network request that is sent, we can identify that the server is running Apache.
![img-description](/assets/img/thm-lofi-inspect.png)
The default directory for web content is `var/www.html`. Thus if we include the following escape sequence `../../../flag.txt` we should be able to move up in the directory to the root directory and access the flag file.
![img-description](/assets/img/thm-lofi-url.png)
