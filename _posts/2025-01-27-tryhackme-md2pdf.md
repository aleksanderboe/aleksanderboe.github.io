---
title: TryHackMe - MD2PDF
date: 2025-01-27
categories: [CTF Challenges]
tags:
  [
    Web Exploitation,
    TryHackMe,
    File Upload,
    PDF Generation,
    Server-Side,
    Web Security,
  ]
---

Description of CTF [MD2PDF](https://tryhackme.com/room/md2pdf) from [TryHackMe](https://tryhackme.com/)

> TopTierConversions LTD is proud to present its latest product launch.

![img-description](/assets/img/thm-md2pdf-banner.png)

## Overview

This CTF challenge focuses on a web application that converts Markdown files to PDF format.

## Initial Reconnaissance

Starting with a standard nmap scan of the provided IP address to identify open ports and services.

![img-description](/assets/img/thm-md2pdf-nmap-scan.png)

The scan revealed web services running on the target machine. Next, I used gobuster to enumerate hidden directories and discovered an `/admin` route.

![img-description](/assets/img/thm-md2pdf-gobuster-scan.png)

This route was only accessible locally through `http://localhost:5000/admin`, as shown in the admin interface.

![img-description](/assets/img/thm-md2pdf-admin-site.png)

## Website Analysis

Visiting the main website, I found a markdown to PDF conversion service. I tested the functionality by inputting some basic markdown code and converting it to PDF.

![img-description](/assets/img/thm-md2pdf-website.png)

The conversion process used the `/convert` route. After downloading the generated PDF file, I used exiftool to extract metadata from the file.

![img-description](/assets/img/thm-md2pdf-exiftool.png)

This revealed that the application was using **wkhtmltopdf version 0.12.5** for PDF generation.

## Exploitation

Searching Exploit-DB for vulnerabilities in wkhtmltopdf, I found a Server Side Request Forgery (SSRF) vulnerability in version 0.12.6 that could potentially affect the 0.12.5 version as well.

[Exploit-DB: wkhtmltopdf 0.12.6 - Server Side Request Forgery](https://www.exploit-db.com/exploits/51039)

The vulnerability allowed me to use HTML iframe tags to make the server request internal resources. By including the following HTML in my markdown:

```html
<iframe src="http://localhost:5000/admin"></iframe>
```

I was able to render the local admin page that contained the flag.

![img-description](/assets/img/thm-md2pdf-flag-censored.png)
