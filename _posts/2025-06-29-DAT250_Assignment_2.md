---
title: Vulnerability Remediation of “Social Insecurity”
date: 2025-06-29
tags: []
---

# **Information and Software Security - Vulnerability Remediation of “Social Insecurity"**

## **1. Introduction**

This report presents a security analysis of the "Social Insecurity" web application, a Flask-based application intentionally designed with several vulnerabilities for educational purposes. The purpose of this assignment is to revisit the previous assignment report, and fix the security vulnerabilities that were found in the vulnerability assessment section.

## **2. Vulnerability recap**

The security analysis of the "Social Insecurity" web application uncovered several significant vulnerabilities. These include Stored Cross-Site Scripting (XSS), which allows attackers to inject malicious scripts into users' browsers, and a lack of Cross-Site Request Forgery (CSRF) protections, enabling unauthorized actions on behalf of users. Additionally, SQL Injection flaws permit access to sensitive data, including plaintext passwords, while the absence of password complexity requirements creates an Insecure Authentication issue. Other vulnerabilities include Unrestricted File Upload, which allows the upload of malicious files, and Broken Access Control, permitting unauthorized access to user profiles. The application also faces risks from Sensitive Data Exposure and the potential for Denial of Service (DoS) attacks due to no rate limiting.

## **3. Remediation Details**

### **3.1 CSRF**

By using the csrf module from flask_wtf we can enable csrf protection globally on the application.

```python
# __init__.py
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()
csrf.init_app(app)

# config.py
Class config:
    ...
    WTF_CSRF_ENABLED = True
```

We then add a hidden field in the form for the CSRF token, so that it is included in the form data. Requests without this token will be rejected, ensuring only requests from the same origin come through.

```html
<!-- templates/profile.html.j2 -->
<form action="" method="post" novalidate>... {{ form.csrf_token }}</form>
```

### **3.2 Path traversal**

By using the secure_filename function from the werkzeug.utils package, we can remove dangerous characters from the filename, such as ../ or other traversal sequences.

```python
from werkzeug.utils import secure_filename

filename = secure_filename(post_form.image.data.filename)
```

### **3.3. Sensitive Data Exposure**

To prevent passwords leaked in the form of plaintext, we can use the password-hashing function from the Crypt module. This ensures that the database does not store the passwords in plaintext, but stores the hash, so if there were to be a data leak, only the hashed password would be revealed.

```python
# __init__.py
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()
bcrypt.init_app(app)
```

```python
# routes.py
@app.route("/", methods=["GET", "POST"])
@app.route("/index", methods=["GET", "POST"])
def index():
    index_form = IndexForm()
    login_form = index_form.login
    register_form = index_form.register

    if login_form.is_submitted() and login_form.submit.data:
        get_user = """
            SELECT *
            FROM Users
            WHERE username = ?;
            """
        user = sqlite.query(get_user, login_form.username.data, one=True)

        if user is None:
            flash("Sorry, this user does not exist!", category="warning")
        elif not bcrypt.check_password_hash(user["password"], login_form.password.data):
            flash("Sorry, wrong password!", category="warning")
        else:
            return redirect(url_for("stream", username=login_form.username.data))

    elif register_form.is_submitted() and register_form.submit.data:
        hashed_password = bcrypt.generate_password_hash(register_form.password.data)

        insert_user = """
            INSERT INTO Users (username, first_name, last_name, password)
            VALUES (?, ?, ?, ?);
            """
        sqlite.query(
            insert_user,
            register_form.username.data,
            register_form.first_name.data,
            register_form.last_name.data,
            hashed_password
        )
        flash("User successfully created!", category="success")
        return redirect(url_for("index"))

    return render_template("index.html.j2", title="Welcome", form=index_form)
```

### **3.4. Insecure Authentication**

Using the wtforms.validators module, we can enforce some requirements to fields when signing up for a new account.

```python
# forms.py
from wtforms.validators import DataRequired, Length, EqualTo

class RegisterForm(FlaskForm):
    """Provides the registration form for the application."""

    first_name = StringField(
        label="First Name",
        validators=[DataRequired(), Length(min=2, max=30)],
        render_kw={"placeholder": "First Name"}
    )

    last_name = StringField(
        label="Last Name",
        validators=[DataRequired(), Length(min=2, max=30)],
        render_kw={"placeholder": "Last Name"}
    )

    username = StringField(
        label="Username",
        validators=[DataRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"}
    )

    password = PasswordField(
        label="Password",
        validators=[DataRequired(), Length(min=6)],
        render_kw={"placeholder": "Password"}
    )

    confirm_password = PasswordField(
        label="Confirm Password",
        validators=[DataRequired(), EqualTo('password', message="Passwords must match")],
        render_kw={"placeholder": "Confirm Password"}
    )

    submit = SubmitField(label="Sign Up")
```

### **3.5 Denial of Service (DoS)**

Using flask-limiter, we can set a rate-limit, the number of times someone can access the website, before being timed out. This measure can help against a DoS attack.

```python
# __init__.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])
```

```python
# routes.py
@limiter.limit("5 per minute", methods=["POST"], key_func=get_remote_address)
def index():
    ...
```

### **3.6 Unrestricted File Upload**

To restrict file upload, we only allow upload of files that are images.

```python
# Config.py
Class config:
    ...
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
```

```python
# routes.py
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

# @app.route("/stream/<string:username>", methods=["GET", "POST"])
def stream(username: str):
    ...
    if post_form.is_submitted():
        if post_form.image.data:
            if not allowed_file(post_form.image.data.filename):
                flash('Allowed file types are png, jpg, jpeg, gif', category="warning")
```

### **3.7. Cross Site Scripting (XSS)**

Using parameterized queries and escaping user input, we can prevent XSS attacks from occurring.

```python
# routes.py
@app.route("/stream/<string:username>", methods=["GET", "POST"])
def stream(username: str):
    ...
    safe_content = html.escape(post_form.content.data)

    insert_post = """
    INSERT INTO Posts (u_id, content, image, creation_time)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP);
    """
    sqlite.query(insert_post, user["id"], safe_content, post_form.image.data.filename)
    return redirect(url_for("stream", username=username))
```

## **4. Validation and Testing**

### **4.1 CSRF**

We made an edit to the profile, inspected the request payload and verified that the CSRF token was present.

![img-description](/assets/img/DAT250-Assignment-2/image1.png)

By using CURL, we can send the same request through the terminal, to make sure the mitigation has been applied correctly.

```bash
curl -X POST http://127.0.0.1:5000/profile/test -d "education=CSRF"
```

We got the following response that confirmed that our mitigation worked.

```html
<!DOCTYPE html>
<html lang="en">
  <title>400 Bad Request</title>
  <h1>Bad Request</h1>
  <p>The CSRF token is missing.</p>
</html>
```

### **4.2 Path traversal**

To verify that our changes prevent the path traversal, we upload a file, intercept the request with burp suite, modify it to include traversal sequences. We then verify by debugging the application and seeing the traversal sequences being removed.

In the visual studio code debugger we can see that the filename includes the traversal sequence in the raw request

![img-description](/assets/img/DAT250-Assignment-2/image2.png)

Stepping over the lines, we can now see that the filename returned from secure_filename is stripped of any traversal sequences

![img-description](/assets/img/DAT250-Assignment-2/image3.png)

### **4.3. Sensitive Data Exposure**

By looking at the database file, we can confirm that the passwords are now stored by hash.

![img-description](/assets/img/DAT250-Assignment-2/image4.png)

### **4.4. Insecure Authentication**

In this instance, we observe the enforcement of specific requirements, including a stipulation that the password must be at least six characters long, ensuring that users create a password that meets the minimum security standards established by the system.

![img-description](/assets/img/DAT250-Assignment-2/image5.png)

### **4.5 Denial of Service (DoS)**

When we refresh the website a total of ten times within a short span of time, we encounter rate-limiting measures that restrict our ability to access the site further.

![img-description](/assets/img/DAT250-Assignment-2/image6.png)

### **4.6 Unrestricted File Upload**

When we attempt to upload a file that is not an image, the system responds by displaying a warning message indicating that the file type is not supported, and as a result, the upload process is halted, preventing the file from being successfully uploaded to the server.

![img-description](/assets/img/DAT250-Assignment-2/image7.png)

### **4.7. Cross Site Scripting (XSS)**

In the image below, we can see that the user input has been escaped. It is no longer treated as javascript code, but rather in raw text.

![img-description](/assets/img/DAT250-Assignment-2/image8.png)

## **5. Lessons Learned**

Through this assignment we have learned the importance of sanitizing and validating input to prevent XSS and SQL injections. We cannot trust the client, as clients can manipulate outgoing requests with tools like Burp Suite, as seen in the Path Traversal exploit. Hashing passwords are important, if a database were to be compromised, the plaintext password would not be revealed.

# Appendix

**Source Code:** The source code for the 'Social Insecurity' web application is available at: https://github.com/xnira01/social-insecurity
