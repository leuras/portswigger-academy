# Web shell upload via obfuscated file extension

[Lab in PortSwigger](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension)

## Definition
Even the most exhaustive blacklists can potentially be bypassed using classic obfuscation techniques. Let's say the validation code is case sensitive and fails to recognize that exploit.pHp is in fact a .php file. If the code that subsequently maps the file extension to a MIME type is not case sensitive, this discrepancy allows you to sneak malicious PHP files past validation that may eventually be executed by the server.

You can also achieve similar results using the following techniques:

- Provide multiple extensions. Depending on the algorithm used to parse the filename, the following file may be interpreted as either a PHP file or JPG image: `exploit.php.jpg`

- Add trailing characters. Some components will strip or ignore trailing whitespaces, dots, and suchlike: `exploit.php.`

- Try using the URL encoding (or double URL encoding) for dots, forward slashes, and backward slashes. If the value isn't decoded when validating the file extension, but is later decoded server-side, this can also allow you to upload malicious files that would otherwise be blocked: `exploit%2Ephp`

- Add semicolons or URL-encoded null byte characters before the file extension. If validation is written in a high-level language like PHP or Java, but the server processes the file using lower-level functions in C/C++, for example, this can cause discrepancies in what is treated as the end of the filename: `exploit.asp;.jpg or exploit.asp%00.jpg`

- Try using multibyte unicode characters, which may be converted to null bytes and dots after unicode conversion or normalization. Sequences like `xC0` `x2E`, `xC4` `xAE` or `xC0` `xAE` may be translated to `x2E` if the filename parsed as a UTF-8 string, but then converted to ASCII characters before being used in a path.

Other defenses involve stripping or replacing dangerous extensions to prevent the file from being executed. If this transformation isn't applied recursively, you can position the prohibited string in such a way that removing it still leaves behind a valid file extension. For example, consider what happens if you strip .php from the following filename:
`exploit.p.phphp`

This is just a small selection of the many ways it's possible to obfuscate file extensions. 

## Notes
In the avatar upload request, just add a null byte followed by a JPEG or PNG extension. The file name will look like this: `exploit.php%00.jpg`.
To execute the script, do a request ignoring anything after the null bytes:
```http
GET /files/avatars/exploit.php HTTP/1.1
```

## Key Words
> file upload, web shell, rce