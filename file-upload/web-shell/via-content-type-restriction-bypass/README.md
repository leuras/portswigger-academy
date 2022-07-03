# Web shell upload via Content-Type restriction bypass

[Lab in PortSwigger](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass)

## Definition
One way that websites may attempt to validate file uploads is to check that this input-specific `Content-Type` header matches an expected MIME type. If the server is only expecting image files, for example, it may only allow types like `image/jpeg` and `image/png`. Problems can arise when the value of this header is implicitly trusted by the server. If no further validation is performed to check whether the contents of the file actually match the supposed MIME type, this defense can be easily bypassed using tools like Burp Repeater. 

## Notes
To exploit this flaw, upload the `exploit.php` and intercept the POST request. In the `content-type` field, change from `applicationx-php` to `image/jpeg` and release the request. After that, do a GET request to the uploaded exploit.

## Key Words
> file upload, web shell, rce